#include "../include/remote_hooker.h"
#include "../include/syscalls.h"
#include "../include/shellcode_builder.h"
#include "../vendor/ldasm/LDasm.h"
#include <algorithm>
#include <cstdio>

RemoteHooker::RemoteHooker(HANDLE hProcess)
    : hProcess(hProcess)
    , targetAddress(0)
    , remoteShellcodeAddress(0)
    , trampolineAddress(0)
    , isHookInstalled(false)
    , useHardwareBreakpoint(false)
{
}

RemoteHooker::~RemoteHooker() {
    UninstallHook();
}

namespace {
    void DebugProtectChange(const char* label, void* address, SIZE_T size, DWORD protect) {
        char buffer[160]{};
        _snprintf_s(buffer, sizeof(buffer) - 1, _TRUNCATE, "[RemoteHooker] %s addr=%p size=%zu prot=0x%lx\n",
            label, address, static_cast<size_t>(size), static_cast<unsigned long>(protect));
        OutputDebugStringA(buffer);
    }
}

PVOID RemoteHooker::RemoteAllocate(SIZE_T size, DWORD protect) {
    PVOID baseAddress = nullptr;
    SIZE_T regionSize = size;
    
    NTSTATUS status = IndirectSyscalls::NtAllocateVirtualMemory(
        hProcess,
        &baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        protect
    );
    
    return (status == STATUS_SUCCESS) ? baseAddress : nullptr;
}

bool RemoteHooker::RemoteWrite(PVOID address, const void* data, SIZE_T size) {
    SIZE_T bytesWritten = 0;
    
    NTSTATUS status = IndirectSyscalls::NtWriteVirtualMemory(
        hProcess,
        address,
        (PVOID)data,
        size,
        &bytesWritten
    );
    
    return (status == STATUS_SUCCESS && bytesWritten == size);
}

bool RemoteHooker::RemoteRead(PVOID address, void* buffer, SIZE_T size) {
    SIZE_T bytesRead = 0;
    
    NTSTATUS status = IndirectSyscalls::NtReadVirtualMemory(
        hProcess,
        address,
        buffer,
        size,
        &bytesRead
    );
    
    return (status == STATUS_SUCCESS && bytesRead == size);
}

bool RemoteHooker::RemoteProtect(PVOID address, SIZE_T size, DWORD newProtect, DWORD* oldProtect) {
    ULONG oldProt = 0;
    
    NTSTATUS status = IndirectSyscalls::NtProtectVirtualMemory(
        hProcess,
        &address,
        &size,
        newProtect,
        &oldProt
    );
    
    if (oldProtect) {
        *oldProtect = oldProt;
    }
    
    return (status == STATUS_SUCCESS);
}

size_t RemoteHooker::CalculateHookLength(const BYTE* code) {
    size_t totalLen = 0;
    const size_t minLen = 14; // 我们需要至少14字节来放置长跳转
    ldasm_data data = { 0 };
    
    while (totalLen < minLen) {
        //使用ldasm来做指令长度计算
        size_t instrLen = ldasm((void*)(code + totalLen), &data, 1);
        if (instrLen == 0) {
            return 0; // 失败
        }
        totalLen += instrLen;
    }
    
    return totalLen;
}

bool RemoteHooker::CreateTrampoline(uintptr_t targetAddr) {
    // 读取目标地址的原始字节
    BYTE originalCode[32];
    if (!RemoteRead((PVOID)targetAddr, originalCode, sizeof(originalCode))) {
        return false;
    }
    
    // 计算需要备份的指令长度
    size_t hookLen = CalculateHookLength(originalCode);
    if (hookLen == 0 || hookLen > 32) {
        return false;
    }
    
    originalBytes.assign(originalCode, originalCode + hookLen);
    
    // 分配Trampoline内存
    // Trampoline = 原始指令 + 跳转回原函数的JMP指令
    SIZE_T trampolineSize = hookLen + 14; // 原始指令 + 长跳转
    RemoteMemory trampMem;
    if (!trampMem.allocate(hProcess, trampolineSize, PAGE_READWRITE)) {
        return false;
    }
    PVOID trampolineAddr = trampMem.get();
    
    trampolineAddress = (uintptr_t)trampolineAddr;
    
    // 写入原始指令
    if (!RemoteWrite(trampolineAddr, originalCode, hookLen)) {
        return false;
    }
    
    // 生成跳转回原函数的指令
    uintptr_t returnAddress = targetAddr + hookLen;
    std::vector<BYTE> jmpBack = GenerateJumpInstruction(trampolineAddress + hookLen, returnAddress);
    
    if (!RemoteWrite((PVOID)(trampolineAddress + hookLen), jmpBack.data(), jmpBack.size())) {
        trampolineAddress = 0;
        return false;
    }

    if (!trampMem.protect(PAGE_EXECUTE_READ)) {
        trampolineAddress = 0;
        return false;
    }
    DebugProtectChange("trampoline RX", trampolineAddr, trampolineSize, PAGE_EXECUTE_READ);
    trampolineMemory = std::move(trampMem);
    
    return true;
}

std::vector<BYTE> RemoteHooker::GenerateJumpInstruction(uintptr_t from, uintptr_t to) {
    std::vector<BYTE> jmp;
    
    // 计算相对偏移
    INT64 offset = (INT64)to - (INT64)from - 5;
    
    // 如果可以使用5字节短跳转（rel32）
    if (offset >= INT32_MIN && offset <= INT32_MAX) {
        jmp.push_back(0xE9); // JMP rel32
        INT32 offset32 = (INT32)offset;
        jmp.push_back((BYTE)(offset32 & 0xFF));
        jmp.push_back((BYTE)((offset32 >> 8) & 0xFF));
        jmp.push_back((BYTE)((offset32 >> 16) & 0xFF));
        jmp.push_back((BYTE)((offset32 >> 24) & 0xFF));
    }
    else {
        // 使用14字节长跳转
        // mov rax, addr64
        jmp.push_back(0x48);
        jmp.push_back(0xB8);
        for (int i = 0; i < 8; i++) {
            jmp.push_back((BYTE)((to >> (i * 8)) & 0xFF));
        }
        // jmp rax
        jmp.push_back(0xFF);
        jmp.push_back(0xE0);
    }
    
    return jmp;
}

bool RemoteHooker::InstallHook(uintptr_t targetFunctionAddress, const ShellcodeConfig& shellcodeConfig) {
    if (isHookInstalled) {
        return false; // 已经安装过Hook
    }
    
    targetAddress = targetFunctionAddress;
    
    // 1. 创建Trampoline
    if (!CreateTrampoline(targetAddress)) {
        return false;
    }
    
    // 2. 构建Shellcode（需要更新配置以包含正确的trampoline地址）
    ShellcodeConfig updatedConfig = shellcodeConfig;
    updatedConfig.trampolineAddress = trampolineAddress;
    
    ShellcodeBuilder builder;
    std::vector<BYTE> shellcode = builder.BuildHookShellcode(updatedConfig);
    
    // 3. 在远程进程中分配Shellcode内存
    RemoteMemory shellMem;
    if (!shellMem.allocate(hProcess, shellcode.size(), PAGE_READWRITE)) {
        trampolineMemory.reset();
        trampolineAddress = 0;
        return false;
    }
    PVOID remoteShellcode = shellMem.get();
    remoteShellcodeAddress = (uintptr_t)remoteShellcode;
    
    // 4. 写入Shellcode
    if (!RemoteWrite(remoteShellcode, shellcode.data(), shellcode.size())) {
        trampolineMemory.reset();
        trampolineAddress = 0;
        remoteShellcodeAddress = 0;
        return false;
    }

    if (!shellMem.protect(PAGE_EXECUTE_READ)) {
        trampolineMemory.reset();
        trampolineAddress = 0;
        remoteShellcodeAddress = 0;
        return false;
    }
    DebugProtectChange("shellcode RX", remoteShellcode, shellcode.size(), PAGE_EXECUTE_READ);
    shellcodeMemory = std::move(shellMem);

    DWORD shellOldProtect = 0;
    if (!RemoteProtect(remoteShellcode, shellcode.size(), PAGE_EXECUTE_READ, &shellOldProtect)) {
        shellcodeMemory.reset();
        shellcodeMemory = RemoteMemory();
        trampolineMemory.reset();
        remoteShellcodeAddress = 0;
        trampolineAddress = 0;
        return false;
    }
    DebugProtectChange("shellcode RX", remoteShellcode, shellcode.size(), PAGE_EXECUTE_READ);
    
    // 5. 生成Hook跳转指令
    std::vector<BYTE> hookJump = GenerateJumpInstruction(targetAddress, remoteShellcodeAddress);
    
    // 确保有足够的空间
    if (hookJump.size() > originalBytes.size()) {
        shellcodeMemory.reset();
        shellcodeMemory = RemoteMemory();
        trampolineMemory.reset();
        remoteShellcodeAddress = 0;
        trampolineAddress = 0;
        return false;
    }
    
    // 填充NOP
    while (hookJump.size() < originalBytes.size()) {
        hookJump.push_back(0x90); // NOP
    }
    
    if (useHardwareBreakpoint) {
        // 硬件断点模式：不写补丁，直接返回，由上层负责设置断点/VEH
        isHookInstalled = true;
        return true;
    } else {
        // Inline Patch 模式（回退）
        // 6. 修改目标函数的保护属性
        DWORD oldProtect;
        if (!RemoteProtect((PVOID)targetAddress, originalBytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            shellcodeMemory.reset();
            shellcodeMemory = RemoteMemory();
            trampolineMemory.reset();
            remoteShellcodeAddress = 0;
            trampolineAddress = 0;
            return false;
        }
        
        // 7. 写入Hook跳转指令（原子操作）
        bool writeSuccess = RemoteWrite((PVOID)targetAddress, hookJump.data(), hookJump.size());
        
        // 8. 恢复原始保护属性
        DWORD tempProtect;
        RemoteProtect((PVOID)targetAddress, originalBytes.size(), oldProtect, &tempProtect);
        
        if (!writeSuccess) {
            shellcodeMemory.reset();
            shellcodeMemory = RemoteMemory();
            trampolineMemory.reset();
            remoteShellcodeAddress = 0;
            trampolineAddress = 0;
            return false;
        }
        
        isHookInstalled = true;
        return true;
    }
}

bool RemoteHooker::UninstallHook() {
    if (!isHookInstalled) {
        return true;
    }

    bool restoreSuccess = true;

    if (!useHardwareBreakpoint) {
        // Inline patch 模式才需要恢复补丁
        DWORD oldProtect;
        if (!RemoteProtect((PVOID)targetAddress, originalBytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            return false;
        }
        restoreSuccess = RemoteWrite((PVOID)targetAddress, originalBytes.data(), originalBytes.size());
        DWORD tempProtect;
        RemoteProtect((PVOID)targetAddress, originalBytes.size(), oldProtect, &tempProtect);
    }

    // 4. 释放远程内存
    shellcodeMemory.reset();
    remoteShellcodeAddress = 0;
    trampolineMemory.reset();
    trampolineAddress = 0;
    
    isHookInstalled = false;
    return restoreSuccess;
}

