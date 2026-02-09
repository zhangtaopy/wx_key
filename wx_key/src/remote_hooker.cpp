#include "../include/remote_hooker.h"
#include "../include/syscalls.h"
#include "../include/shellcode_builder.h"
#include <algorithm>
#include <cstdio>

// 这个原来的太简单会有问题(sub esp,xx等),AI生成一份改一改凑合着用吧，最好换成成熟的反汇编指令长度计算库
// 简单的x64反汇编长度检测器
// 支持常见指令，用于计算需要备份多少字节
namespace X64Disasm {
    inline bool is_prefix(uint8_t b) {
        return (b == 0xF0 || b == 0xF2 || b == 0xF3 ||  // LOCK/REP
            b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || // segment
            b == 0x64 || b == 0x65 || b == 0x66 || b == 0x67);  // FS/GS/operand/addr
    }

    inline bool is_rex(uint8_t b) {
        return (b >= 0x40 && b <= 0x4F);
    }
    
    // 获取单条指令的长度
    size_t GetInstructionLength(const BYTE* code, size_t max_len = 15) {
        const uint8_t* start = code;
        uint8_t rex = 0;

        // 处理前缀
        while (code - start < max_len) {
            if (is_rex(*code)) {
                rex = *code;
                code++;
                continue;
            }
            if (is_prefix(*code)) {
                code++;
                continue;
            }
            break;
        }

        if (code - start >= max_len) return 1; // 安全返回

        uint8_t opcode = *code++;
        uint8_t modrm = 0;  // 移到这里定义

        // 处理两字节操作码
        if (opcode == 0x0F) {
            if (code - start >= max_len) return 2;
            opcode = *code++;

            // 条件跳转
            if (opcode >= 0x80 && opcode <= 0x8F) {
                if (code + 4 - start > max_len) return 2;
                return code + 4 - start;
            }

            // SIMD等指令
            switch (opcode) {
            case 0x10: case 0x11: case 0x12: case 0x13:
            case 0x14: case 0x15: case 0x16: case 0x17:
            case 0x28: case 0x29: case 0x2A: case 0x2B:
            case 0x2C: case 0x2D: case 0x2E: case 0x2F:
                // 需要ModR/M
                if (code - start >= max_len) return 2;
                code++;
                return code - start;
            }

            return 2; // 其他两字节指令
        }

        // 主操作码处理
        switch (opcode) {
            // 1字节指令
        case 0x90: case 0x91: case 0x92: case 0x93:
        case 0x94: case 0x95: case 0x96: case 0x97:
        case 0x98: case 0x99: case 0x9B: case 0x9C:
        case 0x9D: case 0x9E: case 0x9F:
        case 0xC3: case 0xCB: case 0xCC:
        case 0xF4: case 0xF5: case 0xF8: case 0xF9:
        case 0xFA: case 0xFB: case 0xFC: case 0xFD:
            return code - start;

            // push/pop寄存器
        case 0x50: case 0x51: case 0x52: case 0x53:
        case 0x54: case 0x55: case 0x56: case 0x57:
        case 0x58: case 0x59: case 0x5A: case 0x5B:
        case 0x5C: case 0x5D: case 0x5E: case 0x5F:
            return code - start;

            // 立即数到寄存器
        case 0xB0: case 0xB1: case 0xB2: case 0xB3:
        case 0xB4: case 0xB5: case 0xB6: case 0xB7:
            if (code + 1 - start > max_len) return 1;
            return code + 1 - start;

        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF:
            if (rex & 0x8) { // REX.W
                if (code + 8 - start > max_len) return 1;
                return code + 8 - start;
            }
            else {
                if (code + 4 - start > max_len) return 1;
                return code + 4 - start;
            }

            // 短跳转
        case 0x70: case 0x71: case 0x72: case 0x73:
        case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7A: case 0x7B:
        case 0x7C: case 0x7D: case 0x7E: case 0x7F:
        case 0xEB: case 0xE3:
            if (code + 1 - start > max_len) return 1;
            return code + 1 - start;

            // CALL/JMP相对
        case 0xE8: case 0xE9:
            if (code + 4 - start > max_len) return 1;
            return code + 4 - start;

            // 操作码组
        case 0x80: case 0x81: case 0x82: case 0x83:
        case 0x88: case 0x89: case 0x8A: case 0x8B:
        case 0x8C: case 0x8D: case 0x8E: case 0x8F:
        case 0xC0: case 0xC1: case 0xC6: case 0xC7:
        case 0xD0: case 0xD1: case 0xD2: case 0xD3:
        case 0xF6: case 0xF7: case 0xFE: case 0xFF:
            if (code - start >= max_len) return 1;
            modrm = *code++;  // 这里只是赋值，不是定义

            {
                uint8_t mod = (modrm >> 6) & 3;
                uint8_t rm = modrm & 7;

                // 处理SIB
                if (mod != 3 && rm == 4) {
                    if (code - start >= max_len) return code - start;
                    code++; // SIB
                }

                // 处理disp
                if (mod == 1) {
                    if (code + 1 - start > max_len) return code - start;
                    code += 1;
                }
                else if (mod == 2 || (mod == 0 && rm == 5)) {
                    if (code + 4 - start > max_len) return code - start;
                    code += 4;
                }

                // 处理立即数
                switch (opcode) {
                case 0x80: case 0x82: case 0x83:
                case 0xC0: case 0xC1: case 0xC6:
                case 0xD0: case 0xD1: case 0xD2: case 0xD3:
                    if (code + 1 - start > max_len) return code - start;
                    code += 1;
                    break;

                case 0x81: case 0xC7:
                    if (rex & 0x8) {
                        if (code + 8 - start > max_len) return code - start;
                        code += 8;
                    }
                    else {
                        if (code + 4 - start > max_len) return code - start;
                        code += 4;
                    }
                    break;
                }
            }

            return code - start;

        default:
            // 其他指令返回1字节
            return 1;
        }
    }
}

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
    
    while (totalLen < minLen) {
        size_t instrLen = X64Disasm::GetInstructionLength(code + totalLen);
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

