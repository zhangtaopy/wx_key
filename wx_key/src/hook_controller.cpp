#define HOOK_EXPORTS

#include <Windows.h>
#include <string>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <memory>
#include <vector>

#include "../include/hook_controller.h"
#include "../include/syscalls.h"
#include "../include/remote_scanner.h"
#include "../include/remote_scanner_common.h"
#include "../include/ipc_manager.h"
#include "../include/remote_hooker.h"
#include "../include/shellcode_builder.h"
#include "../include/string_obfuscator.h"
#include "../include/remote_veh.h"
#include "../include/remote_memory.h"

#pragma execution_character_set("utf-8")

// 全局状态
namespace {
    bool InitializeContext(DWORD targetPid);
    void CleanupContext();
    struct StatusMessage {
        std::string message;
        int level;
    };

    struct HookContext {
        HANDLE hProcess{ nullptr };
        std::unique_ptr<IPCManager> ipc;
        std::unique_ptr<RemoteHooker> hooker;
        RemoteMemory remoteData;
        RemoteMemory spoofStack;
        CRITICAL_SECTION dataLock{};
        bool csInitialized{ false };
        std::string pendingKeyData;
        bool hasNewKey{ false };
        std::vector<StatusMessage> statusQueue;
        bool initialized{ false };

        void InitLock() {
            if (!csInitialized) {
                InitializeCriticalSection(&dataLock);
                csInitialized = true;
            }
        }

        void FreeLock() {
            if (csInitialized) {
                DeleteCriticalSection(&dataLock);
                csInitialized = false;
            }
        }

        void ResetDataQueues() {
            pendingKeyData.clear();
            hasNewKey = false;
            statusQueue.clear();
        }
    };

    HookContext g_ctx;
    std::string g_lastError;

    std::string WideToUtf8(const std::wstring& wide) {
        if (wide.empty()) {
            return std::string();
        }
        int sizeNeeded = WideCharToMultiByte(
            CP_UTF8,
            0,
            wide.c_str(),
            static_cast<int>(wide.size()),
            nullptr,
            0,
            nullptr,
            nullptr
        );
        if (sizeNeeded <= 0) {
            return std::string();
        }
        std::string utf8(sizeNeeded, 0);
        WideCharToMultiByte(
            CP_UTF8,
            0,
            wide.c_str(),
            static_cast<int>(wide.size()),
            reinterpret_cast<LPSTR>(&utf8[0]),
            sizeNeeded,
            nullptr,
            nullptr
        );
        return utf8;
    }
    
    // 生成唯一ID
    std::string GenerateUniqueId(DWORD pid) {
        std::stringstream ss;
        ss << std::hex << pid << "_" << GetTickCount64();
        return ss.str();
    }

    // 发送状态信息
    void SendStatus(const std::string& message, int level) {
        // 统一由外层日志系统加等级前缀
        const std::string& prefixed = message;
        if (g_ctx.csInitialized) {
            EnterCriticalSection(&g_ctx.dataLock);
        }
        g_ctx.statusQueue.push_back({prefixed, level});
        // 限制队列大小
        if (g_ctx.statusQueue.size() > 100) {
            g_ctx.statusQueue.erase(g_ctx.statusQueue.begin());
        }
        if (g_ctx.csInitialized) {
            LeaveCriticalSection(&g_ctx.dataLock);
        }
    }
    
    std::string GetSystemErrorMessage(DWORD errorCode) {
        if (errorCode == 0) {
            return std::string();
        }

        LPWSTR buffer = nullptr;
        DWORD length = FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            errorCode,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPWSTR>(&buffer),
            0,
            nullptr
        );

        std::string message;
        if (length && buffer) {
            std::wstring wideMessage(buffer, length);
            while (!wideMessage.empty() && (wideMessage.back() == L'\r' || wideMessage.back() == L'\n')) {
                wideMessage.pop_back();
            }
            message = WideToUtf8(wideMessage);
        }

        if (buffer) {
            LocalFree(buffer);
        }
        return message;
    }

    std::string FormatWin32Error(const std::string& baseMessage, DWORD errorCode) {
        std::ostringstream oss;
        oss << baseMessage;
        if (errorCode != 0) {
            oss << " (code " << errorCode << ")";
            std::string detail = GetSystemErrorMessage(errorCode);
            if (!detail.empty()) {
                oss << ": " << detail;
            }
        }
        return oss.str();
    }

    std::string FormatNtStatusError(const std::string& baseMessage, NTSTATUS status) {
        std::ostringstream oss;
        oss << baseMessage << " (NTSTATUS 0x"
            << std::uppercase << std::hex << std::setw(8) << std::setfill('0')
            << static_cast<unsigned long>(status) << ")";
        return oss.str();
    }

    // 设置错误信息
    void SetLastError(const std::string& error) {
        g_lastError = error;
        SendStatus(error, 2); // level 2 = error
    }
    // 数据回调处理（从IPC线程调用）
    void OnDataReceived(const SharedKeyData& data) {
        // Validate data
        if (data.dataSize != 32) {
            SendStatus("收到的密钥数据长度不正确", 2);
            return;
        }
        
        // 转换为十六进制字符串
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (DWORD i = 0; i < data.dataSize; i++) {
            ss << std::setw(2) << static_cast<int>(data.keyBuffer[i]);
        }
        
        std::string keyHex = ss.str();
        
        // 存入队列
        if (g_ctx.csInitialized) {
            EnterCriticalSection(&g_ctx.dataLock);
        }
        g_ctx.pendingKeyData = keyHex;
        g_ctx.hasNewKey = true;
        if (g_ctx.csInitialized) {
            LeaveCriticalSection(&g_ctx.dataLock);
        }
        
        SendStatus("已成功接收到密钥", 1); // level 1 = success
    }
}

namespace {
    bool InitializeContext(DWORD targetPid) {
        if (g_ctx.initialized) {
            SetLastError("Hook已经初始化");
            return false;
        }

        g_ctx.InitLock();
        g_ctx.ResetDataQueues();

        SendStatus("开始初始化Hook系统...", 0);

        // 1. 初始化系统调用
        SendStatus("正在初始化系统调用...", 0);
        if (!IndirectSyscalls::Initialize()) {
            DWORD errorCode = GetLastError();
            SetLastError(FormatWin32Error("初始化间接系统调用失败", errorCode));
            g_ctx.FreeLock();
            return false;
        }

        // 2. 打开进程
        SendStatus("正在打开目标进程...", 0);
        MY_OBJECT_ATTRIBUTES objAttr;
        memset(&objAttr, 0, sizeof(MY_OBJECT_ATTRIBUTES));
        objAttr.Length = sizeof(MY_OBJECT_ATTRIBUTES);

        MY_CLIENT_ID clientId;
        memset(&clientId, 0, sizeof(MY_CLIENT_ID));
        clientId.UniqueProcess = (PVOID)(ULONG_PTR)targetPid;

        HANDLE hProcess = NULL;
        NTSTATUS status = IndirectSyscalls::NtOpenProcess(
            &hProcess,
            PROCESS_ALL_ACCESS,
            &objAttr,
            &clientId
        );
        g_ctx.hProcess = hProcess;
        if (status != STATUS_SUCCESS || !g_ctx.hProcess) {
            SetLastError(FormatNtStatusError("打开目标进程失败", status));
            CleanupContext();
            return false;
        }

        // 3. 查找目标hook地址
        RemoteScannerCommon common_scanner;
        ScanResult result;
        if (!common_scanner.SearchForHookAddress(g_ctx.hProcess, result)) {
            SetLastError(result.msg);
            //降级处理,使用原特征搜索逻辑
            RemoteScanner scanner;
            result.reset();
            if (!scanner.SearchForHookAddress(g_ctx.hProcess, result)) {
                SetLastError(result.msg);
                return false;
            }
        } 
        else {
            std::stringstream addrMsg;
            addrMsg << u8"目标函数地址: 0x" << std::hex << result.target;
            SendStatus(addrMsg.str(), 0);
        }

        // 4. 在目标进程中分配数据缓冲区（用于存放密钥）
        SendStatus("正在分配远程数据缓冲区...", 0);
        if (!g_ctx.remoteData.allocate(g_ctx.hProcess, sizeof(SharedKeyData), PAGE_READWRITE)) {
            SetLastError("分配远程数据缓冲区失败");
            CleanupContext();
            return false;
        }

        // 4.1 分配伪栈
        SendStatus("正在分配远程伪栈...", 0);
        const SIZE_T spoofStackSize = 0x8000; // 32KB 伪栈
        if (!g_ctx.spoofStack.allocate(g_ctx.hProcess, spoofStackSize, PAGE_READWRITE)) {
            SetLastError("分配远程伪栈失败");
            CleanupContext();
            return false;
        }
        uintptr_t spoofStackTop = reinterpret_cast<uintptr_t>(g_ctx.spoofStack.get()) + spoofStackSize - 0x20; // 留出对齐空间

        // 5. 初始化IPC
        SendStatus("正在初始化IPC通信...", 0);
        std::string uniqueId = GenerateUniqueId(targetPid);
        g_ctx.ipc = std::make_unique<IPCManager>();
        if (!g_ctx.ipc->Initialize(uniqueId)) {
            DWORD ipcError = GetLastError();
            SetLastError(FormatWin32Error("初始化IPC通信失败", ipcError));
            CleanupContext();
            return false;
        }

        g_ctx.ipc->SetRemoteBuffer(g_ctx.hProcess, g_ctx.remoteData.get());
        g_ctx.ipc->SetDataCallback(OnDataReceived);
        if (!g_ctx.ipc->StartListening()) {
            DWORD ipcError = GetLastError();
            SetLastError(FormatWin32Error("启动IPC监听失败", ipcError));
            CleanupContext();
            return false;
        }

        // 6. 创建hook
        SendStatus("正在准备安装Hook...", 0);
        g_ctx.hooker = std::make_unique<RemoteHooker>(g_ctx.hProcess);
        g_ctx.hooker->EnableHardwareBreakpointMode(false); // ！！暂时不用硬件断点+VEH，测试期间先用稳定的Inline Hook！！

        // 7. 配置Shellcode
        ShellcodeConfig shellcodeConfig{};
        shellcodeConfig.sharedMemoryAddress = g_ctx.remoteData.get(); // 使用远程分配的地址
        shellcodeConfig.eventHandle = nullptr; // 不再使用事件，改用轮询
        shellcodeConfig.trampolineAddress = 0; // 将由RemoteHooker填充
        shellcodeConfig.enableStackSpoofing = true; // 强制开启堆栈伪造
        shellcodeConfig.spoofStackPointer = spoofStackTop;

        // 8. 安装hook
        SendStatus("正在安装远程Hook...", 0);
        if (!g_ctx.hooker->InstallHook(result.target, shellcodeConfig)) {
            DWORD hookError = GetLastError();
            SetLastError(FormatWin32Error("安装Hook失败", hookError));
            CleanupContext();
            return false;
        }

        g_ctx.initialized = true;
        SendStatus("Hook安装成功，现在登录微信...", 1);
        return true;
    }

    void CleanupContext() {
        if (g_ctx.hooker) {
            g_ctx.hooker->UninstallHook();
            g_ctx.hooker.reset();
        }

        if (g_ctx.ipc) {
            g_ctx.ipc->StopListening();
            g_ctx.ipc->Cleanup();
            g_ctx.ipc.reset();
        }

        g_ctx.remoteData.reset();
        g_ctx.spoofStack.reset();

        if (g_ctx.hProcess) {
            CloseHandle(g_ctx.hProcess);
            g_ctx.hProcess = nullptr;
        }

        IndirectSyscalls::Cleanup();

        if (g_ctx.csInitialized) {
            EnterCriticalSection(&g_ctx.dataLock);
            g_ctx.ResetDataQueues();
            LeaveCriticalSection(&g_ctx.dataLock);
            g_ctx.FreeLock();
        }

        g_ctx.initialized = false;
    }
}

// 导出函数
HOOK_API bool InitializeHook(DWORD targetPid) {
    return InitializeContext(targetPid);
}

HOOK_API bool CleanupHook() {
    if (!g_ctx.initialized) {
        return true;
    }
    SendStatus("正在清理Hook...", 0);
    CleanupContext();
    return true;
}

HOOK_API bool PollKeyData(char* keyBuffer, int bufferSize) {
    if (!g_ctx.initialized || !keyBuffer || bufferSize < 65) {
        return false;
    }

    if (g_ctx.csInitialized) {
        EnterCriticalSection(&g_ctx.dataLock);
    }

    if (!g_ctx.hasNewKey) {
        if (g_ctx.csInitialized) {
            LeaveCriticalSection(&g_ctx.dataLock);
        }
        return false;
    }

    size_t copyLen = (g_ctx.pendingKeyData.length() < static_cast<size_t>(bufferSize - 1)) ? g_ctx.pendingKeyData.length() : static_cast<size_t>(bufferSize - 1);
    memcpy(keyBuffer, g_ctx.pendingKeyData.c_str(), copyLen);
    keyBuffer[copyLen] = '\0';
    g_ctx.hasNewKey = false;
    g_ctx.pendingKeyData.clear();

    if (g_ctx.csInitialized) {
        LeaveCriticalSection(&g_ctx.dataLock);
    }

    return true;
}

HOOK_API bool GetStatusMessage(char* statusBuffer, int bufferSize, int* outLevel) {
    if (!g_ctx.initialized || !statusBuffer || bufferSize < 256 || !outLevel) {
        return false;
    }

    if (g_ctx.csInitialized) {
        EnterCriticalSection(&g_ctx.dataLock);
    }

    if (g_ctx.statusQueue.empty()) {
        if (g_ctx.csInitialized) {
            LeaveCriticalSection(&g_ctx.dataLock);
        }
        return false;
    }

    StatusMessage msg = g_ctx.statusQueue.front();
    g_ctx.statusQueue.erase(g_ctx.statusQueue.begin());

    if (g_ctx.csInitialized) {
        LeaveCriticalSection(&g_ctx.dataLock);
    }

    size_t copyLen = (msg.message.length() < static_cast<size_t>(bufferSize - 1)) ? msg.message.length() : static_cast<size_t>(bufferSize - 1);
    memcpy(statusBuffer, msg.message.c_str(), copyLen);
    statusBuffer[copyLen] = '\0';
    *outLevel = msg.level;

    return true;
}

HOOK_API const char* GetLastErrorMsg() {
    return g_lastError.c_str();
}
