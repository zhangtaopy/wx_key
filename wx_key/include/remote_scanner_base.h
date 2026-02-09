#ifndef REMOTE_SCANNER_BASE_H
#define REMOTE_SCANNER_BASE_H

#include <string>
#include <Psapi.h>
#include "../include/syscalls.h"

#pragma comment(lib, "Psapi.lib")

struct ScanResult
{
    uintptr_t target;
    std::string msg;

    ScanResult() {
        target = NULL;
    }

    void reset() {
        target = NULL;
        msg.clear();
    }
};

struct RemoteModuleInfo {
    HMODULE baseAddress;
    SIZE_T imageSize;
    std::string moduleName;
};

class IRemoteScannerBase
{
public:
    IRemoteScannerBase() {};
    virtual ~IRemoteScannerBase() {};

public:
    virtual bool SearchForHookAddress(HANDLE hProcess, ScanResult& result) = 0;

protected:
    bool GetRemoteModuleInfo(HANDLE hProcess, const std::string& moduleName, RemoteModuleInfo& outInfo)
    {
        HMODULE hMods[1024];
        DWORD cbNeeded;

        if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            return false;
        }

        DWORD moduleCount = cbNeeded / sizeof(HMODULE);

        for (DWORD i = 0; i < moduleCount; i++) {
            char szModName[MAX_PATH];

            if (GetModuleBaseNameA(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(char))) {
                if (_stricmp(szModName, moduleName.c_str()) == 0) {
                    MODULEINFO modInfo;
                    if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                        outInfo.baseAddress = hMods[i];
                        outInfo.imageSize = modInfo.SizeOfImage;
                        outInfo.moduleName = szModName;
                        return true;
                    }
                }
            }
        }

        return false;
    }

    bool ReadRemoteMemory(HANDLE hProcess, uintptr_t address, void* buffer, SIZE_T size) {
        SIZE_T bytesRead = 0;
        NTSTATUS status = IndirectSyscalls::NtReadVirtualMemory(
            hProcess,
            (PVOID)address,
            buffer,
            size,
            &bytesRead
        );

        return (status == 0 && bytesRead == size);
    }
};

#endif
