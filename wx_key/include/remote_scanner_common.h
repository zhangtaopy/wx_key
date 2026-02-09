#ifndef REMOTE_SCANNER_COMMON_H
#define REMOTE_SCANNER_COMMON_H

#include <Windows.h>
#include <vector>
#include <string>
#include "remote_scanner_base.h"

class RemoteScannerCommon 
    : public IRemoteScannerBase {

public:
    RemoteScannerCommon();
    ~RemoteScannerCommon();

public:
    virtual bool SearchForHookAddress(HANDLE hProcess, ScanResult& result) override;

protected:
    uintptr_t SearchByStringReferenceRemote(
        const RemoteModuleInfo& mod,
        const char* signature,
        std::string& err);

    std::vector<uintptr_t> FindReferenceRemote(
        uintptr_t textBase,
        SIZE_T textSize,
        const BYTE* opcode,
        size_t opcodeLen,
        size_t instructionLen,
        size_t offsetPos,
        uintptr_t target);

    uintptr_t SearchBackRemote(
        uintptr_t addr,
        const BYTE* pat,
        size_t patLen,
        size_t range);

    bool GetRemoteSections(
        uintptr_t base,
        std::vector<IMAGE_SECTION_HEADER>& secs);

    bool FindSectionByName(
        const std::vector<IMAGE_SECTION_HEADER>& secs,
        const char* name,
        IMAGE_SECTION_HEADER& out);

    uintptr_t FindStringInSectionRemote(
        uintptr_t secBase,
        SIZE_T secSize,
        const char* str);

private:
    HANDLE hProcess;
};

#endif