#include "../include/remote_scanner_common.h"
#include "../include/string_obfuscator.h"
#include <sstream>

RemoteScannerCommon::RemoteScannerCommon() : hProcess(NULL) {

}

RemoteScannerCommon::~RemoteScannerCommon() {

}

bool RemoteScannerCommon::SearchForHookAddress(HANDLE hProcess, ScanResult& result) {

    if (hProcess == NULL) {
        result.msg = "进程句柄为空";
        return false;
    }

    this->hProcess = hProcess;

    std::string weixinDll = ObfuscatedStrings::GetWeixinDllName();
    RemoteModuleInfo moduleInfo;

    if (!GetRemoteModuleInfo(this->hProcess, weixinDll, moduleInfo)) {
        result.msg = "未找到目标dll模块";
        return false;
    }

    std::string err;
    uintptr_t target = SearchByStringReferenceRemote(moduleInfo, ObfuscatedStrings::GetSignature().c_str(), err);
    if (!target) {
        result.msg = err;
        return false;
    }

    result.target = target;
    return true;
}

uintptr_t RemoteScannerCommon::SearchByStringReferenceRemote(
    const RemoteModuleInfo& mod, 
    const char* signature,
    std::string& err) {

    std::vector<IMAGE_SECTION_HEADER> secs;

    if (!GetRemoteSections(
        (uintptr_t)mod.baseAddress,
        secs))
        return 0;

    IMAGE_SECTION_HEADER rdata{}, text{};

    if (!FindSectionByName(secs, ".rdata", rdata))
        return 0;

    if (!FindSectionByName(secs, ".text", text))
        return 0;

    uintptr_t base = (uintptr_t)mod.baseAddress;

    uintptr_t rdataBase = base + rdata.VirtualAddress;
    uintptr_t textBase = base + text.VirtualAddress;

    SIZE_T rdataSize = max(rdata.SizeOfRawData, rdata.Misc.VirtualSize);

    SIZE_T textSize = max(text.SizeOfRawData, text.Misc.VirtualSize);

    //1. 找到字符串位置 com.Tencent.WCDB.Config.Cipher
    uintptr_t strAddr =FindStringInSectionRemote(rdataBase, rdataSize, signature);

    if (!strAddr) {
        err = "无法找到字符串";
        return 0;
    }

    //2. 查找引用，然后定位 unk_7FFCBEA05AE0，计算 unk_7FFCBEA05AE0实际位置
    /*
    .text:00007FFCB62D9F02 48 8D 0D D7 BB 72 08                    lea     rcx, unk_7FFCBEA05AE0
    .text:00007FFCB62D9F09 48 8D 15 B8 BC 62 06                    lea     rdx, aComTencentWcdb_6 ; "com.Tencent.WCDB.Config.Cipher"
    .text:00007FFCB62D9F10 E8 AB 52 28 FF                          call    sub_7FFCB555F1C0
    */
    BYTE leaRdx[] = { 0x48,0x8D,0x15 };

    auto refs = FindReferenceRemote(
            textBase,
            textSize,
            leaRdx,
            3,
            7,
            3,
            strAddr);

    if (refs.empty()) {
        err = "无法找到字符串引用位置";
        return 0;
    }
 

    uintptr_t leaRdxAddr = refs[0];

    BYTE buf[7];
    if (!ReadRemoteMemory(
        this->hProcess,
        leaRdxAddr - 7,
        buf,
        7))
        return 0;

    if (!(buf[0] == 0x48 &&
        buf[1] == 0x8D &&
        buf[2] == 0x0D))
        return 0;

    INT32 rel = *(INT32*)&buf[3];

    uintptr_t target = (leaRdxAddr - 7) + 7 + rel;

    //3. 再次查找unk_7FFCBEA05AE0引用，定位setCipherKey
    auto refs2 =
        FindReferenceRemote(
            textBase,
            textSize,
            leaRdx,
            3,
            7,
            3,
            target);

    if (refs2.empty()) {
        err = "无法找到目标引用位置";
        return 0;
    }

    //4. 反向查找函数头
    BYTE pat[] = { 0xCC,0xCC,0xCC,0xCC };

    uintptr_t head = SearchBackRemote(refs2[0], pat, 4, 0x100);

    if (!head) {
        err = "无法找到函数头";
        return 0;
    }

    return head + 4;
}

std::vector<uintptr_t> RemoteScannerCommon::FindReferenceRemote(
    uintptr_t textBase, 
    SIZE_T textSize, 
    const BYTE* opcode, 
    size_t opcodeLen, 
    size_t instructionLen, 
    size_t offsetPos, 
    uintptr_t target) {

    const SIZE_T CHUNK = 1 << 20;
    const SIZE_T OVERLAP = instructionLen;

    std::vector<uintptr_t> hits;
    std::vector<BYTE> buf(CHUNK + OVERLAP);

    for (SIZE_T off = 0; off < textSize; off += CHUNK) {
        SIZE_T want = min(CHUNK + OVERLAP, textSize - off);

        if (!ReadRemoteMemory(
            this->hProcess,
            textBase + off,
            buf.data(),
            want))
            continue;

        for (SIZE_T i = 0;
            i + instructionLen <= want;
            ++i) {
            if (memcmp(buf.data() + i,
                opcode,
                opcodeLen) != 0)
                continue;

            INT32 rel = *(INT32*)(buf.data() + i + offsetPos);

            uintptr_t ins = textBase + off + i;

            uintptr_t calc = ins + instructionLen + rel;

            //找到一个直接退出
            if (calc == target) {
                hits.push_back(ins);
                break;
            }
        }
    }

    return hits;
}

uintptr_t RemoteScannerCommon::SearchBackRemote(
    uintptr_t addr,
    const BYTE* pat,
    size_t patLen,
    size_t range) {

    if (range < patLen)
        return 0;

    std::vector<BYTE> buf(range);

    uintptr_t start = addr - range;

    if (!ReadRemoteMemory(
        this->hProcess,
        start,
        buf.data(),
        range))
        return 0;

    for (size_t i = range - patLen + 1; i-- > 0; ) {
        if (memcmp(buf.data() + i, pat, patLen) == 0) {
            return start + i;
        }
    }

    return 0;
}

bool RemoteScannerCommon::GetRemoteSections(uintptr_t base, std::vector<IMAGE_SECTION_HEADER>& secs) {
    IMAGE_DOS_HEADER dos{};
    if (!ReadRemoteMemory(this->hProcess, base, &dos, sizeof(dos)))
        return false;

    if (dos.e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    IMAGE_NT_HEADERS64 nt{};
    if (!ReadRemoteMemory(
        this->hProcess,
        base + dos.e_lfanew,
        &nt,
        sizeof(nt)))
        return false;

    secs.resize(nt.FileHeader.NumberOfSections);

    uintptr_t secAddr =
        base + dos.e_lfanew +
        sizeof(DWORD) +
        sizeof(IMAGE_FILE_HEADER) +
        nt.FileHeader.SizeOfOptionalHeader;

    return ReadRemoteMemory(
        this->hProcess,
        secAddr,
        secs.data(),
        secs.size() * sizeof(IMAGE_SECTION_HEADER));
}

bool RemoteScannerCommon::FindSectionByName(
    const std::vector<IMAGE_SECTION_HEADER>& secs, 
    const char* name, IMAGE_SECTION_HEADER& out) {

    for (auto& s : secs) {
        if (_stricmp((char*)s.Name, name) == 0) {
            out = s;
            return true;
        }
    }
    return false;
}

uintptr_t RemoteScannerCommon::FindStringInSectionRemote(uintptr_t secBase, SIZE_T secSize, const char* str) {
    size_t len = strlen(str);
    const SIZE_T CHUNK = 1 << 20;

    std::vector<BYTE> buf(CHUNK + len);

    for (SIZE_T off = 0; off < secSize; off += CHUNK) {
        SIZE_T want =
            min(CHUNK + len, secSize - off);

        if (!ReadRemoteMemory(
            this->hProcess,
            secBase + off,
            buf.data(),
            want))
            continue;

        for (SIZE_T i = 0; i + len <= want; ++i) {
            if (memcmp(buf.data() + i, str, len) == 0)
                return secBase + off + i;
        }
    }

    return 0;
}
