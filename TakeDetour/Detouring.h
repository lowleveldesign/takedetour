#pragma once

namespace takedetour {
    typedef struct {
        PCCH FunctionName;
        PVOID* FunctionAddress;
    } FunctionCharacteristics;

    HANDLE start_process(const std::wstring& injectdll, const std::wstring& exe, const std::wstring& args);
    HANDLE attach_to_process(DWORD pid, const std::wstring& injectdll);
    void detach_from_process(HANDLE targetProcess);
}
