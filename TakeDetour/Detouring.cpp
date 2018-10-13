#include <Windows.h>
#include <Psapi.h>
#include <cassert>
#include <cinttypes>
#include <iostream>
#include <sstream>
#include <string>
#include <locale>
#include <codecvt>
#include <memory>

#include "Detouring.h"
#include "../include/detours.h"

using namespace std;

string ws2s(const std::wstring& wstr)
{
    using convert_typeX = std::codecvt_utf8<wchar_t>;
    std::wstring_convert<convert_typeX, wchar_t> converterX;

    return converterX.to_bytes(wstr);
}

//----------------------------------------------------------------

void ThrowWin32Exception(const char *funcname)
{
    DWORD dwError = GetLastError();
    ostringstream os;
    os << funcname << " failed: 0x" << hex << dwError << endl;
    throw exception(os.str().c_str());
}

//----------------------------------------------------------------

HANDLE StartProcess(const string& injectdll, const wstring& exe, const wstring& args)
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    auto command = make_unique<wchar_t[]>(args.length() + 1);
    wmemcpy_s(command.get(), args.length(), args.c_str(), args.length());
    command.get()[args.length()] = L'\0';

    if (!DetourCreateProcessWithDllEx(exe.c_str(), command.get(),
        NULL, NULL, TRUE,
        CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED,
        NULL, NULL, &si, &pi, injectdll.c_str(), NULL)) {
        ThrowWin32Exception("DetourCreateProcessWithDllEx");
    }

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);

    return pi.hProcess;
}

//----------------------------------------------------------------

BOOL CALLBACK EnumerateExportCallback(PVOID pContext, ULONG nOrdinal, LPCSTR pszName, PVOID pCode)
{
    FunctionCharacteristics* func = reinterpret_cast<FunctionCharacteristics*>(pContext);
    if (strcmp(func->FunctionName, pszName) == 0) {
        *(func->FunctionAddress) = pCode;
        return FALSE;
    }
    return TRUE;
}

//----------------------------------------------------------------

HMODULE LocateModuleInRemoteProcess(HANDLE hProcess, const wstring& modulePath)
{
    HMODULE modules[1024];
    DWORD cb = sizeof(modules);
    DWORD requiredcb;
    if (!EnumProcessModules(hProcess, modules, cb, &requiredcb)) {
        ThrowWin32Exception("EnumProcessModules");
    }

    if (requiredcb > cb) {
        throw exception("EnumProcessModules failed: the modules buffer was too small.");
    }

    for (DWORD i = 0; i < requiredcb / sizeof(HMODULE); i++) {
        wchar_t moduleName[MAX_PATH];
        DWORD moduleNameLength = GetModuleFileNameEx(hProcess, modules[i], moduleName, sizeof(moduleName) / sizeof(wchar_t));
        // FIXME: if moduleNameLength == MAX_PATH there is chance the module name array was too small
        if (moduleNameLength == 0) {
            ThrowWin32Exception("GetModuleFileNameEx");
        }
        if (moduleNameLength >= modulePath.length()
            && _wcsicmp(modulePath.c_str(), moduleName + moduleNameLength - modulePath.length()) == 0) {
            return modules[i];
        }
    }
    return NULL;
}

//----------------------------------------------------------------

// Return address of the LoadLibrary function in the remote process
PVOID LocateExportedFunctionInModule(HMODULE moduleHandle, const char* functionName)
{
    // we found the kernel32.dll
    PVOID functionAddress = nullptr;
    FunctionCharacteristics context = { functionName, &functionAddress };
    if (!DetourEnumerateExports(moduleHandle, &context, EnumerateExportCallback)) {
        ThrowWin32Exception("DetourEnumerateExports");
    }
    return functionAddress;
}

//----------------------------------------------------------------

HANDLE AttachToProcess(DWORD pid, const wstring& injectdll)
{
    DWORD flags = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ | SYNCHRONIZE;
    HANDLE targetProcess = OpenProcess(flags, FALSE, pid);
    if (targetProcess == NULL) {
        ThrowWin32Exception("OpenProcess");
    }

    HMODULE kernel32 = LocateModuleInRemoteProcess(targetProcess, L"\\kernel32.dll");
    if (!kernel32) {
        throw exception("Can't find kernel32.dll in the remote process.");
    }

    PVOID LoadLibraryWAddress = LocateExportedFunctionInModule(kernel32, "LoadLibraryW");
    assert(LoadLibraryWAddress != NULL);

    // allocate injection buffer
    SIZE_T injectdllLengthInBytes = (injectdll.length() + 1) * sizeof(wchar_t);
    PBYTE injectionBuffer = (PBYTE)VirtualAllocEx(targetProcess, NULL, injectdllLengthInBytes,
        MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!injectionBuffer) {
        ThrowWin32Exception("VirtualAllocEx");
    }
    SIZE_T n;
    if (!WriteProcessMemory(targetProcess, injectionBuffer, injectdll.c_str(), injectdllLengthInBytes, &n)
        || n != injectdllLengthInBytes) {
        ThrowWin32Exception("WriteProcessMemory");
    }

    HANDLE injectedThread;
    DWORD injecteeThreadId;
    injectedThread = CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryWAddress,
        injectionBuffer, 0, &injecteeThreadId);
    if (!injectedThread) {
        ThrowWin32Exception("CreateRemoteThread");
    }

    if (WaitForSingleObject(injectedThread, INFINITE) == WAIT_FAILED) {
        ThrowWin32Exception("WaitForSingleObject (remote thread)");
    }
    CloseHandle(injectedThread);

    if (!VirtualFreeEx(targetProcess, injectionBuffer, 0, MEM_RELEASE)) {
        ThrowWin32Exception("VirtualFreeEx");
    }

    return targetProcess;
}

//----------------------------------------------------------------

void DetachFromProcess(HANDLE targetProcess, const wstring& injectdll)
{
    HMODULE modules[1024];
    DWORD cb = sizeof(modules);
    DWORD requiredcb;
    if (!EnumProcessModules(targetProcess, modules, cb, &requiredcb)) {
        ThrowWin32Exception("EnumProcessModules");
    }

    HMODULE kernel32 = LocateModuleInRemoteProcess(targetProcess, L"\\kernel32.dll");
    if (!kernel32) {
        throw exception("Can't find kernel32.dll in the remote process.");
    }
    PVOID FreeLibraryAddress = LocateExportedFunctionInModule(kernel32, "FreeLibrary");
    assert(FreeLibraryAddress != NULL);

    HMODULE injectdllHandle = LocateModuleInRemoteProcess(targetProcess, injectdll);
    if (injectdllHandle == NULL) {
        throw exception("Can't find the injected dll in the remote process.");
    }

    HANDLE injectedThread;
    DWORD injecteeThreadId;
    injectedThread = CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)FreeLibraryAddress,
        injectdllHandle, 0, &injecteeThreadId);
    if (!injectedThread) {
        ThrowWin32Exception("CreateRemoteThread");
    }

    if (WaitForSingleObject(injectedThread, INFINITE) == WAIT_FAILED) {
        ThrowWin32Exception("WaitForSingleObject (remote thread)");
    }
    CloseHandle(injectedThread);
}