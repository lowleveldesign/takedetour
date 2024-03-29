// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>
#include <iostream>
#include <sstream>
#include <detours/detours.h>

using namespace std;

static BOOL(WINAPI * TrueCreateDirectory)(
    LPCWSTR               lpPathName,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes
) = CreateDirectory;

BOOL WINAPI TracedCreateDirectory(
    LPCWSTR               lpPathName,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes
)
{
    wostringstream output;
    output << L"Traced CreateDirectory: " << lpPathName;
    OutputDebugString(output.str().c_str());

    return TrueCreateDirectory(lpPathName, lpSecurityAttributes);
}


BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    LONG error;
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DetourRestoreAfterWith();

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)TrueCreateDirectory, TracedCreateDirectory);
        error = DetourTransactionCommit();
        if (error != NO_ERROR) {
            wostringstream output;
            output << L"Error detouring: " << error;
            OutputDebugString(output.str().c_str());
        }
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)TrueCreateDirectory, TracedCreateDirectory);
        error = DetourTransactionCommit();
        if (error != NO_ERROR) {
            wostringstream output;
            output << L"Error detouring: " << error;
            OutputDebugString(output.str().c_str());
        }
        break;
    }
    return TRUE;
}

