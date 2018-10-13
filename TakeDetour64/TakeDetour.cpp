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
#include "../TakeDetour/Detouring.h"

#include "../include/detours.h"

using namespace std;

bool stopRequested = false;

BOOL WINAPI HandleConsoleInterrupt(DWORD dwCtrlType);

int32_t wmain(int32_t argc, wchar_t *argv[])
{
    assert(argc >= 2);

    int argumentIndex = 1;
    bool waitForTarget = false;
    if (wcscmp(argv[1], L"-w") == 0) {
        waitForTarget = true;
        argumentIndex++;
    }

    DWORD pid = wcstoul(argv[argumentIndex], nullptr, 10);
    // this version can only attach to a process
    assert(pid != 0);
    try {
        wchar_t buffer[MAX_PATH];
        DWORD len = GetModuleFileName(NULL, buffer, MAX_PATH);
        // FIXME: if moduleNameLength == MAX_PATH there is chance the module name array was too small
        if (len == 0) {
            ThrowWin32Exception("GetModuleFileName");
        }
        wstring binaryPath = buffer;
        auto separatorIndex = binaryPath.find_last_of(L"\\/");
        assert(separatorIndex != string::npos);
        if (separatorIndex == string::npos) {
            throw exception("Bad entry binary path");
        }
        wstring injectdll = binaryPath.substr(0, separatorIndex) + L"\\InjectDll64.dll";
        cout << "INFO: Attaching to the target process (" << pid << ")." << endl;
        HANDLE targetProcess = AttachToProcess(pid, injectdll);

        if (!SetConsoleCtrlHandler(HandleConsoleInterrupt, TRUE)) {
            ThrowWin32Exception("SetConsoleCtrlHandler");
        }
        if (waitForTarget) {
            cout << endl << "Press Ctrl + C to stop and unload the DLL from the target process." << endl;
            while (!stopRequested) {
                DWORD waitResult = WaitForSingleObject(targetProcess, 200);
                if (waitResult == WAIT_OBJECT_0) {
                    cout << "INFO: Target process exited. Stopping." << endl;
                    break;
                }
                if (waitResult == WAIT_FAILED) {
                    ThrowWin32Exception("WaitForSingleObject");
                }
            }

            DWORD exitCode;
            if (stopRequested && GetExitCodeProcess(targetProcess, &exitCode) && exitCode == STILL_ACTIVE) {
                DetachFromProcess(targetProcess, injectdll);
            }
        }
        CloseHandle(targetProcess);
    } catch (exception& ex) {
        cerr << endl << "ERROR: " << ex.what() << endl;
        return 1;
    }

    return 0;
}

BOOL WINAPI HandleConsoleInterrupt(DWORD dwCtrlType)
{
    cout << "INFO: Received Ctrl + C. Stopping." << endl;
    stopRequested = true;
    return TRUE;
}