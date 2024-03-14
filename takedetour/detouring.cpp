#include <Windows.h>
#include <Psapi.h>
#include <cassert>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <stdexcept>

#include <detours/detours.h>
#include <wil/result.h>
#include "Detouring.h"

namespace takedetour
{
    // helper functions
    std::string ws2s(const std::wstring& wstr)
    {
        auto len = ::WideCharToMultiByte(CP_OEMCP, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
        if (len == 0) {
            THROW_LAST_ERROR_MSG("Error converting '%ws' to multibyte", wstr.c_str());
        }

        std::vector<char> out(len);
        if (len != ::WideCharToMultiByte(CP_OEMCP, 0, wstr.c_str(), -1, out.data(), static_cast<int>(out.size()), NULL, NULL)) {
            THROW_LAST_ERROR_MSG("Error converting '%ws' to multibyte (invalid len)", wstr.c_str());
        }

        return std::string{ out.begin(), out.end() };
    }

    HMODULE locate_module_in_process(const HANDLE hProcess, const std::wstring& module_name)
    {
        HMODULE modules[1024];
        DWORD cb = sizeof(modules);
        DWORD requiredcb;

        THROW_IF_WIN32_BOOL_FALSE(::EnumProcessModules(hProcess, modules, cb, &requiredcb));

        if (requiredcb > cb) {
            throw std::runtime_error{ "EnumProcessModules failed: the modules buffer was too small." };
        }

        wchar_t name[MAX_PATH];
        for (DWORD i = 0; i < requiredcb / sizeof(HMODULE); i++) {
            DWORD len = ::GetModuleBaseName(hProcess, modules[i], name, MAX_PATH);
            if (len == 0) {
                continue;
            }

            if (module_name.compare(0, len, name) == 0) {
                return modules[i];
            }
        }

        return NULL;
    }

    PVOID locate_exported_function(HMODULE module_handle, const char* function_name)
    {
        PF_DETOUR_ENUMERATE_EXPORT_CALLBACK callback = [](PVOID pContext, ULONG nOrdinal, LPCSTR pszName, PVOID pCode) {
            auto func = reinterpret_cast<FunctionCharacteristics*>(pContext);
            if (strcmp(func->FunctionName, pszName) == 0) {
                *(func->FunctionAddress) = pCode;
                return FALSE;
            }
            return TRUE;
        };

        PVOID function_address{};
        FunctionCharacteristics context{ function_name, &function_address };
        THROW_IF_WIN32_BOOL_FALSE(::DetourEnumerateExports(module_handle, &context, callback));
        return function_address;
    }

    HANDLE start_process(const std::wstring& injectdll, const std::wstring& exe, const std::wstring& args)
    {
        ::STARTUPINFO si;
        ::PROCESS_INFORMATION pi;

        ::ZeroMemory(&si, sizeof(si));
        ::ZeroMemory(&pi, sizeof(pi));
        si.cb = sizeof(si);

        std::vector v(args.begin(), args.end());
        THROW_IF_WIN32_BOOL_FALSE(
            ::DetourCreateProcessWithDllEx(exe.c_str(), v.size() == 0 ? NULL : v.data(), NULL, NULL, TRUE,
                CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED, NULL, NULL, &si, &pi,
                ws2s(injectdll).c_str(), NULL));

        ::ResumeThread(pi.hThread);
        ::CloseHandle(pi.hThread);

        return pi.hProcess;
    }

    HANDLE attach_to_process(DWORD pid, const std::wstring& injectdll)
    {
        DWORD flags = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
            PROCESS_VM_WRITE | PROCESS_VM_READ | SYNCHRONIZE;
        auto process_handle = ::OpenProcess(flags, FALSE, pid);
        THROW_LAST_ERROR_IF_NULL(process_handle);

        auto kernel32 = locate_module_in_process(process_handle, L"\\kernel32.dll");
        if (!kernel32) {
            throw std::runtime_error{ "Can't find kernel32.dll in the remote process." };
        }

        PVOID fn_LoadLibraryWAddress = locate_exported_function(kernel32, "LoadLibraryW");
        assert(fn_LoadLibraryWAddress != NULL);

        // allocate injection buffer
        SIZE_T injectdll_len_in_bytes = (injectdll.length() + 1) * sizeof(wchar_t);
        PBYTE injection_buffer = (PBYTE)::VirtualAllocEx(process_handle, NULL, injectdll_len_in_bytes,
            MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        THROW_LAST_ERROR_IF_NULL(injection_buffer);

        THROW_IF_WIN32_BOOL_FALSE(::WriteProcessMemory(process_handle, injection_buffer,
            injectdll.c_str(), injectdll_len_in_bytes, NULL));

        DWORD thread_id{};
        wil::unique_handle injected_thread{ ::CreateRemoteThread(process_handle, NULL, 0, (LPTHREAD_START_ROUTINE)fn_LoadLibraryWAddress,
            injection_buffer, 0, &thread_id) };
        if (!injected_thread.is_valid()) {
            THROW_LAST_ERROR_MSG("CreateRemoteThread");
        }

        THROW_LAST_ERROR_IF_MSG(::WaitForSingleObject(injected_thread.get(), INFINITE) == WAIT_FAILED, "WaitForSingleObject (remote thread)");

        LOG_IF_WIN32_BOOL_FALSE(::VirtualFreeEx(process_handle, injection_buffer, 0, MEM_RELEASE));

        return process_handle;
    }

    void detach_from_process(HANDLE process_handle)
    {
        HMODULE modules[1024];
        DWORD cb = sizeof(modules);
        DWORD requiredcb;

        THROW_IF_WIN32_BOOL_FALSE(::EnumProcessModules(process_handle, modules, cb, &requiredcb));

        HMODULE kernel32 = locate_module_in_process(process_handle, L"kernel32.dll");
        if (!kernel32) {
            throw std::runtime_error{ "Can't find kernel32.dll in the remote process." };
        }
        PVOID fn_FreeLibrary = locate_exported_function(kernel32, "FreeLibrary");
        assert(fn_FreeLibrary != NULL);

        HMODULE injectdll = locate_module_in_process(process_handle, L"injectdll64.dll");
        if (injectdll == NULL) {
            HMODULE injectdll = locate_module_in_process(process_handle, L"injectdll32.dll");
            if (injectdll == NULL) {
                throw std::runtime_error("Can't find the injected dll in the remote process.");
            }
        }

        DWORD thread_id{};
        wil::unique_handle injected_thread{ ::CreateRemoteThread(process_handle, NULL, 0, (LPTHREAD_START_ROUTINE)fn_FreeLibrary, injectdll, 0, &thread_id) };
        if (!injected_thread.is_valid()) {
            THROW_LAST_ERROR_MSG("CreateRemoteThread (detach)");
        }

        THROW_LAST_ERROR_IF_MSG(::WaitForSingleObject(injected_thread.get(), INFINITE) == WAIT_FAILED, "WaitForSingleObject (detach)");
    }
}