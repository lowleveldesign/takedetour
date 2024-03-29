#include <Windows.h>

#include <cassert>
#include <vector>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>
#include <variant>
#include <exception>
#include <ranges>

#include <detours/detours.h>
#include <wil/resource.h>
#include <wil/result.h>

#include "Detouring.h"
#include "resource.h"

namespace fs = std::filesystem;

bool stopRequested = false;

// FIXME: take from resource
void show_usage() {
	std::cout << "TakeDetour v1.0" << std::endl;
	std::cout << "Copyright (C) 2018 Sebastian Solnica (@lowleveldesign)" << std::endl << std::endl;

	std::cout << "TakeDetour.exe OPTIONS <pid | exe_path args>" << std::endl << std::endl;
	std::cout << "OPTIONS include:" << std::endl;
	std::cout << "  -w    wait for Ctrl+C to finish and unload the injected DLL" << std::endl;
	std::cout << "  -h    show help" << std::endl;
	std::cout << "  -v    show verbose logs" << std::endl;
}

typedef struct _CommandLineArgs
{
	bool show_help;
	bool wait_for_target;
	std::variant<unsigned int, std::tuple<std::wstring, std::wstring>> target;

	bool target_process_exists() const noexcept {
		return std::get_if<0>(&target) != nullptr;
	}
} CommandLineArgs;

CommandLineArgs parse_args(wchar_t* argv[], int argc) {
	CommandLineArgs result{};

	const std::vector<std::wstring> args{ argv + 1, argv + argc };
	std::wstring inject_config{};

	auto iter = args.begin();
	while (iter != args.end()) {
		if (*iter == L"-h") {
			result.show_help = true;
		} else if (*iter == L"-w") {
			result.wait_for_target = true;
		} else {
			// anything other than these two options stops parsing
			break;
		}
		iter++;
	}

	if (!result.show_help) {
		if (iter == args.end()) {
			throw std::invalid_argument{ "missing target process information" };
		}
		auto pid = std::wcstoul(iter->c_str(), nullptr, 10);
		if (pid > 0) {
			if (pid > UINT32_MAX) {
				throw std::invalid_argument{ "invalid PID" };
			}
			result.target = static_cast<unsigned int>(pid);
		} else {
			std::wstring exe_path{ *iter };
			std::wstring exe_args{};
			while (++iter != args.end()) {
				exe_args += *iter;
				exe_args += L' ';
			}

			result.target = std::make_tuple(exe_path, exe_args);
		}
	}

	return result;
}

BOOL WINAPI handle_console_interrupt(DWORD dwCtrlType) {
	std::cout << "INFO: Received Ctrl + C. Stopping." << std::endl;
	stopRequested = true;
	return TRUE;
}

fs::path unpack_dependencies() {
	auto unpack_binary_file = [](int resid, const std::wstring& dest_path) {
		// find location of the resource and get handle to it
		auto resource_dll = ::FindResource(NULL, MAKEINTRESOURCE(resid), L"BINARY");
		THROW_LAST_ERROR_IF_NULL(resource_dll);

		// loads the specified resource into global memory.
		auto resource = ::LoadResource(NULL, resource_dll);
		THROW_LAST_ERROR_IF_NULL(resource);

		// get a pointer to the loaded resource!
		const auto resource_data = static_cast<char*>(::LockResource(resource));
		THROW_LAST_ERROR_IF_NULL(resource_data);

		// determine the size of the resource, so we know how much to write out to file!
		auto resource_size = ::SizeofResource(NULL, resource_dll);
		THROW_LAST_ERROR_IF_MSG(resource_size == 0, "SizeofResource");

		std::ofstream outputFile(dest_path, std::ios::binary);
		outputFile.write(resource_data, resource_size);
		outputFile.close();
	};

	wchar_t buffer[MAX_PATH + 1];
	auto len = ::GetTempPath(MAX_PATH + 1, buffer);
	assert(len <= MAX_PATH + 1);
	THROW_LAST_ERROR_IF(len == 0);

	fs::path binaries_path{ {buffer, len} };
	binaries_path /= L"takedetour";
	THROW_LAST_ERROR_IF_MSG(!::CreateDirectory(binaries_path.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS,
		"Creation of the unpack folder failed.");

	// unpack all the binaries from resources
	unpack_binary_file(IDR_BINARY1, binaries_path / L"injectdll64.dll");
	unpack_binary_file(IDR_BINARY2, binaries_path / L"injectdll32.dll");

	return binaries_path;
}

template <typename T>
const T* safe_cstr(const T* s) {
	static std::basic_string<T> empty{};

	if (s == nullptr) {
		return empty.c_str();
	}

	return s;
}

int wmain(int argc, wchar_t* argv[]) {
	try {
		auto args = parse_args(argv, argc);

		if (args.show_help) {
			show_usage();
			return 0;
		}

		auto injectdll = unpack_dependencies() / "injectdll64.dll";

		auto start_process = [&args, &injectdll]() {
			auto& target = std::get<1>(args.target);
			auto& exe = std::get<0>(target);
			auto& exe_args = std::get<1>(target);
			return takedetour::start_process(injectdll, exe, exe_args);
		};

		const unsigned int* ppid = std::get_if<0>(&args.target);
		wil::unique_process_handle target{ ppid == nullptr ? start_process() : takedetour::attach_to_process(*ppid, injectdll) };

		THROW_IF_WIN32_BOOL_FALSE(::SetConsoleCtrlHandler(handle_console_interrupt, TRUE));

		if (args.wait_for_target) {
			std::cout << std::endl << (!args.target_process_exists() ? "Press Ctrl + C to stop the target process." :
				"Press Ctrl + C to stop and unload the DLL from the target process.") << std::endl;
			while (!stopRequested) {
				DWORD waitResult = ::WaitForSingleObject(target.get(), 200);
				if (waitResult == WAIT_OBJECT_0) {
					std::cout << "INFO: Target process exited. Stopping." << std::endl;
					break;
				}
				THROW_LAST_ERROR_IF_MSG(waitResult == WAIT_FAILED, "WaitForSingleObject");
			}

			DWORD exitCode;
			if (stopRequested && ::GetExitCodeProcess(target.get(), &exitCode) && exitCode == STILL_ACTIVE) {
				if (!args.target_process_exists()) {
					THROW_IF_WIN32_BOOL_FALSE(::TerminateProcess(target.get(), 1));
					std::cout << "INFO: Target process killed." << std::endl;
				} else {
					takedetour::detach_from_process(target.get());
					std::cout << "INFO: Injected DLL detached from the target process." << std::endl;
				}
			}
		}
	} catch (wil::ResultException& ex) {
		auto& failinfo = ex.GetFailureInfo();
		std::wcerr << std::endl
			<< L"---------------------------" << std::endl
			<< L"WIN32 error: 0x" << std::hex << ex.GetErrorCode() << std::endl
			<< L"Message: " << safe_cstr(failinfo.pszMessage) << std::endl
			<< L"---------------------------" << std::endl
			<< safe_cstr(failinfo.pszFunction) << std::endl
			<< L"---------------------------" << std::endl
			<< safe_cstr(failinfo.pszCode) << std::endl;
	} catch (std::exception& ex) {
		std::cerr << std::endl << "Runtime error: " << ex.what() << std::endl;
		return 1;
	}

	return 0;
}
