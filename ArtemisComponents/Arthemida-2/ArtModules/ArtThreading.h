/*
	Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC & holmes0
*/
/**
* Assignee: holmes0
* Done:
*		Protect threads with termination-preventing flags (BSOD on manual termination)
*		Protect threads with suspension-preventing flags on Win10 19H1+ (ignores suspension requests)
*
* TBD in future parts:
*		Thread intercommunication, one thread get suspended/terminated - every other thread knows about it.
*		Thread communication with main MTA thread (if someone kills/suspends all threads, main thread will take care of it)
*/
#include "../API/ArtemisInterface.h"
#pragma comment(lib, "Version.lib")
using namespace ArtemisData;

class ArtThreading
{
public:
	class SpinLock
	{
	private:
		std::atomic_flag _lockFlag;

	public:
		SpinLock()
			: _lockFlag{ ATOMIC_FLAG_INIT }
		{
		}

		void lock()
		{
			while (_lockFlag.test_and_set(std::memory_order_acquire))
			{
			}
		}

		bool try_lock()
		{
			return !_lockFlag.test_and_set(std::memory_order_acquire);
		}

		void unlock()
		{
			_lockFlag.clear();
		}
	};


private:
	typedef NTSTATUS(NTAPI* pfnNtCreateThreadEx)
		(
			OUT PHANDLE hThread,
			IN ACCESS_MASK DesiredAccess,
			IN PVOID ObjectAttributes,
			IN HANDLE ProcessHandle,
			IN PVOID lpStartAddress,
			IN PVOID lpParameter,
			IN ULONG Flags,
			IN SIZE_T StackZeroBits,
			IN SIZE_T SizeOfStackCommit,
			IN SIZE_T SizeOfStackReserve,
			OUT PVOID lpBytesBuffer);

	typedef NTSTATUS(NTAPI* pfnNtSetInformationThread)(
		HANDLE ThreadHandle,
		Utils::THREAD_INFORMATION_CLASS ThreadInformationClass,
		PVOID ThreadInformation,
		ULONG ThreadInformationLength
		);


#define THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE 0x40
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004

	static bool Is19H1OrGreater()
	{
		DWORD dwHandle;
		DWORD cbInfo = GetFileVersionInfoSizeExW(FILE_VER_GET_NEUTRAL, L"kernel32.dll", &dwHandle);
		std::vector<char> buffer(cbInfo);
		GetFileVersionInfoExW(FILE_VER_GET_NEUTRAL, L"kernel32.dll", dwHandle, buffer.size(), &buffer[0]);

		void* p = nullptr;
		UINT size = 0;
		VerQueryValueW(buffer.data(), L"\\", &p, &size);

		VS_FIXEDFILEINFO* vsFixedFileInfo = (VS_FIXEDFILEINFO*)p;
		if (HIWORD(vsFixedFileInfo->dwFileVersionLS) > 18362) return true;
		return false;
	}


public:
	static HANDLE CreateProtectedThread(PVOID lpStartAddress, PVOID lpParameter)
	{
		pfnNtCreateThreadEx fnNtCreateThreadEx = (pfnNtCreateThreadEx)Utils::RuntimeIatResolver("ntdll.dll", "NtCreateThreadEx");
		if (fnNtCreateThreadEx == NULL) return INVALID_HANDLE_VALUE;

		HANDLE hThread = NULL;

		if (Is19H1OrGreater())
		{
#ifdef ARTEMIS_DEBUG
			fnNtCreateThreadEx(&hThread, MAXIMUM_ALLOWED, nullptr, GetCurrentProcess(), lpStartAddress, lpParameter, 0, 0, 0, 0, nullptr);
#else
			fnNtCreateThreadEx(&hThread, MAXIMUM_ALLOWED, nullptr, GetCurrentProcess(), lpStartAddress, lpParameter, THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE | THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER, 0, 0, 0, nullptr);
#endif
		}
		else
		{
#ifdef ARTEMIS_DEBUG
			fnNtCreateThreadEx(&hThread, MAXIMUM_ALLOWED, nullptr, GetCurrentProcess(), lpStartAddress, lpParameter, 0, 0, 0, 0, nullptr);
#else
			fnNtCreateThreadEx(&hThread, MAXIMUM_ALLOWED, nullptr, GetCurrentProcess(), lpStartAddress, lpParameter, THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER, 0, 0, 0, nullptr);
#endif
		}

		Utils::SetPrivilege(NULL, SE_DEBUG_NAME, TRUE);

		pfnNtSetInformationThread NtSetInformationThread = (pfnNtSetInformationThread)Utils::RuntimeIatResolver("ntdll.dll", "NtSetInformationThread");
#ifndef ARTEMIS_DEBUG // Dangerous protection (BSOD on manual thread termination only)
		ULONG Enable = true;
		NTSTATUS ntThreadBreakOnTermination = NtSetInformationThread(hThread, Utils::ThreadBreakOnTermination, &Enable, sizeof(Enable));
#else
		if (ntThreadBreakOnTermination != 0) Utils::LogInFile(ARTEMIS_LOG, "[ERROR/ArtThreading] Failed to set ThreadBreakOnTermination! NTSTATUS: 0x%08X\n", ntThreadBreakOnTermination);
		printf("[ArtThreading] Created protected thread handle 0x%08X with param 0x%08X\n", (DWORD)lpStartAddress, (DWORD)lpParameter);
#endif

		//m_protectedThreads.push_back(hThread);
		return hThread;
	}

	static void Pulse(HANDLE hCallingThread)
	{

	}
};

namespace ThreadGuard
{
	typedef NTSTATUS(NTAPI* pfnNtQueryInformationThread)(
		HANDLE ThreadHandle,
		Utils::THREAD_INFORMATION_CLASS ThreadInformationClass,
		PVOID ThreadInformation,
		ULONG ThreadInformationLength,
		PULONG ReturnLength
	);

	void __stdcall ThreadScanner(ArtemisConfig* cfg);
}
