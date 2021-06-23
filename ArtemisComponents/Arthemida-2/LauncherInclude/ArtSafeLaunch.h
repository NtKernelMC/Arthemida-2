#pragma once
#include <Windows.h>
#include <stdio.h>
#include <map>
#include <winternl.h>
#include "MiniJumper.h"
#include "../ArtUtils/sigscan.h"
#include "../ArtUtils/WinReg.hpp"
#include <random>
#define SAFE_LAUNCH_DEBUG

#define AFL_BUF_SIZE 22
constexpr wchar_t AFL_SM_NAME[] = L"Global\\NT";
constexpr unsigned char AFL_SECRET_GUID[] = {
	0x6d, 0x7a, 0x19, 0x29, 0xfa, 0xe2, 0x4f, 0x1d, 0x96, 0x32, 0x48, 0xad, 0x02, 0x71, 0x48, 0x46
};

void AFL_XOR(void* pBuffer, size_t size, DWORD dwKey)
{
	BYTE* pMask = new BYTE[size];
	for (size_t i = 0; i < size; i += 4)
	{
		memcpy(&pMask[i], (BYTE*)&dwKey, 4);
	}

	for (size_t i = 0; i < size; i++)
	{
		((BYTE*)pBuffer)[i] ^= pMask[i];
	}

	delete[] pMask;
}

namespace SafeLaunch
{
	DWORD dwNtCreateUserProcess = 0x0;
	BYTE  bSyscallCode = 0x0;
	__declspec(naked) NTSTATUS NTAPI NtCreateUserProcess(
		PUNICODE_STRING      ImagePath,
		ULONG                ObjectAttributes,
		PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
		PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
		PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
		HANDLE               ParentProcess,
		BOOLEAN              InheritHandles,
		HANDLE               DebugPort,
		HANDLE               ExceptionPort,
		void*				 ProcessInformation
	)
	{
		__asm {
			mov al, bSyscallCode
			mov edx, fs:[0xC0]
			call edx
			ret 0x2C
		}
	}
	class ProcessGate sealed
	{
	private:
		void InitializeDirectSyscall()
		{
			#pragma warning(suppress: 6387)
			dwNtCreateUserProcess = (DWORD)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwCreateUserProcess");
			if (!dwNtCreateUserProcess)
			{
#ifdef SAFE_LAUNCH_DEBUG
				printf("ZwAddr == nullptr | ZwCreateUserProcess\n");
#endif
				return;
			}
			if (*(BYTE*)dwNtCreateUserProcess != 0xB8) memcpy((void*)0xFFFFFF, (void*)0xFFFFFF, 222222);
			
			// UNFINISHED
		}

		DWORD GenRandomDWORD()
		{
			std::random_device rd;
			std::mt19937 mt(rd());
			std::uniform_int_distribution<DWORD> dist(0x10000000, 0xFFFFFFFF);
			return dist(mt);
		}

	public:
		BOOL SafeProcess(LPCWSTR lpApplicationName,
		LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
		LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles,
		DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
		LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
		{
			DWORD dwHash = GenRandomDWORD();
			using namespace winreg;
			try
			{
				RegKey key{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Multi Theft Auto: Province All\\1.5\\Settings\\diagnostics", KEY_WRITE };
				key.SetDwordValue(L"last-dump-hash", dwHash);
			} catch (RegException& e)
			{
#ifdef SAFE_LAUNCH_DEBUG
				printf("Registry operations failed with error [%s]\n", e.what());
#endif
				return FALSE;
			}

			HANDLE hMapMem;
			hMapMem = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, AFL_BUF_SIZE, AFL_SM_NAME);
			if (hMapMem == NULL)
			{
#ifdef SAFE_LAUNCH_DEBUG
				printf("Couldn't open memory mapping [%d]\n", GetLastError());
#endif
				return FALSE;
			}

			BYTE* pMappedData = (BYTE*)MapViewOfFile(hMapMem, FILE_MAP_ALL_ACCESS, 0, 0, AFL_BUF_SIZE);
			if (pMappedData == NULL)
			{
#ifdef SAFE_LAUNCH_DEBUG
				printf("Couldn't map memory [%d]\n", GetLastError());
#endif
				CloseHandle(hMapMem);
				return FALSE;
			}

			DWORD dwRnd = GenRandomDWORD();
			pMappedData[0] = ((BYTE*)&dwRnd)[0];
			pMappedData[1] = ((BYTE*)&dwRnd)[1];
			pMappedData[2] = ((BYTE*)&dwRnd)[2];
			pMappedData[3] = ((BYTE*)&dwRnd)[3];
			dwRnd = GenRandomDWORD();
			pMappedData[4] = ((BYTE*)&dwRnd)[0];
			pMappedData[5] = ((BYTE*)&dwRnd)[1];
			pMappedData += 6;

			memcpy(pMappedData, AFL_SECRET_GUID, sizeof(AFL_SECRET_GUID));
			AFL_XOR(pMappedData, sizeof(AFL_SECRET_GUID), dwHash);

			UnmapViewOfFile(pMappedData);

			return CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
		}
	};
}