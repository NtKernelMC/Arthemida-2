#pragma once
#include <Windows.h>
#include <stdio.h>
#include <map>
#include <winternl.h>
#include "..\..\Arthemida-2\LauncherInclude\MiniJumper.h"
#define SAFE_LAUNCH_DEBUG
namespace SafeLaunch
{
	using namespace MiniJumper; 
	DWORD ZwAddr = 0x0, fTrampoline = 0x0, syscall_addr = 0x0;
	BYTE prologue[5]; PVOID syscall = nullptr;
	__declspec(naked) void __stdcall ZwCreateUserProcess()
	{
		__asm jmp syscall_addr
	}
	class ProcessGate sealed
	{
	private:
		PVOID ApiAddr = nullptr;
	public:
		explicit ProcessGate(PVOID api_address)
		{
			this->ApiAddr = api_address;
		}
		void ProtectFromHooking()
		{
			auto getOSver = []()
			{
				NTSTATUS(WINAPI * RtlGetVersion)(LPOSVERSIONINFOEXW); OSVERSIONINFOEXW osInfo;
				*(FARPROC*)&RtlGetVersion = GetProcAddress(GetModuleHandleA("ntdll"), "RtlGetVersion");
				if (NULL != RtlGetVersion)
				{
					osInfo.dwOSVersionInfoSize = sizeof(osInfo); RtlGetVersion(&osInfo);
					return std::make_tuple(osInfo.dwMajorVersion, osInfo.dwMinorVersion);
				}
				return std::make_tuple((DWORD)0x0, (DWORD)0x0);
			};
			ZwAddr = (DWORD_PTR)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwCreateUserProcess");
			if (!ZwAddr)
			{
#ifdef SAFE_LAUNCH_DEBUG
				printf("ZwAddr == nullptr | ZwCreateUserProcess\n");
#endif
				return;
			}
#ifdef _WIN64
			if (*(BYTE*)ZwAddr != 0x4C) memcpy((void*)0xFFFFFF, (void*)0xFFFFFF, 222222);
			syscall = VirtualAlloc(0, 11, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			memcpy(syscall, (void*)ZwAddr, 8); *(BYTE*)((DWORD_PTR)syscall + 8) = 0x0F;
			*(BYTE*)((DWORD_PTR)syscall + 9) = 0x05; *(BYTE*)((DWORD_PTR)syscall + 10) = 0xC3;
#else
			if (*(BYTE*)ZwAddr != 0xB8) memcpy((void*)0xFFFFFF, (void*)0xFFFFFF, 222222);
			SYSTEM_INFO systemInfo = { 0 }; GetNativeSystemInfo(&systemInfo); 
			std::tuple<DWORD, DWORD> OsVerInfo = getOSver();
			DWORD codeSize = 15; if (systemInfo.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_INTEL)
			{
				if (std::get<0>(OsVerInfo) == 6 && std::get<1>(OsVerInfo) == 0) codeSize = 21;
				if (std::get<0>(OsVerInfo) == 6 && std::get<1>(OsVerInfo) == 1) codeSize = 24;
			}
			else // added win10 x32 syscall`s
			{
				if ((std::get<0>(OsVerInfo) == 6 && (std::get<1>(OsVerInfo) == 3 || std::get<1>(OsVerInfo) == 2))
				|| (std::get<1>(OsVerInfo) == 10 || std::get<1>(OsVerInfo) == 0)) codeSize = 18;
			}
#ifdef SAFE_LAUNCH_DEBUG
			printf("Major: %d | Minor: %d | CodeSize: %d\n", std::get<0>(OsVerInfo), std::get<1>(OsVerInfo), codeSize);
			//return;
#endif
			syscall = VirtualAlloc(0, codeSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			memcpy(syscall, (void*)ZwAddr, codeSize); 
			syscall_addr = (DWORD)syscall;
#endif      
			fTrampoline = CustomHooks::MakeJump(ZwAddr, (DWORD)&ZwCreateUserProcess, prologue, 5);
			if (fTrampoline != NULL)
			{
#ifdef SAFE_LAUNCH_DEBUG
				printf("[INSTALLER] Hook for syscall redirection was successfully installed!\n");
#endif
			}
			else
			{
#ifdef SAFE_LAUNCH_DEBUG
				printf("[Hooking Error] By some reasons, hook is not exist in to the list!\n");
				printf("[REPORT] System Error Code: %d\n", GetLastError());
#endif
			}
		}
		template<typename UnkStr, typename UnkSTARTUPINFO>
		BOOL SafeProcess(UnkStr lpApplicationName,
		UnkStr lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
		LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles,
		DWORD dwCreationFlags, LPVOID lpEnvironment, UnkStr lpCurrentDirectory,
		UnkSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
		{
			if (ApiAddr == nullptr) return NULL;
			ProtectFromHooking();
			DWORD ulFlags = CREATE_SUSPENDED;
#ifdef _CONSOLE
			ulFlags = CREATE_SUSPENDED | CREATE_NEW_CONSOLE;
#endif
			using CreateSafeProc = BOOL(*)(UnkStr lpApplicationName,
			UnkStr lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
			LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles,
			DWORD dwCreationFlags, LPVOID lpEnvironment, UnkStr lpCurrentDirectory,
			UnkSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
			CreateSafeProc CreateSafeProcess = (CreateSafeProc)ApiAddr;
			BOOL rslt = CreateSafeProcess(lpApplicationName, lpCommandLine,
			lpProcessAttributes, lpThreadAttributes, bInheritHandles,
			ulFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
			if (lpProcessInformation->hProcess == NULL || rslt == NULL) return NULL;
			DISPLAY_DEVICE DevInfo; DevInfo.cb = sizeof(DISPLAY_DEVICE);
			EnumDisplayDevicesA(NULL, 0, &DevInfo, 0);
			std::string VideoCard = DevInfo.DeviceString;
			HANDLE hMutex = CreateMutexA(FALSE, FALSE, VideoCard.c_str());
			if (hMutex)
			{
#ifdef SAFE_LAUNCH_DEBUG
				printf("[MUTEX] Signal was created!\n");
#endif
			}
			ResumeThread(lpProcessInformation->hThread);
			if (fTrampoline != NULL)
			{
#ifdef SAFE_LAUNCH_DEBUG
				printf("[UNHOOKING] Hook was found, trying to remove it...\n");
#endif
				if (CustomHooks::RestorePrologue(ZwAddr, prologue, 5)) 
				{
#ifdef SAFE_LAUNCH_DEBUG
					printf("[REMOVED] Inline hook was erased, original bytes restored!\n");
#endif
				}
#ifdef SAFE_LAUNCH_DEBUG
				else printf("[Unhooking Error] Failed to restore original code.\n[REPORT] System Error Code: %d\n", GetLastError());
			}
			else printf("[Unhooking Error] By some reasons, hook is not exist in to the list!\n[REPORT] System Error Code: %d\n", GetLastError());
#endif
			if (syscall != nullptr)
			{
				BOOL mmr = VirtualFree(syscall, 0, MEM_RELEASE);
				if (mmr)
				{
#ifdef SAFE_LAUNCH_DEBUG
					printf("Custom syscall memory released!\n");
#endif
				}
				else
				{
#ifdef SAFE_LAUNCH_DEBUG
					printf("Custom syscall memory failed to free.\n");
#endif
				}
			}
			if (rslt) return rslt;
			return NULL;
		}
	};
}