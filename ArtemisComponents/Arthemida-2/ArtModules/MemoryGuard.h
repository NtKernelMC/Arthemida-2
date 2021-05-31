/*
	Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC & holmes0
*/
/**
* Assignee: holmes0
* Done: 
*		Hook NtProtectVirtualMemory and block changes to executable memory
*		Keep constantly updated list of memory page rights in order to detect any external modifications
*			This still allows fast external protection changing and writing, impossible to perfectly protect from usermode.
* 
*		(FIXED) Bug: Page containing NtProtectVirtualMemory remains with PAGE_READWRITE_EXECUTE rights for hook library to remove and place hook back (consider switching to another library).
*
* TBD:
*		WIP Enhancement: Multithreaded (faster) scanning to detect and prevent patching.
*/
#include "ArtemisInterface.h"

std::map<DWORD, DWORD> mpProtectionList;

typedef NTSTATUS(__stdcall* pNtProtectVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
pNtProtectVirtualMemory ptrNtProtectVirtualMemory;
pNtProtectVirtualMemory ptrOriginalNtProtectVirtualMemory;

NTSTATUS __stdcall hkNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection)
{
#define CALL_ORIG(a, b, c, d, e) ptrOriginalNtProtectVirtualMemory(a, b, c, d, e);

	ULONG ulOldProt;
	NTSTATUS result = CALL_ORIG(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, &ulOldProt);
	
	if (ulOldProt & PAGE_EXECUTE_READWRITE)
	{
		CALL_ORIG(ProcessHandle, BaseAddress, NumberOfBytesToProtect, PAGE_EXECUTE_READ, &ulOldProt);
		*OldAccessProtection = PAGE_EXECUTE_READ;
		return result;
	}
	
	if (ulOldProt & (PAGE_EXECUTE | PAGE_EXECUTE_READ))
	{
		CALL_ORIG(ProcessHandle, BaseAddress, NumberOfBytesToProtect, ulOldProt, &ulOldProt);
		*OldAccessProtection = ulOldProt;
		return 0xC0000022; // STATUS_ACCESS_DENIED
	}

	if (NewAccessProtection & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
	{
		CALL_ORIG(ProcessHandle, BaseAddress, NumberOfBytesToProtect, ulOldProt, &ulOldProt);
		*OldAccessProtection = ulOldProt;
		return 0xC0000022; // STATUS_ACCESS_DENIED
	}

	return result;
}

void __stdcall MemoryGuardScanner(ArtemisConfig* cfg)
{
	if (cfg == nullptr)
	{
#ifdef ARTEMIS_DEBUG
		Utils::LogInFile(ARTEMIS_LOG, "[ERROR] Passed null pointer to MemoryGuardScanner\n");
#endif
		return;
	}
#ifdef ARTEMIS_DEBUG
	Utils::LogInFile(ARTEMIS_LOG, "[INFO] Created async thread for MemoryGuardScanner! Thread id: %d\n", GetCurrentThreadId());
#endif

	SetProcessDEPPolicy(PROCESS_DEP_ENABLE);

	ptrNtProtectVirtualMemory = (pNtProtectVirtualMemory)Utils::RuntimeIatResolver("ntdll.dll", "NtProtectVirtualMemory");
	
	BYTE* Trampoline = (BYTE*)VirtualAlloc(NULL, 10, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // don't change to new/malloc!
	memcpy(Trampoline, ptrNtProtectVirtualMemory, 5);
	Trampoline[5] = 0xE9;
	DWORD dwRelJmpBack = ((DWORD)ptrNtProtectVirtualMemory + 5) - (DWORD)&Trampoline[5] - 5;
	memcpy(Trampoline + 6, &dwRelJmpBack, 4);
	DWORD dwOldProt;
	VirtualProtect(Trampoline, 10, PAGE_EXECUTE_READ, &dwOldProt);
	ptrOriginalNtProtectVirtualMemory = (pNtProtectVirtualMemory)Trampoline;

	DWORD dwRelAddr = (((DWORD)&hkNtProtectVirtualMemory) - (DWORD)ptrNtProtectVirtualMemory) - 5;
	BYTE patch[5] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
	memcpy(&patch[1], &dwRelAddr, 4);
	VirtualProtect(ptrNtProtectVirtualMemory, 5, PAGE_EXECUTE_READWRITE, &dwOldProt);
	memcpy(ptrNtProtectVirtualMemory, patch, 5);
	ULONG ulBytesToProtect = 5;
	ptrOriginalNtProtectVirtualMemory(GetCurrentProcess(), (void**)&ptrOriginalNtProtectVirtualMemory, &ulBytesToProtect, PAGE_EXECUTE_READ, &dwOldProt);

	auto CallDetect = [&cfg](void* ptrBase, DWORD dwLength, bool bPossibleFalsePositive = false)
	{
		ARTEMIS_DATA data;
		data.baseAddr = ptrBase;
		data.regionSize = dwLength;
		if (bPossibleFalsePositive) data.type = DetectionType::ART_MEMORY_PROTECT_MAYBE_VIOLATION;
		else data.type = DetectionType::ART_MEMORY_PROTECT_VIOLATION;

		cfg->callback(&data);
	};

	SYSTEM_INFO sysInfo{ 0 }; 
	GetNativeSystemInfo(&sysInfo);
	SIZE_T MaxAddr = (DWORD)sysInfo.lpMaximumApplicationAddress - (DWORD)sysInfo.lpMinimumApplicationAddress;
	while (true)
	{
		if (!cfg->MemoryGuard) return;

		auto WatchMemoryAllocations = [&, cfg]
		(const void* ptr, size_t length, MEMORY_BASIC_INFORMATION* info, int size)
		{
			if (ptr == nullptr || info == nullptr) return;
			const void* end = (const void*)((const char*)ptr + length);
			while (ptr < end && VirtualQuery(ptr, &info[0], sizeof(*info)) == sizeof(*info))
			{
				//printf("[Memory Guard] Working with ptr %X %X\n", (DWORD)ptr, ((MEMORY_BASIC_INFORMATION*)&info[0])->BaseAddress);
				MEMORY_BASIC_INFORMATION* i = &info[0];
				if ((i->State != MEM_FREE && i->State != MEM_RELEASE))
				{
					DWORD dwBase = (DWORD)ptr;
					if (i->Protect & (PAGE_EXECUTE_READWRITE) && !(dwBase < (DWORD)ptrNtProtectVirtualMemory && ((DWORD)ptrNtProtectVirtualMemory - dwBase) < i->RegionSize))
					{
						DWORD dwOldProt;
						VirtualProtect(i->BaseAddress, i->RegionSize, PAGE_EXECUTE_READ, &dwOldProt);
						CallDetect((void*)ptr, i->RegionSize, true);
					}

					if (mpProtectionList.find(dwBase) == mpProtectionList.end())
					{
						mpProtectionList[dwBase] = i->Protect;
					}
					else if(i->Protect != mpProtectionList[dwBase])
					{
						if (i->Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ) && !(mpProtectionList[dwBase] & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
							CallDetect((void*)ptr, i->RegionSize);

						mpProtectionList[dwBase] = i->Protect;
					}
				}
				ptr = (const void*)((const char*)(i->BaseAddress) + i->RegionSize);
			}
		};
		MEMORY_BASIC_INFORMATION mbi{ 0 };
		WatchMemoryAllocations(sysInfo.lpMinimumApplicationAddress, MaxAddr,
			&mbi, sizeof(MEMORY_BASIC_INFORMATION));

		Sleep(cfg->MemoryGuardScanDelay);
	}
}