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
#include "MemoryGuard.h"
using namespace ArtemisData;

struct sMemoryGuardPageDescriptor
{
    XXH32_hash_t XXH32_hash = 0;
    bool         bIsBeingLegallyHooked = false;
};
std::map<DWORD, sMemoryGuardPageDescriptor> mpExecutablePageList;
CRITICAL_SECTION*                           CArtemisReal::m_pCsExecutablePageList = nullptr;

typedef NTSTATUS(__stdcall* pLdrUnloadDll)(HANDLE ModuleHandle);
pLdrUnloadDll ptrLdrUnloadDll;
pLdrUnloadDll ptrOriginalLdrUnloadDll;

void __inline CheckInitCS()
{
    if (CArtemisReal::m_pCsExecutablePageList == nullptr)
    {
        CArtemisReal::m_pCsExecutablePageList = new CRITICAL_SECTION;
        InitializeCriticalSection(CArtemisReal::m_pCsExecutablePageList);
    }
}

NTSTATUS __stdcall hkLdrUnloadDll(HANDLE ModuleHandle)
{
    if (ModuleHandle == 0)
        goto retnOrig;

    CheckInitCS();
    EnterCriticalSection(CArtemisReal::m_pCsExecutablePageList);

    MODULEINFO modInfo;
    if (K32GetModuleInformation(GetCurrentProcess(), (HMODULE)ModuleHandle, &modInfo, sizeof(modInfo)))
    {
        LPVOID ptr = modInfo.lpBaseOfDll;
        LPVOID end = (BYTE*)modInfo.lpBaseOfDll + modInfo.SizeOfImage;
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        while (ptr < end && VirtualQuery(ptr, &mbi, sizeof(mbi)))
        {
            if (mpExecutablePageList.find((DWORD)mbi.BaseAddress) != mpExecutablePageList.end())
                mpExecutablePageList.erase((DWORD)mbi.BaseAddress);
            ptr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        }
    }

    LeaveCriticalSection(CArtemisReal::m_pCsExecutablePageList);

retnOrig:
    return ptrOriginalLdrUnloadDll(ModuleHandle);
}

bool CArtemisReal::MemoryGuardBeginHook(void* pTarget)
{
    MEMORY_BASIC_INFORMATION mbi;
    if(VirtualQuery(pTarget, &mbi, sizeof(mbi)) != sizeof(mbi))
        return false;
    CheckInitCS();
    EnterCriticalSection(m_pCsExecutablePageList);
    if (mpExecutablePageList.find((DWORD)mbi.BaseAddress) != mpExecutablePageList.end())
        mpExecutablePageList[(DWORD)mbi.BaseAddress].bIsBeingLegallyHooked = true;
    LeaveCriticalSection(m_pCsExecutablePageList);
    return true;
}

bool CArtemisReal::MemoryGuardEndHook(void* pTarget)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(pTarget, &mbi, sizeof(mbi)) != sizeof(mbi))
        return false;
    CheckInitCS();
    EnterCriticalSection(m_pCsExecutablePageList);
    if (mpExecutablePageList.find((DWORD)mbi.BaseAddress) != mpExecutablePageList.end())
    {
        mpExecutablePageList[(DWORD)mbi.BaseAddress].XXH32_hash = XXH32(mbi.BaseAddress, mbi.RegionSize, 0);
        mpExecutablePageList[(DWORD)mbi.BaseAddress].bIsBeingLegallyHooked = false;
    }
    LeaveCriticalSection(m_pCsExecutablePageList);
    return true;
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

    CheckInitCS();
	SetProcessDEPPolicy(PROCESS_DEP_ENABLE);

    {
        ptrLdrUnloadDll = (pLdrUnloadDll)Utils::RuntimeIatResolver("ntdll.dll", "LdrUnloadDll");

        BYTE* Trampoline = (BYTE*)VirtualAlloc(NULL, 10, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);            // don't change to new/malloc!
        memcpy(Trampoline, ptrLdrUnloadDll, 5);
        Trampoline[5] = 0xE9;
        DWORD dwRelJmpBack = ((DWORD)ptrLdrUnloadDll + 5) - (DWORD)&Trampoline[5] - 5;
        memcpy(Trampoline + 6, &dwRelJmpBack, 4);
        DWORD dwOldProt;
        VirtualProtect(Trampoline, 10, PAGE_EXECUTE_READ, &dwOldProt);
        ptrOriginalLdrUnloadDll = (pLdrUnloadDll)Trampoline;

        DWORD dwRelAddr = (((DWORD)&hkLdrUnloadDll) - (DWORD)ptrLdrUnloadDll) - 5;
        BYTE  patch[5] = {0xE9, 0x00, 0x00, 0x00, 0x00};
        memcpy(&patch[1], &dwRelAddr, 4);
        VirtualProtect(ptrLdrUnloadDll, 5, PAGE_EXECUTE_READWRITE, &dwOldProt);
        memcpy(ptrLdrUnloadDll, patch, 5);
        VirtualProtect(ptrLdrUnloadDll, 5, PAGE_EXECUTE_READ, &dwOldProt);
    }

    auto CallDetect = [&cfg](void* ptrBase, DWORD dwLength, DetectionType detectionType = DetectionType::ART_MEMORY_INTEGRITY_VIOLATION) {
        ARTEMIS_DATA data;
        data.baseAddr = ptrBase;
        data.regionSize = dwLength;
        data.type = detectionType;

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
			while (ptr < end)
			{
                EnterCriticalSection(CArtemisReal::m_pCsExecutablePageList);
                if (VirtualQuery(ptr, &info[0], sizeof(*info)) != sizeof(*info))
                    break;
				MEMORY_BASIC_INFORMATION* i = &info[0];
                DWORD dwBase = (DWORD)i->BaseAddress;
                //printf("[Memory Guard] Working with REGION: %08X [%X]\n", dwBase, i->RegionSize);
                if (i->State == MEM_FREE)
                {
                    if (mpExecutablePageList.find(dwBase) != mpExecutablePageList.end())
                        mpExecutablePageList.erase(dwBase);
                }

                if (i->State != MEM_FREE && i->Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
                {
                    HMODULE hModule = NULL;
                    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (wchar_t*)dwBase, &hModule) &&
                        hModule != NULL)
                    {
                        if (mpExecutablePageList.find(dwBase) == mpExecutablePageList.end())
                            mpExecutablePageList[dwBase].XXH32_hash = XXH32(i->BaseAddress, i->RegionSize, 0);

                        else if (!mpExecutablePageList[dwBase].bIsBeingLegallyHooked)
                        {
                            if (mpExecutablePageList[dwBase].XXH32_hash != XXH32(i->BaseAddress, i->RegionSize, 0))
                                CallDetect((void*)ptr, i->RegionSize);
                        }
                    }
                }

                LeaveCriticalSection(CArtemisReal::m_pCsExecutablePageList);

				ptr = (const void*)((const char*)(i->BaseAddress) + i->RegionSize);
			}
		};

		MEMORY_BASIC_INFORMATION mbi{ 0 };
		WatchMemoryAllocations(sysInfo.lpMinimumApplicationAddress, MaxAddr,
			&mbi, sizeof(MEMORY_BASIC_INFORMATION));

		Sleep(cfg->MemoryGuardScanDelay);
	}
}
