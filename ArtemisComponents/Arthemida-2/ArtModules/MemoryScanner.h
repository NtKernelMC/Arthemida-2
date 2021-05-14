/*
	Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC & holmes0
*/
#include "ArtemisInterface.h"
void __stdcall MemoryScanner(ArtemisConfig* cfg)
{
	if (cfg == nullptr)
	{
#ifdef ARTEMIS_DEBUG
		Utils::LogInFile(ARTEMIS_LOG, "[ERROR] Passed null pointer to MemoryScanner\n");
#endif
		return;
	}
#ifdef ARTEMIS_DEBUG
	Utils::LogInFile(ARTEMIS_LOG, "[INFO] Created async thread for MemoryScanner! Thread id: %d\n", GetCurrentThreadId());
#endif
	while (true)
	{
		auto WatchMemoryAllocations = [&, cfg]
		(const void* ptr, size_t length, MEMORY_BASIC_INFORMATION* info, int size)
		{
			if (ptr == nullptr || info == nullptr) return;
			const void* end = (const void*)((const char*)ptr + length);
			//DWORD mask = (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_WRITECOPY);
			DWORD mask = (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ);
			while (ptr < end && VirtualQuery(ptr, &info[0], sizeof(*info)) == sizeof(*info))
			{
				MEMORY_BASIC_INFORMATION* i = &info[0]; 
				if ((i->State != MEM_FREE && i->State != MEM_RELEASE) && i->Protect & mask)
				{
					BYTE complete_sequence = 0; DWORD_PTR foundIAT = 0x0;
					for (DWORD_PTR z = (DWORD_PTR)ptr; z < ((DWORD_PTR)ptr + i->RegionSize); z++)
					{
						for (DWORD x = 0; x < (8 * 6); x += 0x6)
						{
							if ((x + z) < ((DWORD_PTR)ptr + i->RegionSize) && 
							(x + z + 0x1) < ((DWORD_PTR)ptr + i->RegionSize))
							{
								if ((*(BYTE*)(z + x) == 0xFF && *(BYTE*)(x + z + 0x1) == 0x25))
								{
									foundIAT = (x + z);
									complete_sequence++;
								}
								else complete_sequence = 0;
							}
							else complete_sequence = 0;
						}
						if (complete_sequence >= 8)
						{
							complete_sequence = 0x0; char MappedName[256]; memset(MappedName, 0, sizeof(MappedName));
							lpGetMappedFileNameA(cfg->CurrProc, (PVOID)z, MappedName, sizeof(MappedName));
							std::string possible_name = Utils::GetDllName(MappedName); bool cloacked = false;
							if (!Utils::IsMemoryInModuledRange(z, possible_name, &cloacked))
							{
								if (!Utils::IsVecContain(cfg->ExcludedImages, i->BaseAddress))
								{
									// SHARED MEMORY can bring to us a couple of false-positives from Wow64 addreses!
									if (std::string(MappedName).find("Windows\\SysWOW64") == std::string::npos)
									{
										ARTEMIS_DATA data; data.baseAddr = i->BaseAddress;
										data.MemoryRights = i->Protect; data.regionSize = i->RegionSize;
										data.dllName = cloacked ? possible_name : " ";
										data.dllPath = cloacked ? MappedName : " ";
										data.type = DetectionType::ART_MANUAL_MAP;
										cfg->callback(&data); cfg->ExcludedImages.push_back(i->BaseAddress);
									}
								}
							}
						}
					}
				}
				ptr = (const void*)((const char*)(i->BaseAddress) + i->RegionSize);
			}
		};
		MEMORY_BASIC_INFORMATION mbi { 0 }; SYSTEM_INFO sysInfo { 0 }; GetNativeSystemInfo(&sysInfo); 
		SIZE_T MaxAddr = (DWORD)sysInfo.lpMaximumApplicationAddress - (DWORD)sysInfo.lpMinimumApplicationAddress;
		WatchMemoryAllocations(sysInfo.lpMinimumApplicationAddress, MaxAddr,
		&mbi, sizeof(MEMORY_BASIC_INFORMATION)); Sleep(cfg->MemoryScanDelay);
	}
}