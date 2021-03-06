/*
	Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC & holmes0
*/
#include "ArtemisInterface.h"
#include "../ArtUtils/seh.h"
void trans_func(unsigned int u, EXCEPTION_POINTERS*)
{
	throw SE_Exception(u);
}
void __stdcall MemoryScanner(ArtemisConfig* cfg)
{
	Scoped_SE_Translator scoped_se_translator{ trans_func };

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
					try
					{
						BYTE complete_sequence = 0; DWORD foundIAT = 0x0;
						for (DWORD z = (DWORD)ptr; z < ((DWORD)ptr + i->RegionSize); z++)
						{
							for (DWORD x = 0; x < (8 * 6); x += 0x6)
							{
								if ((x + z) < ((DWORD)ptr + i->RegionSize) &&
									(x + z + 0x1) < ((DWORD)ptr + i->RegionSize))
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
								lpGetMappedFileNameA(cfg->CurrProc, i->BaseAddress, MappedName, sizeof(MappedName));
								std::string possible_name = Utils::GetDllName(MappedName); bool cloacked = false;
								if (!Utils::IsMemoryInModuledRange((DWORD)i->BaseAddress, possible_name, &cloacked))
								{
									if (!Utils::IsVecContain(cfg->ExcludedImages, i->BaseAddress))
									{
										if ((i->Protect == 0x20 && cloacked) && !possible_name.empty()) continue;
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
					catch (const SE_Exception& e)
					{
#ifdef ARTEMIS_DEBUG
					    printf("[SEH/MemoryScanner] %8.8x\n", e.getSeNumber());
#endif
					} catch (...) {
#ifdef ARTEMIS_DEBUG
						printf("[SEH/MemoryScanner] Unknown\n");
#endif
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
