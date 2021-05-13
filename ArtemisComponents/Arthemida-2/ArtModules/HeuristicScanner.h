/*
	Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC & holmes0
*/
#include "ArtemisInterface.h"
char* SearchStringInMemory(const std::string& data, size_t len, PVOID from, PVOID to, size_t &out_len)
{
	MEMORY_BASIC_INFORMATION info { 0 }; std::vector<char> chunk;
	char* p = (char*)from; while (p < (PVOID)((DWORD)from + (DWORD)to))
	{
		if (VirtualQuery(p, &info, sizeof(info)) == sizeof(info))
		{
			p = (char*)info.BaseAddress; chunk.resize(info.RegionSize);
			if (memcpy(&chunk[0], p, info.RegionSize) != nullptr)
			{
				for (size_t i = 0; i < (info.RegionSize - len); ++i)
				{
					if (Utils::findStringIC(data.c_str(), std::string(&chunk[i], len)))
					{
						char* fnd_ptr = (char*)p + i;
						while (*fnd_ptr != '\0') fnd_ptr++;
						out_len = fnd_ptr - ((char*)p + i);
						return (char*)p + i;
					}
				}
			}
			p += info.RegionSize;
		}
	}
	return nullptr;
}
bool __stdcall IsModulePacked(HMODULE hModule, const std::vector<std::string>& ExcludedModules)
{
	if (hModule == nullptr) return false;
	else
	{
		auto fnd = std::find(ExcludedModules.begin(), ExcludedModules.end(), Utils::GetLibNameFromHandle(hModule));
		if (fnd != ExcludedModules.end()) return false;
		bool ContainTextSection = false; PIMAGE_NT_HEADERS NtHeader = ImageNtHeader(hModule);
		WORD NumSections = NtHeader->FileHeader.NumberOfSections;
		PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeader);
		for (WORD i = 0; i < NumSections; i++)
		{
			if (Utils::findStringIC((const char*)Section->Name, ".vmp") || 
			Utils::findStringIC((const char*)Section->Name, ".upx")) return true;
			if (Utils::findStringIC((const char*)Section->Name, ".text"))
			{
				ContainTextSection = true;
				if (NtHeader->OptionalHeader.AddressOfEntryPoint < Section->VirtualAddress || 
				NtHeader->OptionalHeader.AddressOfEntryPoint >
				(Section->VirtualAddress + Section->Misc.VirtualSize)) return true;
			}
			Section++;
		}
		if (!ContainTextSection) return true;
	}
	return false;
}
void __stdcall SigScanner(ArtemisConfig* cfg) 
{
	if (cfg == nullptr)
	{
#ifdef ARTEMIS_DEBUG
		Utils::LogInFile(ARTEMIS_LOG, "[ERROR] Passed null pointer to SigScanner\n");
#endif
		return;
	}
#ifdef ARTEMIS_DEBUG
	Utils::LogInFile(ARTEMIS_LOG, "[INFO] Created async thread for SigScanner! Thread id: %d\n", GetCurrentThreadId());
#endif
	if (cfg->IllegalPatterns.empty())
	{
#ifdef ARTEMIS_DEBUG
		Utils::LogInFile(ARTEMIS_LOG, "[ERROR] Empty hack patterns list for SigScanner!\n");
#endif
		return;
	}
	if (cfg->SignatureScanner) return;
	cfg->SignatureScanner = true;
	while (true) 
	{
		for (const auto& KeyValuePair : cfg->IllegalPatterns)
		{
			/*for (const auto& it : orderedMapping)
			{
				if (it.first == (DWORD)GetModuleHandleA("kernel32.dll")) continue;
				DWORD scanAddr = SigScan::FindPatternExplicit((DWORD)it.first, it.second,
				std::get<0>(KeyValuePair.second), std::get<1>(KeyValuePair.second));
				if (scanAddr != NULL && !Utils::IsVecContain(cfg->ExcludedSigAddresses, (PVOID)it.first))
				{
					CHAR szFilePath[MAX_PATH + 1]; GetModuleFileNameA((HMODULE)it.first, szFilePath, MAX_PATH + 1);
					std::string NameOfDLL = Utils::GetDllName(szFilePath);
					MEMORY_BASIC_INFORMATION mme{ 0 }; ARTEMIS_DATA data; 
					VirtualQuery((PVOID)it.first, &mme, sizeof(MEMORY_BASIC_INFORMATION));
					data.baseAddr = (PVOID)it.first; data.MemoryRights = mme.AllocationProtect;
					data.regionSize = mme.RegionSize; data.dllName = NameOfDLL; data.dllPath = szFilePath;
					data.HackName = KeyValuePair.first; data.type = DetectionType::ART_SIGNATURE_DETECT;
					cfg->callback(&data); cfg->ExcludedSigAddresses.push_back((PVOID)it.first);
				}
			}*/
		}
		Sleep(cfg->PatternScanDelay);
	}
}