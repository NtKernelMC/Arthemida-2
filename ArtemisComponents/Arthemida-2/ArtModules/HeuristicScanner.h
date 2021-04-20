/*
	Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC & holmes0
*/
#include "ArtemisInterface.h"
void __stdcall SigScanner(ArtemisConfig* cfg) // CAUTION! Not tested yet.
{
	if (cfg == nullptr)
	{
#ifdef ARTEMIS_DEBUG
		Utils::LogInFile(ARTEMIS_LOG, "[ERROR] Passed null pointer to SigScanner\n");
#endif
		return;
	}
#ifdef ARTEMIS_DEBUG
	Utils::LogInFile(ARTEMIS_LOG, "[INFO] Created async thread for SigScanner!\n");
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
			for (const auto& it : orderedMapping)
			{
				if (it.first == GetModuleHandleA("kernel32.dll")) continue;
				DWORD scanAddr = SigScan::FindPatternExplicit((DWORD)it.first, it.second,
				std::get<0>(KeyValuePair.second), std::get<1>(KeyValuePair.second));
				if (scanAddr != NULL && !Utils::IsVecContain(cfg->ExcludedSigAddresses, it.first))
				{
					CHAR szFilePath[MAX_PATH + 1]; GetModuleFileNameA((HMODULE)it.first, szFilePath, MAX_PATH + 1);
					std::string NameOfDLL = Utils::GetDllName(szFilePath);
					MEMORY_BASIC_INFORMATION mme{ 0 }; ARTEMIS_DATA data; data.EmptyVersionInfo = true;
					VirtualQuery(it.first, &mme, sizeof(MEMORY_BASIC_INFORMATION));
					data.baseAddr = it.first; data.MemoryRights = mme.AllocationProtect;
					data.regionSize = mme.RegionSize; data.dllName = NameOfDLL; data.dllPath = szFilePath;
					data.HackName = KeyValuePair.first; data.type = DetectionType::ART_SIGNATURE_DETECT;
					cfg->callback(&data); cfg->ExcludedSigAddresses.push_back(it.first);
				}
			}
		}
		Sleep(cfg->PatternScanDelay);
	}
}