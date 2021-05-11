/*
	Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC & holmes0
*/
#include "ArtemisInterface.h"
void __stdcall ModuleScanner(ArtemisConfig* cfg)
{
	if (cfg == nullptr)
	{
#ifdef ARTEMIS_DEBUG
		Utils::LogInFile(ARTEMIS_LOG, "[ERROR] Passed null pointer to ModuleScanner\n");
#endif
		return;
	}
#ifdef ARTEMIS_DEBUG
	Utils::LogInFile(ARTEMIS_LOG, "[INFO] Created async thread for ModuleScanner! Thread id: %d\n", GetCurrentThreadId());
#endif
	if (cfg->ModuleScanner) return;
	cfg->ModuleScanner = true;
	decltype(auto) DiagnosticMSG = [](const std::string& reason_text) -> DWORD
	{
#ifdef ARTEMIS_DEBUG
		Utils::LogInFile(ARTEMIS_LOG, "%s", reason_text.c_str());
#endif
		return 0xDEADC0D3;
	};
	DWORD appHost = (DWORD)GetModuleHandleA(NULL); // Optimizated (Now is non-recursive call!)
	while (true) // Runtime Duplicates-Module Scanner && ProxyDLL Detector
	{
		Utils::BuildModuledMemoryMap(cfg->CurrProc); // Refactored parser -> now faster on 70% than previous!
		for (const auto& it : orderedMapping)
		{
			if (it.first == 0x0 || it.second == 0x0) continue; // validating every page record from memory list
			if ((it.first != appHost && it.first != (DWORD)cfg->hSelfModule) &&
			!Utils::IsVecContain(cfg->ExcludedModules, (PVOID)it.first))
			{
				std::string NameOfDLL = "", szFileName = ""; // Optimizated (Less-recursive calls!)
				if (Utils::IsModuleDuplicated((HMODULE)it.first, szFileName, orderedIdentify, NameOfDLL))
				{
					if (!Utils::OsProtectedFile(Utils::CvAnsiToWide(szFileName).c_str())) // New advanced algorithm!
					{
						MEMORY_BASIC_INFORMATION mme { 0 }; ARTEMIS_DATA data;
						VirtualQuery((LPCVOID)it.first, &mme, sizeof(MEMORY_BASIC_INFORMATION));
						data.baseAddr = (PVOID)it.first; data.MemoryRights = mme.AllocationProtect;
						data.regionSize = it.second; data.dllName = NameOfDLL;
						data.dllPath = szFileName; data.type = DetectionType::ART_PROXY_LIBRARY;
						cfg->callback(&data); cfg->ExcludedModules.push_back((PVOID)it.first);
					}
				}
			}
		}
		Sleep(cfg->MemoryScanDelay);
	}
}