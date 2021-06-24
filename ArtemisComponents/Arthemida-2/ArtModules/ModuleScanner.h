/*
	Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC & holmes0
*/
#include "ArtemisInterface.h"

typedef NTSTATUS(__stdcall* pLdrLoadDll)(
	PWCHAR               PathToFile,
	ULONG                Flags,
	PUNICODE_STRING      ModuleFileName,
	PHANDLE             ModuleHandle);
pLdrLoadDll ptrLdrLoadDll;
pLdrLoadDll ptrOriginalLdrLoadDll;

NTSTATUS __stdcall hkLdrLoadDll(
	PWCHAR               PathToFile,
	ULONG                Flags,
	PUNICODE_STRING      ModuleFileName,
	PHANDLE             ModuleHandle)
{
	static HMODULE appHost = GetModuleHandleA(NULL);
	static ArtemisConfig* cfg = CArtemisReal::GetInstance()->GetConfig();

	auto ModuleThreatReport = [&](PVOID lpBase, DWORD dwSize, const std::string& path,
		const std::string& name, DetectionType detect, const std::string& hack_name = "")
	{
		MEMORY_BASIC_INFORMATION mme{ 0 }; ARTEMIS_DATA data;
		VirtualQuery((LPCVOID)lpBase, &mme, sizeof(MEMORY_BASIC_INFORMATION));
		data.baseAddr = (PVOID)lpBase; data.MemoryRights = mme.AllocationProtect;
		data.regionSize = dwSize; data.dllName = name;
		data.dllPath = path; data.type = detect;
		if (detect == DetectionType::ART_HACK_STRING_FOUND || detect == DetectionType::ART_SIGNATURE_DETECT) data.HackName = hack_name;
		cfg->callback(&data); cfg->ExcludedModules.push_back((PVOID)lpBase);
	};

	NTSTATUS result = ptrOriginalLdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle);
	if (ModuleHandle == 0)
		goto retnOrig;

	MODULEINFO modInfo;
	if (K32GetModuleInformation(GetCurrentProcess(), (HMODULE)*ModuleHandle, &modInfo, sizeof(modInfo)))
	{
		PVOID  lpBase = modInfo.lpBaseOfDll;
		DWORD  dwSize = modInfo.SizeOfImage;
		
		if (lpBase == 0x0 || dwSize == 0x0) goto retnOrig; // validating every page record from memory list
		if ((lpBase != appHost && lpBase != cfg->hSelfModule) &&
			!Utils::IsVecContain(cfg->ExcludedModules, lpBase))
		{
			std::string NameOfDLL = "", szFileName = ""; // Optimizated (Less-recursive calls!)
			std::wstring wideFileName = L""; // wide-version (anti-destruction)
			// IsModuleDuplicated - вернет имя длл и путь в любом случае для пользования в коде ниже этого блока в том числе
			if (Utils::IsModuleDuplicated((HMODULE)lpBase, szFileName, orderedIdentify, NameOfDLL))
			{
				wideFileName = Utils::CvAnsiToWide(szFileName); // данный блок только для детектов прокси дллок либо дубликатных DLL! 
				if (!Utils::OsProtectedFile(wideFileName.c_str())) // New advanced algorithm!
				{
					ModuleThreatReport(lpBase, dwSize, szFileName, NameOfDLL, DetectionType::ART_PROXY_LIBRARY);
					goto retnOrig; // если данный модуль уже словил детект - нет смысла идти дальше по нему
				}
			}
			else
			{
				// чтобы если выше выполнилась проверка то не дублировать вызов еще раз а если нет - конвертим строку
				if (wideFileName.empty()) wideFileName = Utils::CvAnsiToWide(szFileName);
				if (Utils::OsProtectedFile(wideFileName.c_str())) goto retnOrig;
				if (Utils::findStringIC(NameOfDLL, "MSVCP") || Utils::findStringIC(NameOfDLL, "api-ms-win") ||
					Utils::findStringIC(NameOfDLL, "VCRUNTIME")) goto retnOrig;
				if (cfg->DetectPacking && IsModulePacked((HMODULE)lpBase, cfg->AllowedPackedModules))
				{
					ModuleThreatReport(lpBase, dwSize, szFileName, NameOfDLL, DetectionType::ART_PROTECTOR_PACKER);
					goto retnOrig; // если данный модуль уже словил детект - нет смысла идти дальше по нему
				}
				if (cfg->DetectByString)
				{
					for (const auto& zm : cfg->IlegaleLinien) // Список строк для поиска читов (вектор стринг)
					{
						size_t end_len = NULL;
						char* ptr = SearchStringInMemory(zm, zm.length(), (PVOID)lpBase, (PVOID)dwSize, end_len);
						if (ptr != nullptr)
						{
							std::string match = std::string(ptr, zm.length() + end_len);
							ModuleThreatReport(lpBase, dwSize, szFileName, NameOfDLL, DetectionType::ART_HACK_STRING_FOUND, match);
							goto retnOrig; // если данный модуль уже словил детект - нет смысла идти дальше по нему
						}
					}
				}
				if (cfg->DetectBySignature)
				{
					for (const auto& sg : cfg->IllegalPatterns) // Список сигнатур для поиска известных читов или их участков памяти
					{
						DWORD sgAddr = SigScan::FindPattern((HMODULE)lpBase,
							std::get<0>(sg.second).c_str()/*"\x8D\x45\xF4\x64\xA3\x00\x00\x00\x00\x68"*/, std::get<1>(sg.second).c_str());
						//printf("[SIG WALKER] Name: %s | Pattern: %s | Mask: %s | Len: %d\n", NameOfDLL.c_str(),
						//std::get<0>(sg.second).c_str(), std::get<1>(sg.second).c_str(), std::get<0>(sg.second).length());
						if (sgAddr != NULL)
						{
							ModuleThreatReport(lpBase, dwSize, szFileName, NameOfDLL, DetectionType::ART_SIGNATURE_DETECT, sg.first);
						}
					}
				}
			}
		}
	}

retnOrig:
	return result;
}

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

	{
		ptrLdrLoadDll = (pLdrLoadDll)Utils::RuntimeIatResolver("ntdll.dll", "LdrLoadDll");

		BYTE* Trampoline = (BYTE*)VirtualAlloc(NULL, 10, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);            // don't change to new/malloc!
		memcpy(Trampoline, ptrLdrLoadDll, 5);
		Trampoline[5] = 0xE9;
		DWORD dwRelJmpBack = ((DWORD)ptrLdrLoadDll + 5) - (DWORD)&Trampoline[5] - 5;
		memcpy(Trampoline + 6, &dwRelJmpBack, 4);
		DWORD dwOldProt;
		VirtualProtect(Trampoline, 10, PAGE_EXECUTE_READ, &dwOldProt);
		ptrOriginalLdrLoadDll = (pLdrLoadDll)Trampoline;

		DWORD dwRelAddr = (((DWORD)&hkLdrLoadDll) - (DWORD)ptrLdrLoadDll) - 5;
		BYTE  patch[5] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
		memcpy(&patch[1], &dwRelAddr, 4);
		VirtualProtect(ptrLdrLoadDll, 5, PAGE_EXECUTE_READWRITE, &dwOldProt);
		memcpy(ptrLdrLoadDll, patch, 5);
		VirtualProtect(ptrLdrLoadDll, 5, PAGE_EXECUTE_READ, &dwOldProt);
	}

	auto ModuleThreatReport = [&](const auto& it, const std::string& path, 
	const std::string& name, DetectionType detect, const std::string& hack_name = "")
	{
		MEMORY_BASIC_INFORMATION mme { 0 }; ARTEMIS_DATA data;
		VirtualQuery((LPCVOID)it.first, &mme, sizeof(MEMORY_BASIC_INFORMATION));
		data.baseAddr = (PVOID)it.first; data.MemoryRights = mme.AllocationProtect;
		data.regionSize = it.second; data.dllName = name;
		data.dllPath = path; data.type = detect; 
		if (detect == DetectionType::ART_HACK_STRING_FOUND || detect == DetectionType::ART_SIGNATURE_DETECT) data.HackName = hack_name;
		cfg->callback(&data); cfg->ExcludedModules.push_back((PVOID)it.first);
	};
	DWORD appHost = (DWORD)GetModuleHandleA(NULL); // Optimizated (Now is non-recursive call!)
	Utils::BuildModuledMemoryMap(cfg->CurrProc); // Refactored parser -> now faster on 70% than previous!
	for (const auto& it : orderedMapping)
	{
		if (it.first == 0x0 || it.second == 0x0) continue; // validating every page record from memory list
		if ((it.first != appHost && it.first != (DWORD)cfg->hSelfModule) &&
		!Utils::IsVecContain(cfg->ExcludedModules, (PVOID)it.first))
		{
			std::string NameOfDLL = "", szFileName = ""; // Optimizated (Less-recursive calls!)
			std::wstring wideFileName = L""; // wide-version (anti-destruction)
			// IsModuleDuplicated - вернет имя длл и путь в любом случае для пользования в коде ниже этого блока в том числе
			if (Utils::IsModuleDuplicated((HMODULE)it.first, szFileName, orderedIdentify, NameOfDLL)) 
			{
				wideFileName = Utils::CvAnsiToWide(szFileName); // данный блок только для детектов прокси дллок либо дубликатных DLL! 
				if (!Utils::OsProtectedFile(wideFileName.c_str())) // New advanced algorithm!
				{
					ModuleThreatReport(it, szFileName, NameOfDLL, DetectionType::ART_PROXY_LIBRARY);
					continue; // если данный модуль уже словил детект - нет смысла идти дальше по нему
				}
			}
			else
			{
				// чтобы если выше выполнилась проверка то не дублировать вызов еще раз а если нет - конвертим строку
				if (wideFileName.empty()) wideFileName = Utils::CvAnsiToWide(szFileName); 
				if (Utils::OsProtectedFile(wideFileName.c_str())) continue;
				if (Utils::findStringIC(NameOfDLL, "MSVCP") || Utils::findStringIC(NameOfDLL, "api-ms-win") ||
				Utils::findStringIC(NameOfDLL, "VCRUNTIME")) continue;
				if (cfg->DetectPacking && IsModulePacked((HMODULE)it.first, cfg->AllowedPackedModules))
				{
					ModuleThreatReport(it, szFileName, NameOfDLL, DetectionType::ART_PROTECTOR_PACKER);
					continue; // если данный модуль уже словил детект - нет смысла идти дальше по нему
				}
				if (cfg->DetectByString)
				{
					for (const auto& zm : cfg->IlegaleLinien) // Список строк для поиска читов (вектор стринг)
					{
						size_t end_len = NULL;
						char* ptr = SearchStringInMemory(zm, zm.length(), (PVOID)it.first, (PVOID)it.second, end_len);
						if (ptr != nullptr)
						{
							std::string match = std::string(ptr, zm.length() + end_len);
							ModuleThreatReport(it, szFileName, NameOfDLL, DetectionType::ART_HACK_STRING_FOUND, match);
							goto continueMain; // если данный модуль уже словил детект - нет смысла идти дальше по нему
						}
					}
				}
				if (cfg->DetectBySignature)
				{
					for (const auto& sg : cfg->IllegalPatterns) // Список сигнатур для поиска известных читов или их участков памяти
					{
						DWORD sgAddr = SigScan::FindPattern((HMODULE)it.first,
						std::get<0>(sg.second).c_str()/*"\x8D\x45\xF4\x64\xA3\x00\x00\x00\x00\x68"*/, std::get<1>(sg.second).c_str());
						//printf("[SIG WALKER] Name: %s | Pattern: %s | Mask: %s | Len: %d\n", NameOfDLL.c_str(),
						//std::get<0>(sg.second).c_str(), std::get<1>(sg.second).c_str(), std::get<0>(sg.second).length());
						if (sgAddr != NULL)
						{
							ModuleThreatReport(it, szFileName, NameOfDLL, DetectionType::ART_SIGNATURE_DETECT, sg.first);
						}
					}
				}
			}
		}
continueMain:;
	}
}
