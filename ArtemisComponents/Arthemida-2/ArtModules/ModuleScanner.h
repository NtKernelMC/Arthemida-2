/*
	Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC & holmes0
*/
#include "ArtemisInterface.h"
#include "../ArtUtils/Utils.h"

typedef NTSTATUS(__stdcall* pLdrLoadDll)(
	PWCHAR               PathToFile,
	ULONG                Flags,
	PUNICODE_STRING      ModuleFileName,
	PHANDLE             ModuleHandle);
pLdrLoadDll ptrLdrLoadDll;
pLdrLoadDll ptrOriginalLdrLoadDll;

NTSTATUS __stdcall hkLdrLoadDll(
	PWCHAR               PathToFile_OPTIONAL,
	ULONG                Flags,
	PUNICODE_STRING      ModuleFileName,
	PHANDLE             ModuleHandle)
{
	static HMODULE appHost = GetModuleHandleA(NULL);
	static ArtemisConfig* cfg = CArtemisReal::GetInstance()->GetConfig();

	auto ModuleThreatReport = [&](PVOID lpBase, DWORD dwSize, const std::wstring& path,
		const std::wstring& name, DetectionType detect, const std::string& hack_name = "")
	{
		MEMORY_BASIC_INFORMATION mme{ 0 }; ARTEMIS_DATA data;
		VirtualQuery((LPCVOID)lpBase, &mme, sizeof(MEMORY_BASIC_INFORMATION));
		data.baseAddr = (PVOID)lpBase; data.MemoryRights = mme.AllocationProtect;
		char* szPath = new char[path.length() + 1];
		WideCharToMultiByte(CP_ACP, 0, path.c_str(), -1, szPath, (int)path.length(), NULL, NULL);
		szPath[path.length() + 1] = '\00';
		char* szName = new char[name.length() + 1];
		WideCharToMultiByte(CP_ACP, 0, name.c_str(), -1, szName, (int)name.length(), NULL, NULL);
		szName[name.length() + 1] = '\00';
		data.regionSize = dwSize;
		data.dllName = szName;
		data.dllPath = szPath;
		data.type = detect;
		if (detect == DetectionType::ART_HACK_STRING_FOUND || detect == DetectionType::ART_SIGNATURE_DETECT) data.HackName = hack_name;
		cfg->callback(&data); cfg->ExcludedModules.push_back((PVOID)lpBase);
		delete[] szPath;
		delete[] szName;
	};

	std::wstring wstrModuleFileName = std::wstring(ModuleFileName->Buffer, ModuleFileName->Length);
	NTSTATUS result = ptrOriginalLdrLoadDll(PathToFile_OPTIONAL, Flags, ModuleFileName, ModuleHandle);
	if (ModuleHandle == 0 || *ModuleHandle == 0)
		goto retnOrig;
	
	wprintf(L"DLL Loaded: %s\n", wstrModuleFileName.c_str());

	MODULEINFO modInfo;
	if (K32GetModuleInformation(GetCurrentProcess(), (HMODULE)*ModuleHandle, &modInfo, sizeof(modInfo)))
	{
		PVOID  lpBase = modInfo.lpBaseOfDll;
		DWORD  dwSize = modInfo.SizeOfImage;

		if (lpBase == 0x0 || dwSize == 0x0) goto retnOrig; // validating every page record from memory list
		
		orderedMapping.insert(std::pair<DWORD, DWORD>((DWORD)lpBase, dwSize));
		WCHAR wszFileName[MAX_PATH + 1]; 
		if (!GetModuleFileNameW((HMODULE)lpBase, wszFileName, MAX_PATH + 1)) goto retnOrig;
		DWORD CRC32 = Utils::GenerateCRC32(wszFileName, nullptr);
		std::wstring DllName = Utils::GetDllName(wstrModuleFileName);
		orderedIdentify.insert(orderedIdentify.begin(), std::pair<DWORD, std::wstring>(CRC32, DllName));
		
		
		if ((lpBase != appHost && lpBase != cfg->hSelfModule) &&
			!Utils::IsVecContain(cfg->ExcludedModules, lpBase))
		{
			std::wstring NameOfDLL = L"", wszFileName = L"";
			// IsModuleDuplicated - вернет имя длл и путь в любом случае для пользования в коде ниже этого блока в том числе
			if (Utils::IsModuleDuplicated((HMODULE)lpBase, wszFileName, orderedIdentify, NameOfDLL))
			{
				printf("Module duplicated!\n");
				//if (!Utils::OsProtectedFile(wszFileName.c_str())) // New advanced algorithm!
				//{
					//printf("Module not OsProtected! Detect!\n");
					ModuleThreatReport(lpBase, dwSize, wszFileName, NameOfDLL, DetectionType::ART_PROXY_LIBRARY);
					goto retnOrig; // если данный модуль уже словил детект - нет смысла идти дальше по нему
				//}
			}
			else
			{
				// чтобы если выше выполнилась проверка то не дублировать вызов еще раз а если нет - конвертим строку
				if (Utils::OsProtectedFile(wszFileName.c_str()))
				{
					printf("Module OsProtected 2\n");
					goto retnOrig;
				}
				if (Utils::w_findStringIC(NameOfDLL, L"MSVCP") || Utils::w_findStringIC(NameOfDLL, L"api-ms-win") ||
					Utils::w_findStringIC(NameOfDLL, L"VCRUNTIME")) goto retnOrig;
				if (cfg->DetectPacking && IsModulePacked((HMODULE)lpBase, cfg->AllowedPackedModules))
				{
					printf("Module packed!\n");
					ModuleThreatReport(lpBase, dwSize, wszFileName, NameOfDLL, DetectionType::ART_PROTECTOR_PACKER);
					goto retnOrig; // если данный модуль уже словил детект - нет смысла идти дальше по нему
				}
				if (cfg->DetectByString)
				{
					for (const auto& illegalString : cfg->IlegaleLinien) // Список строк для поиска читов (вектор стринг)
					{
						printf("Scanning for string %s\n", illegalString.c_str());
						DWORD dwAddr = SigScan::FindPatternExplicit((DWORD)lpBase, dwSize, illegalString.c_str(), std::string(illegalString.length(), 'x').c_str());
						char* ptr = (char*)dwAddr;
						if (ptr != nullptr)
						{
							std::string match = std::string(ptr, illegalString.length());
							ModuleThreatReport(lpBase, dwSize, wszFileName, NameOfDLL, DetectionType::ART_HACK_STRING_FOUND, match);
							goto retnOrig; // если данный модуль уже словил детект - нет смысла идти дальше по нему
						}
					}
				}
				if (cfg->DetectBySignature)
				{
					for (const auto& sg : cfg->IllegalPatterns) // Список сигнатур для поиска известных читов или их участков памяти
					{
						printf("Scanning for signature...\n");
						DWORD sgAddr = SigScan::FindPattern((HMODULE)lpBase,
							std::get<0>(sg.second).c_str()/*"\x8D\x45\xF4\x64\xA3\x00\x00\x00\x00\x68"*/, std::get<1>(sg.second).c_str());
						//printf("[SIG WALKER] Name: %s | Pattern: %s | Mask: %s | Len: %d\n", NameOfDLL.c_str(),
						//std::get<0>(sg.second).c_str(), std::get<1>(sg.second).c_str(), std::get<0>(sg.second).length());
						if (sgAddr != NULL)
						{
							ModuleThreatReport(lpBase, dwSize, wszFileName, NameOfDLL, DetectionType::ART_SIGNATURE_DETECT, sg.first);
						}
					}
				}
			}
		}
	}
	else printf("Error getting modinfo\n");

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

	auto ModuleThreatReport = [&](const auto& it, const std::wstring& path, 
	const std::wstring& name, DetectionType detect, const std::string& hack_name = "")
	{
		MEMORY_BASIC_INFORMATION mme { 0 }; ARTEMIS_DATA data;
		VirtualQuery((LPCVOID)it.first, &mme, sizeof(MEMORY_BASIC_INFORMATION));
		data.baseAddr = (PVOID)it.first; data.MemoryRights = mme.AllocationProtect;
		char* szPath = new char[path.length() + 1];
		WideCharToMultiByte(CP_ACP, 0, path.c_str(), -1, szPath, (int)path.length(), NULL, NULL);
		char* szName = new char[name.length() + 1];
		WideCharToMultiByte(CP_ACP, 0, name.c_str(), -1, szName, (int)name.length(), NULL, NULL);
		data.regionSize = it.second; 
		data.dllName = szName;
		data.dllPath = szPath; 
		data.type = detect; 
		if (detect == DetectionType::ART_HACK_STRING_FOUND || detect == DetectionType::ART_SIGNATURE_DETECT) data.HackName = hack_name;
		cfg->callback(&data); cfg->ExcludedModules.push_back((PVOID)it.first);
		delete[] szPath;
		delete[] szName;
	};
	DWORD appHost = (DWORD)GetModuleHandleA(NULL); // Optimizated (Now is non-recursive call!)
	Utils::BuildModuledMemoryMap(cfg->CurrProc); // Refactored parser -> now faster on 70% than previous!
	for (const auto& it : orderedMapping)
	{
		if (it.first == 0x0 || it.second == 0x0) continue; // validating every page record from memory list
		if ((it.first != appHost && it.first != (DWORD)cfg->hSelfModule) &&
		!Utils::IsVecContain(cfg->ExcludedModules, (PVOID)it.first))
		{
			std::wstring NameOfDLL = L"", wszFileName = L""; // Optimizated (Less-recursive calls!)
			// IsModuleDuplicated - вернет имя длл и путь в любом случае для пользования в коде ниже этого блока в том числе
			if (Utils::IsModuleDuplicated((HMODULE)it.first, wszFileName, orderedIdentify, NameOfDLL)) 
			{
				if (!Utils::OsProtectedFile(wszFileName.c_str())) // New advanced algorithm!
				{
					ModuleThreatReport(it, wszFileName, NameOfDLL, DetectionType::ART_PROXY_LIBRARY);
					continue; // если данный модуль уже словил детект - нет смысла идти дальше по нему
				}
			}
			else
			{
				// чтобы если выше выполнилась проверка то не дублировать вызов еще раз а если нет - конвертим строку
				if (Utils::OsProtectedFile(wszFileName.c_str())) continue;
				if (Utils::w_findStringIC(NameOfDLL, L"MSVCP") || Utils::w_findStringIC(NameOfDLL, L"api-ms-win") ||
				Utils::w_findStringIC(NameOfDLL, L"VCRUNTIME")) continue;
				if (cfg->DetectPacking && IsModulePacked((HMODULE)it.first, cfg->AllowedPackedModules))
				{
					ModuleThreatReport(it, wszFileName, NameOfDLL, DetectionType::ART_PROTECTOR_PACKER);
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
							ModuleThreatReport(it, wszFileName, NameOfDLL, DetectionType::ART_HACK_STRING_FOUND, match);
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
							ModuleThreatReport(it, wszFileName, NameOfDLL, DetectionType::ART_SIGNATURE_DETECT, sg.first);
						}
					}
				}
			}
		}
continueMain:;
	}
}
