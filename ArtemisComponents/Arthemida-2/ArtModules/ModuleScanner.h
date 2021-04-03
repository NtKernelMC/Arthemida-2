/*
	Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC & holmes0
*/
// TODO:
// Install Hooks on ntdll.dll LdrLoadDLL & LdrUnloadDll (Do First Scan with BuildModuledMemoryMap & next -> hooks)
// Hook GetModuleHandle(client.dll) and check on GetImagePathName (Possible PEB-hide detection)
// GetLibVersion Util and Analyze information of duplicates
/*
	// TryHard ProxyDLL Export Code Sample #1
	74771050 | 55 | push ebp | 01_TryHard.cpp:14
	74771051 | 8BEC | mov ebp,esp |
	74771053 | A1 C0337774 | mov eax,dword ptr ds:[VerFindFileW]
	74771058 | 5D | pop ebp | 01_TryHard.cpp:16
	74771059 | FFE0 | jmp eax | 01_TryHard.cpp:15

	//Early Proxy Load Detect
	kernel32.dll LoadLibraryA + LoadLibraryW -> CheckReturnAddress ->
	if the same module name = Proxy, if unlinked = PEB HIDE
*/
#include "ArtemisInterface.h"
#include "../../Arthemida-2/ArtUtils/SString.hpp"
// Сканнер модулей
struct SLibVersionInfo : VS_FIXEDFILEINFO
{
	MtaUtils::SString strCompanyName;
	MtaUtils::SString strProductName;
};
static bool GetLibVersionInfo(const MtaUtils::SString& strLibName, SLibVersionInfo* pOutLibVersionInfo)
{
	DWORD dwHandle = 0x0, dwLen = 0x0;
	dwLen = GetFileVersionInfoSizeA(strLibName, &dwHandle);
	if (!dwLen) return FALSE;
	LPTSTR lpData = (LPTSTR)malloc(dwLen);
	if (!lpData) return FALSE;
	SetLastError(0);
	if (!GetFileVersionInfoA(strLibName, dwHandle, dwLen, lpData))
	{
		free(lpData);
		return FALSE;
	}
	DWORD dwError = GetLastError();
	if (dwError)
	{
		free(lpData);
		return FALSE;
	}
	UINT BufLen = 0x0; VS_FIXEDFILEINFO* pFileInfo = nullptr;
	if (VerQueryValueA(lpData, "\\", (LPVOID*)&pFileInfo, (PUINT)&BufLen))
	{
		*(VS_FIXEDFILEINFO*)pOutLibVersionInfo = *pFileInfo;
		WORD* langInfo = nullptr; UINT  cbLang = 0x0;
		if (VerQueryValueA(lpData, "\\VarFileInfo\\Translation", (LPVOID*)&langInfo, &cbLang))
		{
			MtaUtils::SString strFirstBit("\\StringFileInfo\\%04x%04x\\", langInfo[0], langInfo[1]);
			LPVOID lpt = nullptr; UINT cbBufSize = 0x0;
			if (VerQueryValueA(lpData, strFirstBit + "CompanyName", &lpt, &cbBufSize))
			pOutLibVersionInfo->strCompanyName = MtaUtils::SStringX((const char*)lpt);
			if (VerQueryValueA(lpData, strFirstBit + "ProductName", &lpt, &cbBufSize))
			pOutLibVersionInfo->strProductName = MtaUtils::SStringX((const char*)lpt);
		}
		free(lpData);
		return true;
	}
	free(lpData);
	return FALSE;
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
	Utils::LogInFile(ARTEMIS_LOG, "[INFO] Created async thread for ModuleScanner!\n");
#endif
	if (cfg->ModuleScanner) return;
	cfg->ModuleScanner = true;
	auto IsNotNativeWinModule = [](const std::string& m_path) -> bool
	{
		if (Utils::findStringIC(m_path, "C:\\Windows\\System32"))
		{
			SLibVersionInfo dll_ver; if (GetLibVersionInfo(m_path.c_str(), &dll_ver))
			{
				if (dll_ver.strCompanyName.length() >= 3 && dll_ver.strProductName.length() >= 3)
				{
#ifdef ARTEMIS_DEBUG
					//Utils::LogInFile(ARTEMIS_LOG, "[VERSION_INFO] Company: %s | Product: %s\n",
					//dll_ver.strCompanyName.c_str(), dll_ver.strProductName.c_str());
#endif
					return false;
				}
			}
		}
		return true;
	};
	while (true)
	{
		// Runtime Duplicates-Module Scanner && ProxyDLL Detector
		std::map<LPVOID, DWORD> NewModuleMap = Utils::BuildModuledMemoryMap(); 
		for (const auto& it : NewModuleMap)
		{
			if ((it.first != GetModuleHandleA(NULL) && it.first != cfg->hSelfModule) && 
			!Utils::IsVecContain(cfg->ExcludedModules, it.first)) 
			{
				CHAR szFileName[MAX_PATH + 1]; GetModuleFileNameA((HMODULE)it.first, szFileName, MAX_PATH + 1);
				if (Utils::IsModuleDuplicated((HMODULE)it.first, cfg->ModuleSnapshot)) 
				// Если наш модуль дублирует чье то имя но его хэш отличается
				{
					if (IsNotNativeWinModule(szFileName)) // Если наш модуль не является родной библиотекой винды
					{
						std::string NameOfDLL = Utils::GetDllName(szFileName);
						MEMORY_BASIC_INFORMATION mme{ 0 }; ARTEMIS_DATA data;
						VirtualQuery(it.first, &mme, sizeof(MEMORY_BASIC_INFORMATION));
						data.baseAddr = it.first; data.EmptyVersionInfo = true;
						data.MemoryRights = mme.AllocationProtect; DWORD fSize = 0x0; 
						FILE* nFile = fopen(szFileName, "rb");
						if (nFile != nullptr)
						{
							fSize = Utils::getFileSize(nFile);
							fclose(nFile);
						}
						data.regionSize = fSize; data.dllName = NameOfDLL; 
						data.dllPath = szFileName; data.type = DetectionType::ART_ILLEGAL_MODULE;
						cfg->callback(&data); cfg->ExcludedModules.push_back(it.first);
					}
				}
			}
		}
		Sleep(cfg->MemoryScanDelay);
	}
}