/*
	Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC & holmes0
*/
#include "ArtemisInterface.h"
#include "../../Arthemida-2/ArtUtils/SString.hpp"
#include "../../Arthemida-2/ArtUtils/MiniJumper.h"
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
typedef NTSTATUS(__stdcall* ptrLdrUnloadDll)(HMODULE ModuleHandle);
ptrLdrUnloadDll callLdrUnloadDll = nullptr;
NTSTATUS __stdcall LdrUnloadDll(HMODULE ModuleHandle)
{
	if (ModuleHandle == nullptr) return ERROR_FILE_NOT_FOUND;
	NTSTATUS rslt = NULL; // CodeAnalyzer : Var Init Rule 
	if (callLdrUnloadDll == nullptr) return rslt;// if somebody is so tired to forgot obtain address for NTAPI
	std::string ModulePath = Utils::GetLibNameFromHandle(ModuleHandle); // extract untill it mapped
	static DWORD tmpMDL = (DWORD)ModuleHandle; // save pointer with unchangable address
	MiniJumper::CustomHooks::RestorePrologue((DWORD)callLdrUnloadDll, (PVOID)fTr2, ldrUnload, 5);
	rslt = callLdrUnloadDll(ModuleHandle); // let`s module will be unmapped for sure
	fTr2 = MiniJumper::CustomHooks::MakeJump((DWORD)callLdrUnloadDll, (DWORD)&LdrUnloadDll, ldrUnload, 5);
	if (NT_ERROR(rslt)) return rslt; // we are not needed in any surprises
#ifdef ARTEMIS_DEBUG
	Utils::LogInFile(ARTEMIS_LOG, "[LdrUnloadDll] %s unloaded | TID: %d\n", ModulePath.c_str(), GetCurrentThreadId());
#endif
	if (fireSignal.try_acquire()) // red
	{
		//orderedMapping.erase(std::find(orderedMapping.begin(), orderedMapping.end(), (HMODULE)tmpMDL));
		//CHAR szFileName[MAX_PATH + 1]; GetModuleFileNameA((HMODULE)tmpMDL, szFileName, MAX_PATH + 1);
		//DWORD CRC32 = Utils::GenerateCRC32(szFileName); 
		//orderedIdentify.erase(std::find(orderedIdentify.begin(), orderedIdentify.end(), CRC32));
	}
	fireSignal.release(); // blue
	return rslt;
}
typedef NTSTATUS(__stdcall* ptrLdrLoadDll)(PWCHAR PathToFile, ULONG FlagsL, 
PUNICODE_STRING ModuleFileName, HMODULE* ModuleHandle);
ptrLdrLoadDll callLdrLoadDll = nullptr;
NTSTATUS __stdcall LdrLoadDll(PWCHAR PathToFile, ULONG FlagsL, PUNICODE_STRING ModuleFileName, HMODULE* ModuleHandle)
{
	NTSTATUS rslt = NULL; // CodeAnalyzer : Var Init Rule 
	if (callLdrLoadDll == nullptr) return rslt;// if somebody is so tired to forgot obtain address for NTAPI
	MiniJumper::CustomHooks::RestorePrologue((DWORD)callLdrLoadDll, (PVOID)fTr1, ldrLoad, 5);
	rslt = callLdrLoadDll(PathToFile, FlagsL, ModuleFileName, ModuleHandle); // let`s module will be mapped for sure
	fTr1 = MiniJumper::CustomHooks::MakeJump((DWORD)callLdrLoadDll, (DWORD)&LdrLoadDll, ldrLoad, 5);
	if (NT_ERROR(rslt)) return rslt; // we are not needed in any surprises
	std::wstring ModulePath(ModuleFileName->Buffer, ModuleFileName->Length); // extract wide-string from PEB Symbolic Link
	if (ModuleHandle != nullptr) // fcking pointer safety
	{
#ifdef ARTEMIS_DEBUG
		Utils::LogInFile(ARTEMIS_LOG, "[LdrLoadDll] %ls loaded!\n(Base: 0x%X | TID: %d)\n",
		ModulePath.c_str(), *ModuleHandle, GetCurrentThreadId());
#endif
		if (fireSignal.try_acquire()) // red
		{
			LPMODULEINFO mem = Utils::GetModuleMemoryInfo(*ModuleHandle);
			if (mem != nullptr)
			{
				//orderedMapping.insert(orderedMapping.begin(), std::pair<PVOID, DWORD>(*ModuleHandle, mem->SizeOfImage));
				//CHAR szFileName[MAX_PATH + 1]; GetModuleFileNameA(*ModuleHandle, szFileName, MAX_PATH + 1);
				//DWORD CRC32 = Utils::GenerateCRC32(szFileName); 
				//std::string DllName = Utils::GetLibNameFromHandle(*ModuleHandle);
				//orderedIdentify.insert(orderedIdentify.begin(), std::pair<DWORD, std::string>(CRC32, DllName));
			}
		}
		fireSignal.release(); // blue
	}
	return rslt;
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
	auto IsNotWinOrAVModule = [](const std::string& m_path) -> bool
	{
		SLibVersionInfo dll_ver; if (GetLibVersionInfo(m_path.c_str(), &dll_ver))
		{
#ifdef ARTEMIS_DEBUG
			//Utils::LogInFile(ARTEMIS_LOG, "[VERSION_INFO] Company: %s len: %d | Product: %s len: %d\n",
			//dll_ver.strCompanyName.c_str(), dll_ver.strCompanyName.length(), 
			//dll_ver.strProductName.c_str(), dll_ver.strProductName.length());
#endif
			if (Utils::findStringIC(m_path, R"(Windows\System32)") ||
			Utils::findStringIC(m_path, R"(Program Files\ESET\ESET Security\x86)"))
			{
				if (dll_ver.strCompanyName.length() >= 4 && dll_ver.strProductName.length() >= 4) return false;
			}
		}
#ifdef ARTEMIS_DEBUG
		//else Utils::LogInFile(ARTEMIS_LOG, "[VERSION_INFO] %d Error! %s\n", GetLastError(), m_path.c_str());
#endif
		return true;
	};
	decltype(auto) DiagnosticMSG = [](const std::string& reason_text) -> DWORD
	{
#ifdef ARTEMIS_DEBUG
		Utils::LogInFile(ARTEMIS_LOG, "%s", reason_text.c_str());
#endif
		return 0xDEADC0D3;
	};
	decltype(auto) PushNativeHooks = [&]() -> DWORD
	{
		callLdrLoadDll = (ptrLdrLoadDll)Utils::RuntimeIatResolver("ntdll.dll", "LdrLoadDll");
		if (callLdrLoadDll == nullptr) return DiagnosticMSG("[FAILURE $1] nullptr | LdrLoadDll\n");
		fTr1 = MiniJumper::CustomHooks::MakeJump((DWORD)callLdrLoadDll, (DWORD)&LdrLoadDll, ldrLoad, 5);
		if (fTr1 != NULL) DiagnosticMSG("[INSTALLER-2] LdrLoadDll hook was successfully installed!\n");
		else return DiagnosticMSG("[Hooking Error #1] By some reasons, hook is not exist in to the list.\n");
		///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		callLdrUnloadDll = (ptrLdrUnloadDll)Utils::RuntimeIatResolver("ntdll.dll", "LdrUnloadDll");
		if (callLdrUnloadDll == nullptr) return DiagnosticMSG("[FAILURE $2] nullptr | LdrUnloadDll\n");
		fTr2 = MiniJumper::CustomHooks::MakeJump((DWORD)callLdrUnloadDll, (DWORD)&LdrUnloadDll, ldrUnload, 5);
		if (fTr2 != NULL) DiagnosticMSG("[INSTALLER-2] LdrUnloadDll hook was successfully installed!\n");
		else return DiagnosticMSG("[Hooking Error #2] By some reasons, hook is not exist in to the list!\n");
		return 0xDEADBEEF;
	}; PushNativeHooks(); Utils::BuildModuledMemoryMap();
	while (true)
	{
		// Runtime Duplicates-Module Scanner && ProxyDLL Detector
		for (const auto& it : orderedMapping)
		{
			if (it.first == nullptr) continue; // fix for dll unloading from another threads
			if ((it.first != GetModuleHandleA(NULL) && it.first != cfg->hSelfModule) && 
			!Utils::IsVecContain(cfg->ExcludedModules, it.first)) 
			{
				CHAR szFileName[MAX_PATH + 1]; GetModuleFileNameA((HMODULE)it.first, szFileName, MAX_PATH + 1);
				if (Utils::IsModuleDuplicated((HMODULE)it.first, orderedIdentify))
				{
					if (IsNotWinOrAVModule(szFileName))
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