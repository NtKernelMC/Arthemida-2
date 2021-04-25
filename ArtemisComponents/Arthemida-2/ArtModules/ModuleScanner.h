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
// Will be changed in next update, detected kernelbase recursive calls with highload perfomance!
// Issued WIN API: GetFileVersionInfoSizeA - There no way i guess to use it in scan cycle, always called FreeLibrary.
static bool GetLibVersionInfo(const MtaUtils::SString& strLibName, SLibVersionInfo* pOutLibVersionInfo)
{
	DWORD dwHandle = 0x0, dwLen = 0x0;
	dwLen = GetFileVersionInfoSizeA(strLibName, &dwHandle);
	if (!dwLen) return false;
	LPTSTR lpData = (LPTSTR)malloc(dwLen);
	if (!lpData) return FALSE; SetLastError(0);
	if (!GetFileVersionInfoA(strLibName, NULL, dwLen, lpData))
	{
		free(lpData);
		return false;
	}
	DWORD dwError = GetLastError();
	if (dwError)
	{
		free(lpData);
		return false;
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
	return false;
}
typedef NTSTATUS(__stdcall* ptrLdrUnloadDll)(HMODULE ModuleHandle);
ptrLdrUnloadDll callLdrUnloadDll = nullptr;
void __stdcall LdrUnloadDll(HMODULE ModuleHandle) // For now - all hooks are in the code-refactoring
{
	if (ModuleHandle == nullptr) return; //return ERROR_FILE_NOT_FOUND;
	/*NTSTATUS rslt = NULL; // CodeAnalyzer : Var Init Rule 
	if (callLdrUnloadDll == nullptr) return rslt; // if somebody is so tired to forgot obtain address for NTAPI
	std::string ModulePath = Utils::GetLibNameFromHandle(ModuleHandle); // extract untill it mapped
	static DWORD tmpMDL = (DWORD)ModuleHandle; // save pointer with unchangable address
	MiniJumper::CustomHooks::RestorePrologue((DWORD)callLdrUnloadDll, (PVOID)fTr2, ldrUnload, 5);
	rslt = callLdrUnloadDll(ModuleHandle); // let`s module will be unmapped for sure
	fTr2 = MiniJumper::CustomHooks::MakeJump((DWORD)callLdrUnloadDll, (DWORD)&LdrUnloadDll, ldrUnload, 5);
	if (NT_ERROR(rslt)) return rslt; // we are not needed in any surprises*/
	std::string ModulePath = Utils::GetLibNameFromHandle(ModuleHandle); // extract untill it mapped
#ifdef ARTEMIS_DEBUG
	Utils::LogInFile(ARTEMIS_LOG, "[LdrUnloadDll] %s unloaded | Base: 0x%X | TID: %d\n",
	ModulePath.c_str(), (DWORD)ModuleHandle, GetCurrentThreadId());
#endif
	// C++17 RAII-Style Scope (Critical Section)
	//{ 
		//std::scoped_lock lock { orderedMapping_mutex, orderedIdentify_mutex };
		/*orderedMapping.erase(orderedMapping.find(tmpMDL));
		CHAR szFileName[MAX_PATH + 1]; GetModuleFileNameA((HMODULE)tmpMDL, szFileName, MAX_PATH + 1);
		DWORD CRC32 = Utils::GenerateCRC32(szFileName);
		orderedIdentify.erase(orderedIdentify.find(CRC32));*/
	//}
	//return rslt;
	__asm jmp fTr2
}
typedef NTSTATUS(__stdcall* ptrLdrLoadDll)(PWCHAR PathToFile, ULONG FlagsL, 
PUNICODE_STRING ModuleFileName, HMODULE* ModuleHandle);
ptrLdrLoadDll callLdrLoadDll = nullptr;
NTSTATUS __stdcall LdrLoadDll(PWCHAR PathToFile, ULONG FlagsL, PUNICODE_STRING ModuleFileName, HMODULE* ModuleHandle)
{
	NTSTATUS rslt = NULL; // CodeAnalyzer : Var Init Rule 
	if (callLdrLoadDll == nullptr) return rslt; // if somebody is so tired to forgot obtain address for NTAPI
	MiniJumper::CustomHooks::RestorePrologue((DWORD)callLdrLoadDll, (PVOID)fTr1, ldrLoad, 5);
	rslt = callLdrLoadDll(PathToFile, FlagsL, ModuleFileName, ModuleHandle); // let`s module will be mapped for sure
	fTr1 = MiniJumper::CustomHooks::MakeJump((DWORD)callLdrLoadDll, (DWORD)&LdrLoadDll, ldrLoad, 5);
	if (NT_ERROR(rslt)) return rslt; // we are not needed in any surprises
	std::wstring ModulePath(ModuleFileName->Buffer, ModuleFileName->Length); // extract wide-string from PEB Symbolic Link
	if (ModuleHandle != nullptr) // fcking pointer safety
	{
#ifdef ARTEMIS_DEBUG
		Utils::LogInFile(ARTEMIS_LOG, "[LdrLoadDll] %ls loaded! Base: 0x%X | TID: %d\n",
		ModulePath.c_str(), *ModuleHandle, GetCurrentThreadId());
#endif
		LPMODULEINFO mem = Utils::GetModuleMemoryInfo(*ModuleHandle);
		if (mem != nullptr)
		{
			// C++17 RAII-Style Scope
			//{ 
				//std::scoped_lock lock { orderedMapping_mutex, orderedIdentify_mutex };
				orderedMapping.insert(orderedMapping.begin(),
				std::pair<DWORD, DWORD>((DWORD)*ModuleHandle, mem->SizeOfImage));
				CHAR szFileName[MAX_PATH + 1]; GetModuleFileNameA(*ModuleHandle, szFileName, MAX_PATH + 1);
				DWORD CRC32 = Utils::GenerateCRC32(szFileName, nullptr);
				std::string DllName = Utils::GetLibNameFromHandle(*ModuleHandle, szFileName);
				orderedIdentify.insert(orderedIdentify.begin(), std::pair<DWORD, std::string>(CRC32, DllName));
			//}
		}
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
	Utils::LogInFile(ARTEMIS_LOG, "[INFO] Created async thread for ModuleScanner! Thread id: %d\n", GetCurrentThreadId());
#endif
	if (cfg->ModuleScanner) return;
	cfg->ModuleScanner = true;
	auto IsNotWinOrAVModule = [](const std::string& m_path) -> bool // Will be modified, found false-positives and etc..
	{
		SLibVersionInfo dll_ver; if (GetLibVersionInfo(m_path.c_str(), &dll_ver))
		{
			if (Utils::findStringIC(m_path, R"(Windows\System32)") ||
			Utils::findStringIC(m_path, R"(Program Files\ESET\ESET Security\x86)"))
			{
				if (dll_ver.strCompanyName.length() >= 4 && dll_ver.strProductName.length() >= 4) return false;
			}
		}
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
		/*fTr1 = MiniJumper::CustomHooks::MakeJump((DWORD)callLdrLoadDll, (DWORD)&LdrLoadDll, ldrLoad, 5);
		if (fTr1 != NULL) DiagnosticMSG("[INSTALLER-2] LdrLoadDll hook was successfully installed!\n");
		else return DiagnosticMSG("[Hooking Error #1] By some reasons, hook is not exist in to the list.\n");*/
		///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		callLdrUnloadDll = (ptrLdrUnloadDll)Utils::RuntimeIatResolver("ntdll.dll", "LdrUnloadDll");
		if (callLdrUnloadDll == nullptr) return DiagnosticMSG("[FAILURE $2] nullptr | LdrUnloadDll\n");
		/*fTr2 = MiniJumper::CustomHooks::MakeJump((DWORD)callLdrUnloadDll, (DWORD)&LdrUnloadDll, ldrUnload, 5);
		if (fTr2 != NULL) DiagnosticMSG("[INSTALLER-2] LdrUnloadDll hook was successfully installed!\n");
		else return DiagnosticMSG("[Hooking Error #2] By some reasons, hook is not exist in to the list!\n");*/
		return 0xDEADBEEF;
	}; 
	// let`s parse it only one times, cuz we need to know wich exactly modules was loaded before us
	//Utils::BuildModuledMemoryMap(); // thread-safe -> called only once before hooks will be installed
	//PushNativeHooks(); // now - we can obtain a fresh lists at the run-time, big advantage for speed perfomance
	//return; // Remove after testing!!!
	while (true) // Runtime Duplicates-Module Scanner && ProxyDLL Detector
	{
		//{ // C++17 RAII-Style Scope
			//std::scoped_lock lock { orderedMapping_mutex, orderedIdentify_mutex };
			Utils::BuildModuledMemoryMap(); // on considering, for test period must be as old-worked style
			for (const auto& it : orderedMapping)
			{
				if (it.first == NULL) continue; // for sure
				if ((it.first != (DWORD)GetModuleHandleA(NULL) && it.first != (DWORD)cfg->hSelfModule) &&
				!Utils::IsVecContain(cfg->ExcludedModules, (PVOID)it.first))
				{
					// C:\Windows\System32\TextShaping.dll - Empty version info, fix false-positive by cert check! (Microsoft)
					std::string NameOfDLL = "", szFileName = ""; DWORD fSize = 0x0; // Optimizated (Less-recursive calls!)
					if (Utils::IsModuleDuplicated((HMODULE)it.first, szFileName, &fSize, orderedIdentify, NameOfDLL))
					{
						/*#ifdef ARTEMIS_DEBUG
						Utils::LogInFile(ARTEMIS_LOG, "[MODULE FILLER] %s\nBase: 0x%X | Size: 0x%X\n",
						szFileName.c_str(), it.first, it.second);
						#endif*/
						if (IsNotWinOrAVModule(szFileName)) // FIX LdrUnloadDll RECURSION FROM THAT SHIT!
						{ 
							MEMORY_BASIC_INFORMATION mme { 0 }; ARTEMIS_DATA data;
							VirtualQuery((PVOID)it.first, &mme, sizeof(MEMORY_BASIC_INFORMATION));
							data.baseAddr = (PVOID)it.first; data.EmptyVersionInfo = true;
							data.MemoryRights = mme.AllocationProtect;
							data.regionSize = fSize; data.dllName = NameOfDLL;
							data.dllPath = szFileName; data.type = DetectionType::ART_PROXY_LIBRARY;
							cfg->callback(&data); cfg->ExcludedModules.push_back((PVOID)it.first);
						}
					}
				}
			}
		//}
		Sleep(cfg->MemoryScanDelay);
	}
}