#pragma once
#include "Utils/Utils.h"
namespace ART_LIB
{
	class ArtemisLibrary
	{
	public:
		enum class DetectionType
		{
			ART_ILLEGAL_THREAD = 1,
			ART_ILLEGAL_MODULE = 2,
			ART_FAKE_LAUNCHER = 3,
			ART_APC_INJECTION = 4,
			ART_RETURN_ADDRESS = 5,
			ART_MANUAL_MAP = 6,
			ART_MEMORY_CHANGED = 7,
			ART_SIGNATURE_DETECT = 8,
			ART_SIGNATURES_MODIFIED = 9
		};
		struct ARTEMIS_DATA
		{
			PVOID baseAddr;
			SIZE_T regionSize;
			DWORD MemoryRights;
			DetectionType type;
			std::string dllName;
			std::string dllPath;
			std::string HackName;
			std::tuple<PVOID, PCONTEXT, const char*> ApcInfo;
		};
		typedef void(__stdcall* ArtemisCallback)(ARTEMIS_DATA* artemis);
		typedef DWORD(__stdcall* LPFN_GetMappedFileNameA)(HANDLE hProcess, LPVOID lpv, LPCSTR lpFilename, DWORD nSize);
		struct ArtemisConfig
		{
			HANDLE hSelfModule = nullptr;
			std::multimap<DWORD, std::string> ModuleSnapshot;
			LPFN_GetMappedFileNameA lpGetMappedFileNameA = nullptr;
			ArtemisCallback callback = nullptr;
			std::vector<PVOID> ExcludedThreads;
			std::vector<PVOID> ExcludedMethods;
			bool DetectThreads = false;
			volatile bool ThreadScanner = false;
			volatile bool ModuleScanner = false;
			DWORD ThreadScanDelay = 0x0;
			std::vector<PVOID> ExcludedModules;
			std::vector<PVOID> ExcludedImages;
			bool DetectModules = false;
			DWORD ModuleScanDelay = 0x0;
			DWORD MemoryScanDelay = 0x0;
			DWORD PatternScanDelay = 0x0;
			bool DetectFakeLaunch = false;
			bool DetectAPC = false;
			bool DetectReturnAddresses = false;
			bool DetectManualMap = false;
			bool DetectMemoryPatch = false;
			bool DetectPatterns = false;
			DWORD MemoryGuardDelay;
			std::vector<PVOID> ExcludedPatches;
			std::vector<std::string> ModulesWhitelist;
			std::map<std::string, std::tuple<const char*, const char*>> IllegalPatterns;
			std::vector<PVOID> DetectedSigAddresses;
		};
		virtual void DumpExportTable(HMODULE hModule, std::multimap<PVOID, std::string>& ExportsList) = 0;
		virtual void __stdcall ScanForDllThreads(ArtemisConfig* cfg) = 0;
		virtual void __stdcall ModuleScanner(ArtemisConfig* cfg) = 0;
		virtual bool __stdcall InstallApcDispatcher(ArtemisConfig* cfg) = 0;
		virtual bool __stdcall DeleteApcDispatcher(void) = 0;
		virtual void __stdcall MemoryScanner(ArtemisConfig* cfg) = 0;
		virtual void __stdcall CheckLauncher(ArtemisConfig* cfg) = 0;
		virtual void __stdcall SigScanner(ArtemisConfig* cfg) = 0;
	};
};
extern ART_LIB::ArtemisLibrary::ArtemisConfig* g_cfg;