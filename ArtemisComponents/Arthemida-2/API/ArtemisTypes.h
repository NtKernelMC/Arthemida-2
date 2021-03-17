#pragma once
#pragma warning (disable : 4477)
#include "../../Arthemida-2/ArtUtils/Utils.h"
namespace ArtemisData
{
	enum class DetectionType
	{
		ART_ILLEGAL_THREAD = 1,
		ART_ILLEGAL_MODULE = 2,
		ART_FAKE_LAUNCHER = 3,
		ART_RETURN_ADDRESS = 4,
		ART_MANUAL_MAP = 5,
		ART_MEMORY_CHANGED = 6,
		ART_SIGNATURE_DETECT = 7
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
}