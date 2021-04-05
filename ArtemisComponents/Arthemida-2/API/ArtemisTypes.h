/*
	Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC & holmes0
*/
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
		ART_SIGNATURE_DETECT = 7,
		ART_ILLEGAL_SERVICE = 8
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
		bool EmptyVersionInfo;
	};
	typedef void(__stdcall* ArtemisCallback)(ARTEMIS_DATA* artemis);
	typedef DWORD(__stdcall* LPFN_GetMappedFileNameA)(HANDLE hProcess, LPVOID lpv, LPCSTR lpFilename, DWORD nSize);
	struct ArtemisConfig
	{
		// basic stuff
		HANDLE hSelfModule = nullptr;
		std::multimap<DWORD, std::string> ModuleSnapshot;
		LPFN_GetMappedFileNameA lpGetMappedFileNameA = nullptr;
		ArtemisCallback callback = nullptr;
		// anticheat controller options
		bool DetectThreads = false;
		bool DetectModules = false;
		bool DetectFakeLaunch = false;
		bool DetectManualMap = false;
		bool DetectMemoryPatch = false;
		bool DetectBySignature = false;
		bool ServiceMon = false;
		// anti-repeatable start for scanners
		volatile bool ThreadScanner = false;
		volatile bool ModuleScanner = false;
		volatile bool MemoryScanner = false;
		volatile bool SignatureScanner = false;
		volatile bool MemGuardScanner = false;
		// iteration delays for scanners
		DWORD ThreadScanDelay = 0x0;
		DWORD ModuleScanDelay = 0x0;
		DWORD MemoryScanDelay = 0x0;
		DWORD PatternScanDelay = 0x0;
		DWORD MemoryGuardScanDelay = 0x0;
		DWORD ServiceMonDelay = 0x0;
		// additional settings & stuff
		std::vector<PVOID> ExcludedThreads;
		std::vector<PVOID> ExcludedModules;
		std::vector<PVOID> ExcludedImages;
		std::vector<PVOID> ExcludedMethods;
		std::vector<PVOID> ExcludedPatches;
		std::vector<PVOID> ExcludedSigAddresses;
		std::map<PVOID, PVOID> HooksList; // DestinyAddress, InterceptorAddress
		//std::map<PVOID, bool> ProtectedFunctions; // DestinyAddress, Detection flag
		std::map<std::string, std::tuple<const char*, const char*>> IllegalPatterns; // hack name, pattern, mask
	};
}