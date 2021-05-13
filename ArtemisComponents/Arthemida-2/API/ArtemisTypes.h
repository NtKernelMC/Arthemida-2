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
		ART_UNKNOWN_DETECT,
		ART_ILLEGAL_THREAD,
		ART_PROXY_LIBRARY,
		ART_DLL_CLOACKING,
		ART_FAKE_LAUNCHER,
		ART_RETURN_ADDRESS,
		ART_MANUAL_MAP,
		ART_MEMORY_CHANGED,
		ART_PROTECTOR_PACKER,
		ART_HACK_STRING_FOUND,
		ART_SIGNATURE_DETECT,
		ART_ILLEGAL_SERVICE
	};
	struct ARTEMIS_DATA
	{
		PVOID baseAddr = nullptr;
		SIZE_T regionSize = 0x0;
		DWORD MemoryRights = 0x0;
		DetectionType type = DetectionType::ART_UNKNOWN_DETECT;
		std::string dllName = "";
		std::string dllPath = "";
		std::string HackName = "";
		std::string filePath = "";
	};
	typedef void(__stdcall* ArtemisCallback)(ARTEMIS_DATA* artemis);
	struct ArtemisConfig
	{
		// basic stuff
		bool SingletonCalled = false;
		HANDLE hSelfModule = nullptr;
		HANDLE CurrProc = nullptr;
		std::vector<HANDLE> OwnThreads;
		ArtemisCallback callback = nullptr;
		// anticheat controller options
		bool DetectThreads = false;
		bool DetectModules = false;
		bool DetectFakeLaunch = false;
		bool DetectManualMap = false;
		bool DetectMemoryPatch = false;
		bool DetectBySignature = false;
		bool DetectPacking = false;
		bool DetectByString = false;
		bool ServiceMon = false;
		// anti-repeatable start for scanners
		bool ThreadScanner = false;
		bool ModuleScanner = false;
		bool MemoryScanner = false;
		bool SignatureScanner = false;
		bool MemGuardScanner = false;
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
		// heuristical detection set
		std::vector<std::string> AllowedPackedModules; // for cfg.DetectPacking = true;
		std::vector<std::string> IlegaleLinien; // for cfg.DetectByString
		// service stuff set
		std::map<PVOID, PVOID> HooksList; // DestinyAddress, InterceptorAddress
		std::map<std::string, std::tuple<const char*, const char*>> IllegalPatterns; 
		// human-readable hack name, pattern, mask
		std::map<std::string, std::tuple<std::string, std::string>> IllegalDriverPatterns; 
		// human-readable driver/hack name, pattern, mask
		std::set<std::string> PriorityDriverNames; 
		// todo: services with servicename or files with filename matching those strings will be given priority in scanner
	};
}