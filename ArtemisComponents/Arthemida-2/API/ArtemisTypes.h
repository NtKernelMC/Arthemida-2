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
		std::map<PVOID, PVOID> HooksList; // DestinyAddress, InterceptorAddress
		//std::map<PVOID, bool> ProtectedFunctions; // DestinyAddress, Detection flag
		std::map<std::string, std::tuple<const char*, const char*>> IllegalPatterns; // hack name, pattern, mask
	};
}