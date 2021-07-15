/*
	Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC & holmes0
*/
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <stdio.h>
#include "../ArtUtils/Utils.h"
#include ".../../../../Arthemida-2/API/ArtemisInterface.h"
using namespace std;
using namespace ArtemisData;
using CortPair = std::pair<std::string, std::tuple<std::string, std::string>>;
void __stdcall ArthemidaCallback(ARTEMIS_DATA* artemis)
{
	system("color 04"); Utils::LogInFile(ARTEMIS_LOG, "\n\n");
	if (artemis == nullptr)
	{
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK ERROR] Passed null pointer!\n");
		return;
	}
	switch (artemis->type)
	{
	case DetectionType::ART_ILLEGAL_THREAD:
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK] Detected Anonymous thread! %s\n%s\nStarted from: 0x%X | Size: 0x%X\n\n",
		artemis->dllName.c_str(), artemis->dllPath.c_str(), artemis->baseAddr, artemis->regionSize);
		break;
	case DetectionType::ART_PROXY_LIBRARY:
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK] Detected Proxy DLL! Base: 0x%X | Image Size: 0x%X | DllName: %s\n\
		\rPath: %s\n\n", artemis->baseAddr, artemis->regionSize, artemis->dllName.c_str(), artemis->dllPath.c_str());
		break;
	case DetectionType::ART_DLL_CLOACKING:
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK] Detected Hidden DLL! Started from: 0x%X\nSize: 0x%X | R: 0x%X | DllName: %s\n\
		\rPath: %s\n\n", artemis->baseAddr, artemis->regionSize, artemis->MemoryRights,
		artemis->dllName.c_str(), artemis->dllPath.c_str());
		break;
	case DetectionType::ART_PROTECTOR_PACKER:
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK] Detected Packed DLL! Base: 0x%X | Image Size: 0x%X | DllName: %s\n\
		\rPath: %s\n\n", artemis->baseAddr, artemis->regionSize, artemis->dllName.c_str(), artemis->dllPath.c_str());
		break;
	case DetectionType::ART_HACK_STRING_FOUND:
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK] Detected DLL Hack! Information: %s\nBase: 0x%X | Image Size: 0x%X | DllName: %s\n\
		\rPath: %s\n\n", artemis->HackName.c_str(), artemis->baseAddr,
		artemis->regionSize, artemis->dllName.c_str(), artemis->dllPath.c_str());
		break;
	case DetectionType::ART_FAKE_LAUNCHER:
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK] Detected Startup from Fake Launcher!\n");
		break;
	case DetectionType::ART_RETURN_ADDRESS:
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK] Detected Return to Hack Function! Address: 0x%X\n", artemis->baseAddr);
		break;
	case DetectionType::ART_MANUAL_MAP:
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK] Detected Mapped Image! %s\n%s\nBase: 0x%X | Size: 0x%X | Rights: 0x%X\n\n",
		artemis->dllName.c_str(), artemis->dllPath.c_str(), artemis->baseAddr, artemis->regionSize, artemis->MemoryRights);
		break;
	case DetectionType::ART_SIGNATURE_DETECT:
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK] Detected Signatured Hack! Name: %s\nBase: 0x%X | Image Size: 0x%X | DllName: %s\n\
		\rPath: %s\n\n", artemis->HackName.c_str(), artemis->baseAddr,
		artemis->regionSize, artemis->dllName.c_str(), artemis->dllPath.c_str());
		break;
	case DetectionType::ART_ILLEGAL_SERVICE:
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK] Detected Illegal service!\nName: %s | Path: %s\n\n", 
		artemis->HackName.c_str(), artemis->filePath.c_str());
		//"Path: %s | \nName: %s  | Description: %s | \nType: %d | BootSet: %s | Group: %s\n | Signed by: %s\n");
		break;
	case DetectionType::ART_THREAD_FLAGS_CHANGED:
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK] Detected thread with modified flags!\nHandle: 0x%X",
			(DWORD)artemis->baseAddr);
		break;
	case DetectionType::ART_MEMORY_INTEGRITY_VIOLATION:
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK] Detected memory integrity violation!\nBase: 0x%X | Size: 0x%X\n\n",
			(DWORD)artemis->baseAddr, (DWORD)artemis->regionSize);
		break;
	default:
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK] Unknown detection code! Base: 0x%X | Size: %d bytes | DllName: %s\n"
		"\rPath: %s\n\n", artemis->baseAddr, artemis->regionSize, artemis->dllName.c_str(), artemis->dllPath.c_str());
		break;
	}
	Utils::LogInFile(ARTEMIS_LOG, "\n\n");
}
/*class RetTest
{
public:
	static bool __stdcall TestStaticMethod(void)
	{
		IArtemisInterface* art_interface = IArtemisInterface::GetInstance();
		if (art_interface != nullptr) art_interface->ConfirmLegitReturn(__FUNCTION__, _ReturnAddress());
		Utils::LogInFile(ARTEMIS_LOG, "\n[ORIGINAL] Called %s!\n\n", __FUNCTION__);
		return true;
	}
	void __thiscall TestMemberMethod(void)
	{
		IArtemisInterface* art_interface = IArtemisInterface::GetInstance();
		if (art_interface != nullptr) art_interface->ConfirmLegitReturn(__FUNCTION__, _ReturnAddress());
		Utils::LogInFile(ARTEMIS_LOG, "\n[ORIGINAL] Called %s!\n\n", __FUNCTION__);
	}
}; RetTest testObj;*/
int main()
{
	SetConsoleCP(1251); SetConsoleOutputCP(1251);
	system("color 02"); SetConsoleTitleA("Arthemida-2 AntiCheat Lightweight Testing");
	printf("ConsoleHost main thread started! Thread ID: %d\n", GetCurrentThreadId());
	ArtemisConfig cfg; LoadLibraryA("version.dll");
	cfg.DetectFakeLaunch = true; // AntiFakeLaunch.h

	cfg.DetectThreads = true; // ThreadScanner.h
	cfg.ThreadScanDelay = 1000;

	cfg.DetectModules = true; // ModuleScanner.h
	cfg.ModuleScanDelay = 1000;
	
	cfg.DetectManualMap = true; // MemoryScanner.h
	cfg.MemoryScanDelay = 1000; 

	cfg.ServiceMon = true; // CServiceMon.h
	cfg.ServiceMonDelay = 1000;

	cfg.MemoryGuard = true; // MemoryGuard.h
	cfg.MemoryGuardScanDelay = 1;

	cfg.ThreadGuard = true; // ThreadGuard.h
	cfg.ThreadGuardDelay = 500;
	//cfg.HooksList.insert(std::pair<PVOID, PVOID>((PVOID)RetTest::TestStaticMethod, (PVOID)HookTestStaticMethod));
	// __thiscall methods must be casted in a different way

	cfg.IllegalDriverPatterns.insert(CortPair("ILLEGAL CERT: Nanjing Zhixiao Information Technology Co.,Ltd", 
		std::make_tuple(
			"\x4E\x61\x6E\x6A\x69\x6E\x67\x20\x5A\x68\x69\x78\x69\x61\x6F\x20\x49\x6E\x66\x6F\x72\x6D\x61\x74\x69\x6F\x6E\x20\x54\x65\x63\x68\x6E\x6F\x6C\x6F\x67\x79\x20\x43\x6F\x2E"s,
			"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"s)));
	cfg.IllegalDriverPatterns.insert(CortPair("HWIDSYS spoofer", std::make_tuple
	("\x61\x70\x70\x6C\x79\x5F\x68\x6F\x6F\x6B"s, "xxxxxxxxxx"s)));
	//todo cfg.PriorityDriverNames
	//////////////////////////////// Heuristical Scanning ///////////////////////////////////////////
	cfg.DetectPacking = true;
	cfg.AllowedPackedModules.push_back("netc.dll"); // white-list for your packed or protected dll`s
	cfg.DetectByString = true; 
	std::vector<std::string> Linien { "imgui", "minhook", "gamesnus", "rdror", "vsdbg", "Hybris", "hybris", "[P414]", "vk.com/hybrisoft" };
	cfg.IlegaleLinien = Linien; // Add deprecated string from hacks here!
	cfg.DetectBySignature = true; 
	cfg.IllegalPatterns.insert(CortPair("HWBP by NtKernelMC", 
	std::make_tuple("\x8D\x45\xF4\x64\xA3\x00\x00\x00\x00\x68"s, "xxxxxxxxxx"s)));
	/////////////////////////////////////////////////////////////////////////////////////////////////
	cfg.callback = (ArtemisCallback)ArthemidaCallback; 

	Utils::LogInFile(ARTEMIS_LOG, "[ARTEMIS-2] Configured and ready, press any key to load...\n"); 
	int whv = _getch(); std::thread heart([] { 
	for (;;) 
	{
		Sleep(3000); static bool first = false; if (!first) { first = true; printf("\n"); }
		// ZAEBALO FLUDIT BLYAT
		//printf("\n[HEART-BEAT] Console is working normally! Thread ID: %d | Press any key to stop.\n\n", GetCurrentThreadId());
	} });

	CArtemisReal* pArt = new CArtemisReal(&cfg, GetModuleHandleA(NULL));
	bool  bSuccess = pArt->InstallArtemisMonitor();
	if (bSuccess)
	{
		Utils::LogInFile(ARTEMIS_LOG, "[ARTEMIS-2] Succussfully obtained pointer to AntiCheat!\n");
		// test detection of illegal calls (return addresses checking)
		//RetTest::TestStaticMethod();
		//testObj.TestMemberMethod(); 
		 // For heuristic-scans on future & excluding false-positives in ProxyDLL detection.
	}
	else Utils::LogInFile(ARTEMIS_LOG, "[ARTEMIS-2] Failure on start :( Last error code: %d\n", GetLastError());
	while (true) 
	{
		Sleep(1000); 
		if (_getch()) 
		{ 
			#pragma warning(suppress: 6258)
			TerminateThread((HANDLE)heart.native_handle(), 0x0);
			#pragma warning(suppress: 6273)
			printf("[HEART-BEAT] Stopped. Thread id: %d | Heart-beat thread id: %d\n", GetCurrentThreadId(), heart.get_id()); 
		}
	}
	while (true) { Sleep(1000); }
	return 1;
}