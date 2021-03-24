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
#include ".../../../../Arthemida-2/API/ArtemisInterface.h"
using namespace std;
using namespace ArtemisData;
using namespace ARTEMIS_INTERFACE;
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
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK] Detected Anonymous thread! Base: 0x%X | Size: 0x%X\n",
		artemis->baseAddr, artemis->regionSize);
		break;
	case DetectionType::ART_ILLEGAL_MODULE:
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK] Detected Illegal module! Base: 0x%X | DllName: %s | Path: %s | Size: %d\n",
		artemis->baseAddr, artemis->dllName.c_str(), artemis->dllPath.c_str(), artemis->regionSize);
		break;
	case DetectionType::ART_FAKE_LAUNCHER:
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK] Detected fake launcher!\n");
		break;
	case DetectionType::ART_RETURN_ADDRESS:
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK] Detected Return to Hack Function! Address: 0x%X\n", artemis->baseAddr);
		break;
	case DetectionType::ART_MANUAL_MAP:
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK] Detected MMAP! Base: 0x%X | Size: 0x%X | Rights: 0x%X\n",
		artemis->baseAddr, artemis->regionSize, artemis->MemoryRights);
		break;
	case DetectionType::ART_MEMORY_CHANGED:
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK] Detected Illegal module! Base: 0x%X | Rights: 0x%X | Size: %d\n",
		artemis->baseAddr, artemis->MemoryRights, artemis->regionSize);
		break;
	case DetectionType::ART_SIGNATURE_DETECT:
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK] Detected Illegal module! Base: 0x%X | Rights: 0x%X | Size: %d\n",
		artemis->baseAddr, artemis->MemoryRights, artemis->regionSize);
		break;
	case DetectionType::ART_ILLEGAL_SERVICE:
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK] Detected Illegal service!\n");
		//"Path: %s | Name: %s  | Description: %s | Type: %d | BootSet: %s | Group: %s | Signed by: %s\n");
		break;
	default:
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK] Unknown detection code! Base: 0x%X | DllName: %s | Path: %s | Size: %d\n",
		artemis->baseAddr, artemis->dllName.c_str(), artemis->dllPath.c_str(), artemis->regionSize);
		break;
	}
	Utils::LogInFile(ARTEMIS_LOG, "\n\n");
}
int main()
{
	system("color 02"); SetConsoleTitleA("Arthemida-2 AntiCheat Lightweight Testing");

	ArtemisConfig cfg;
	cfg.DetectThreads = true; 
	cfg.ThreadScanDelay = 1000;
	
	cfg.DetectModules = true; 
	cfg.ModuleScanDelay = 1000;
	
	cfg.DetectManualMap = true; 
	cfg.MemoryScanDelay = 1000; 
	
	cfg.ServiceMon = true;
	cfg.ServiceMonDelay = 1000;

	//cfg.DetectMemoryPatch = true; cfg.HooksList.insert(std::pair<PVOID, PVOID>(dest, hook)); // -> FOR MTA CLIENT
	
	//cfg.DetectBySignature = true; cfg.PatternScanDelay = 1000; 
	//cfg.IllegalPatterns.insert(std::pair<std::string, std::tuple<const char*, const char*>>
	//(hack_name, std::make_tuple(pattern, mask)));

	cfg.DetectFakeLaunch = true;
	cfg.callback = (ArtemisCallback)ArthemidaCallback; 

	printf("[ARTEMIS-2] Configured and ready, press any key to load...\n"); _getch();
	std::thread heart([] { for (;;) {
		Sleep(3000); static bool first = false; if (!first) { first = true; printf("\n"); }
		printf("\n[HEART-BEAT] Console is working normally! Press any key to stop.\n\n");
	} });

	IArtemisInterface* art = IArtemisInterface::InstallArtemisMonitor(&cfg);
	if (art) printf("[ARTEMIS-2] Succussfully obtained pointer to AntiCheat!\n");
	else printf("[ARTEMIS-2] Failure on start :( Last error code: %d\n", GetLastError());
	while (true) 
	{
		Sleep(1000); 
		if (_getch()) { TerminateThread((HANDLE)heart.native_handle(), 0x0); printf("[HEART-BEAT] Stopped.\n"); }
	}
	return 1;
}