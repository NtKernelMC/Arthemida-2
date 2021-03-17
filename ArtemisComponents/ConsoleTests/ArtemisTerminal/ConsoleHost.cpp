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
	MessageBeep(MB_ICONASTERISK);
	if (artemis == nullptr)
	{
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK ERROR] Passed null pointer!\n");
		return;
	}
	switch (artemis->type)
	{
	case DetectionType::ART_ILLEGAL_THREAD:
		Utils::LogInFile(ARTEMIS_LOG, "Detected Anonymous thread! Base: 0x%X | Size: 0x%X\n",
		artemis->baseAddr, artemis->regionSize);
		break;
	case DetectionType::ART_ILLEGAL_MODULE:
		Utils::LogInFile(ARTEMIS_LOG, "Detected Illegal module! Base: 0x%X | DllName: %s | Path: %s | Size: %d\n",
		artemis->baseAddr, artemis->dllName.c_str(), artemis->dllPath.c_str(), artemis->regionSize);
		break;
	case DetectionType::ART_FAKE_LAUNCHER:
		Utils::LogInFile(ARTEMIS_LOG, "Detected fake launcher!\n");
		break;
	case DetectionType::ART_RETURN_ADDRESS:
		Utils::LogInFile(ARTEMIS_LOG, "Detected Return to Hack Function! Address: 0x%X\n", artemis->baseAddr);
		break;
	case DetectionType::ART_MANUAL_MAP:
		Utils::LogInFile(ARTEMIS_LOG, "Detected MMAP! Base: 0x%X | Size: 0x%X | Rights: 0x%X\n",
		artemis->baseAddr, artemis->regionSize, artemis->MemoryRights);
		break;
	case DetectionType::ART_MEMORY_CHANGED:
		Utils::LogInFile(ARTEMIS_LOG, "Detected Illegal module! Base: 0x%X | Rights: 0x%X | Size: %d\n",
		artemis->baseAddr, artemis->MemoryRights, artemis->regionSize);
		break;
	case DetectionType::ART_SIGNATURE_DETECT:
		Utils::LogInFile(ARTEMIS_LOG, "Detected Illegal module! Base: 0x%X | Rights: 0x%X | Size: %d\n",
		artemis->baseAddr, artemis->MemoryRights, artemis->regionSize);
		break;
	default:
		Utils::LogInFile(ARTEMIS_LOG, "Unknown detection code! Base: 0x%X | DllName: %s | Path: %s | Size: %d\n",
		artemis->baseAddr, artemis->dllName.c_str(), artemis->dllPath.c_str(), artemis->regionSize);
		break;
	}
}
int main()
{
	system("color 4F"); SetConsoleTitleA("Arthemida-2 AntiCheat Lightweight Testing");
	ArtemisConfig cfg; cfg.DetectThreads = true; cfg.ThreadScanDelay = 1000;
	cfg.DetectFakeLaunch = true; cfg.callback = (ArtemisCallback)ArthemidaCallback; 
	IArtemisInterface* art = IArtemisInterface::SwitchArtemisMonitor(&cfg, true);
	if (art)
	{
		printf("[ARTEMIS-2] Succussfully obtained pointer to AntiCheat!\n");
		printf("[DELAY] Gonna sleep few seconds before we unload...\n");
		Sleep(5000); if (art) art->ReleaseInstance();
		else
		{
			printf("[?!] For some reason, the pointer to Arthemida is invalid. Last Error Code: 0x%x\n", GetLastError());
			system("pause"); ExitProcess(0);
		}
		if (!art) printf("[ARTEMIS-2] AntiCheat was successfully unloaded! Memory is released.\n");
	}
	else printf("[ARTEMIS-2] Failure on start :( Last error code: %d\n", GetLastError());
	while (true) { Sleep(1000); }
	return 1;
}