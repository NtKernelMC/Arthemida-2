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
	case DetectionType::ART_PROXY_LIBRARY:
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK] Detected Proxy DLL! Base: 0x%X | DllName: %s\n\
		\r\r\rPath: %s\nSize: %d | Empty Version Info: %d\n",
		artemis->baseAddr, artemis->dllName.c_str(), artemis->dllPath.c_str(), 
		artemis->regionSize, (int)artemis->EmptyVersionInfo);
		break;
	case DetectionType::ART_FAKE_LAUNCHER:
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK] Detected fake launcher!\n");
		break;
	case DetectionType::ART_RETURN_ADDRESS:
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK] Detected Return to Hack Function! Address: 0x%X\n", artemis->baseAddr);
		break;
	case DetectionType::ART_MANUAL_MAP:
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK] Detected MMAP!\nBase: 0x%X | Size: 0x%X | Rights: 0x%X\n",
		artemis->baseAddr, artemis->regionSize, artemis->MemoryRights);
		break;
	case DetectionType::ART_MEMORY_CHANGED:
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK] Detected Illegal module!\nBase: 0x%X | Rights: 0x%X | Size: %d\n",
		artemis->baseAddr, artemis->MemoryRights, artemis->regionSize);
		break;
	case DetectionType::ART_SIGNATURE_DETECT:
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK] Detected Illegal module!\nBase: 0x%X | Rights: 0x%X | Size: %d\n",
		artemis->baseAddr, artemis->MemoryRights, artemis->regionSize);
		break;
	case DetectionType::ART_ILLEGAL_SERVICE:
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK] Detected Illegal service!\n");
		//"Path: %s | \nName: %s  | Description: %s | \nType: %d | BootSet: %s | Group: %s\n | Signed by: %s | Has Version Info: %d\n");
		break;
	default:
		Utils::LogInFile(ARTEMIS_LOG, "[CALLBACK] Unknown detection code! Base: 0x%X | DllName: %s\nPath: %s\nSize: %d | Empty Version Info: %d\n",
		artemis->baseAddr, artemis->dllName.c_str(), artemis->dllPath.c_str(), artemis->regionSize, (int)artemis->EmptyVersionInfo);
		break;
	}
	Utils::LogInFile(ARTEMIS_LOG, "\n\n");
}
class RetTest
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
}; RetTest testObj;
int main()
{
	SetConsoleCP(1251); SetConsoleOutputCP(1251);
	system("color 02"); SetConsoleTitleA("Arthemida-2 AntiCheat Lightweight Testing");
	printf("ConsoleHost main thread started! Thread ID: %d\n", GetCurrentThreadId());
	ArtemisConfig cfg; LoadLibraryA("version.dll");
	//cfg.DetectThreads = true; 
	//cfg.ThreadScanDelay = 1000;
	// For now - Module Scanner on improvments stage, found a better ways to figure out all problems per one-shot :)
	cfg.DetectModules = true; 
	cfg.ModuleScanDelay = 1000;
	
	//cfg.DetectManualMap = true; 
	//cfg.MemoryScanDelay = 1000; 

	//cfg.DetectMemoryPatch = true; 
	//cfg.MemoryGuardScanDelay = 1000;
	//cfg.HooksList.insert(std::pair<PVOID, PVOID>((PVOID)RetTest::TestStaticMethod, (PVOID)HookTestStaticMethod));
	// __thiscall methods must be casted in a different way
	
	//cfg.ServiceMon = true;
	//cfg.ServiceMonDelay = 1000;

	//cfg.DetectBySignature = true; cfg.PatternScanDelay = 1000; 
	//cfg.IllegalPatterns.insert(std::pair<std::string, std::tuple<const char*, const char*>>
	//(hack_name, std::make_tuple(pattern, mask))); // must be incapsulated

	//cfg.DetectFakeLaunch = true;
	cfg.callback = (ArtemisCallback)ArthemidaCallback; 

	Utils::LogInFile(ARTEMIS_LOG, "[ARTEMIS-2] Configured and ready, press any key to load...\n"); 
	int whv = _getch(); std::thread heart([] { 
	for (;;) 
	{
		Sleep(3000); static bool first = false; if (!first) { first = true; printf("\n"); }
		printf("\n[HEART-BEAT] Console is working normally! Thread ID: %d | Press any key to stop.\n\n", GetCurrentThreadId());
	} });

	IArtemisInterface* art = IArtemisInterface::InstallArtemisMonitor(&cfg);
	if (art)
	{
		Utils::LogInFile(ARTEMIS_LOG, "[ARTEMIS-2] Succussfully obtained pointer to AntiCheat!\n");
		// test detection of illegal calls (return addresses checking)
		//RetTest::TestStaticMethod();
		//testObj.TestMemberMethod(); 
		//LoadLibraryA("test.dll");
	}
	else Utils::LogInFile(ARTEMIS_LOG, "[ARTEMIS-2] Failure on start :( Last error code: %d\n", GetLastError());
	while (true) 
	{
		Sleep(1000); 
		if (_getch()) 
		{ 
			#pragma warning(suppress: 6258)
			TerminateThread((HANDLE)heart.native_handle(), 0x0); 
			printf("[HEART-BEAT] Stopped. Thread id: %d | Heart-beat thread id: %d\n", GetCurrentThreadId(), heart.get_id()); 
			break; 
		}
	}
	while (true) { Sleep(1000); }
	return 1;
}