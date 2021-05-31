/*
    Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC & holmes0
*/
#include ".../../../../Arthemida-2/API/ArtemisComponents.h"
using namespace ArtComponent;
ArtemisIncapsulator::ArtemisIncapsulator(ArtemisConfig* cfg)
{
	if (cfg != nullptr)
	{
		if (cfg->CurrProc == nullptr) cfg->CurrProc = GetCurrentProcess();
#ifdef ARTEMIS_DEBUG
		Utils::LogInFile(ARTEMIS_LOG, "[SINGLETON] Called the second generation constructor!\n");
#endif
		if (!Utils::SetPrivilege(NULL, SE_DEBUG_NAME, TRUE))
		{
#ifdef ARTEMIS_DEBUG
			Utils::LogInFile(ARTEMIS_LOG, "[ERROR] Can`t set SE_DEBUG_NAME privilege.\n");
#endif
			return;
		}
		////////////////////////////////////////////////////////////////////////////////////////////////////////
		CheckIfFileProtected = (PtrIfFileProtected)Utils::RuntimeIatResolver("Sfc.dll", "SfcIsFileProtected");
		if (CheckIfFileProtected == nullptr)
		{
#ifdef ARTEMIS_DEBUG
			Utils::LogInFile(ARTEMIS_LOG, "[ERROR] Can`t obtain export from Sfc.dll for SfcIsFileProtected.\n");
#endif
			return;
		}
		lpGetMappedFileNameA = (LPFN_GetMappedFileNameA)Utils::RuntimeIatResolver("psapi.dll", "GetMappedFileNameA");
		if (lpGetMappedFileNameA == nullptr)
		{
#ifdef ARTEMIS_DEBUG
			Utils::LogInFile(ARTEMIS_LOG, "[ERROR] Can`t obtain export from psapi.dll for GetMappedFileNameA.\n");
#endif
			return;
		}
		GetMdlInfo = (GetMdlInfoP)Utils::RuntimeIatResolver("psapi.dll", "GetModuleInformation");
		if (GetMdlInfo == nullptr)
		{
#ifdef ARTEMIS_DEBUG
			Utils::LogInFile(ARTEMIS_LOG, "[ERROR] Can`t obtain export from psapi.dll for GetModuleInformation.\n");
#endif
			return;
		}
		EnumProcModules = (PtrEnumProcessModules)Utils::RuntimeIatResolver("psapi.dll", "EnumProcessModules");
		if (EnumProcModules == nullptr)
		{
#ifdef ARTEMIS_DEBUG
			Utils::LogInFile(ARTEMIS_LOG, "[ERROR] Can`t obtain export from psapi.dll for EnumProcModules.\n");
#endif
			return;
		}
		pNtQueryInformationThread = (tNtQueryInformationThread)Utils::RuntimeIatResolver("ntdll.dll","NtQueryInformationThread");
		if (pNtQueryInformationThread == nullptr)
		{
#ifdef ARTEMIS_DEBUG
			Utils::LogInFile(ARTEMIS_LOG, "[ERROR] Can`t obtain export from ntdll.dll for NtQueryInformationThread.\n");
#endif
			return;
		}
	    callLdrInitializeThunk = (PtrLdrInitializeThunk)Utils::RuntimeIatResolver("ntdll.dll", "LdrInitializeThunk");
		if (callLdrInitializeThunk == nullptr)
		{
#ifdef ARTEMIS_DEBUG
			Utils::LogInFile(ARTEMIS_LOG, "[ERROR] Can`t obtain export from ntdll.dll for LdrInitializeThunk.\n");
#endif
			return;
		}
		cfg->SingletonCalled = true; // First-stage step initialization
	}
	else
	{
#ifdef ARTEMIS_DEBUG
		Utils::LogInFile(ARTEMIS_LOG, "[ERROR] Invalid pointer in config argument! cfg: 0x%X\n", cfg);
#endif
	}
}
ArtemisIncapsulator::~ArtemisIncapsulator() { }
IArtemisInterface* IArtemisInterface::i_art = nullptr;
ArtemisConfig* IArtemisInterface::g_cfg = nullptr;
IArtemisInterface* IArtemisInterface::CreateInstance(ArtemisConfig* cfg)
{
	if (cfg == nullptr) return nullptr;
	i_art = dynamic_cast<IArtemisInterface*>(new ArtemisIncapsulator(cfg));
	if (i_art != nullptr)
	{
		i_art->g_cfg = new ArtemisConfig(); // Выделяем память под конфиг античита
		if (i_art->g_cfg == nullptr) return nullptr;
		memcpy(i_art->g_cfg, cfg, sizeof(ArtemisConfig)); // Копируем указатель конфига артемиды для связи с внешним миром =)
	}
	return i_art;
}
IArtemisInterface* __stdcall IArtemisInterface::GetInstance()
{
	if (i_art == nullptr) return nullptr;
	return i_art;
}
ArtemisConfig* __stdcall IArtemisInterface::GetConfig() 
{ 
	if (i_art == nullptr) return nullptr;
	if (i_art->g_cfg == nullptr) return nullptr;
	return i_art->g_cfg; 
}
/////////////////////////// Protection Modules //////////////////////////////////////////////////////////////
#include "../../Arthemida-2/ArtModules/ArtThreading.h"
#include "../../Arthemida-2/ArtModules/HeuristicScanner.h"
#include "../../Arthemida-2/ArtModules/ThreadScanner.h"
#include "../../Arthemida-2/ArtModules/AntiFakeLaunch.h"
#include "../../Arthemida-2/ArtModules/ModuleScanner.h"
#include "../../Arthemida-2/ArtModules/MemoryScanner.h"
#include "../../Arthemida-2/ArtModules/MemoryGuard.h"
#include "../../Arthemida-2/ArtModules/CServiceMon.h"
void tmp_servmon_stubfunc(CServiceMon* pServiceMon)
{
	pServiceMon->MonitorCycle();
}
IArtemisInterface* __stdcall IArtemisInterface::InstallArtemisMonitor(ArtemisConfig* cfg)
{
	if (cfg == nullptr)
	{
#ifdef ARTEMIS_DEBUG
		Utils::LogInFile(ARTEMIS_LOG, "[ERROR] Invalid pointer in config argument! cfg: 0x%X\n", cfg);
#endif
		return nullptr;
	}
	if (cfg->callback == nullptr)
	{
#ifdef ARTEMIS_DEBUG
		Utils::LogInFile(ARTEMIS_LOG, "[ERROR] Unknown address in callback argument! callback is nullptr.\n");
#endif
		return nullptr;
	}
	IArtemisInterface* ac_info = CreateInstance(cfg); // Создаем фабрику для объекта
	if (ac_info == nullptr)
	{
#ifdef ARTEMIS_DEBUG
		Utils::LogInFile(ARTEMIS_LOG, "[ERROR] Failed to allocate memory from heap. Last error: %d\n", GetLastError());
#endif
		return nullptr;
	}
	Utils::BuildModuledMemoryMap(cfg->CurrProc); // Заполняем список изначально загруженными модулями
	if (cfg->DetectFakeLaunch) // Детект лаунчера (должен запускаться в первую очередь)
	{
		ConfirmLegitLaunch(cfg);
	}
	if (cfg->DetectThreads) // Детект сторонних потоков
	{
		if (!cfg->ThreadScanDelay) cfg->ThreadScanDelay = 1000;
		if (!cfg->ExcludedThreads.empty()) cfg->ExcludedThreads.clear(); 
		HANDLE hThreadScanner = ArtThreading::CreateProtectedThread(&ScanForDllThreads, cfg);
		cfg->OwnThreads.push_back(hThreadScanner);
	}
	if (cfg->DetectModules) // Детект сторонних модулей
	{
		if (!cfg->ModuleScanDelay) cfg->ModuleScanDelay = 1000;
		if (!cfg->ExcludedModules.empty()) cfg->ExcludedModules.clear(); 
		HANDLE hProxyScanner = ArtThreading::CreateProtectedThread(&ModuleScanner, cfg); // Создание и запуск асинхронного потока сканера модулей процесса
		cfg->OwnThreads.push_back(hProxyScanner);
	}
	if (cfg->DetectManualMap) // Детект мануал маппинга
	{
		if (!cfg->MemoryScanDelay) cfg->MemoryScanDelay = 1000;
		if (!cfg->ExcludedImages.empty()) cfg->ExcludedImages.clear();
		HANDLE hMmapScanner = ArtThreading::CreateProtectedThread(&MemoryScanner, cfg); // Запуск асинхронного cканнера для поиска смапленных образов DLL-библиотек
		cfg->OwnThreads.push_back(hMmapScanner);
	}
	if (cfg->ServiceMon) // on dev
	{
		if (!cfg->ServiceMonDelay) cfg->ServiceMonDelay = 1000;
		CServiceMon* servmon = new CServiceMon; //! Утечка памяти, нужен контейнер для класса (статическая инициализация не подходит)
		HANDLE hServmon = servmon->Initialize(cfg, &tmp_servmon_stubfunc);
		cfg->OwnThreads.push_back(hServmon);
	}
	if (cfg->MemoryGuard)
	{
		if (!cfg->MemoryGuardScanDelay) cfg->MemoryGuardScanDelay = 1000;
		HANDLE hMemoryGuard = ArtThreading::CreateProtectedThread(&MemoryGuardScanner, cfg);
		cfg->OwnThreads.push_back(hMemoryGuard);
	}
	if (cfg->ThreadGuard)
	{
		if (!cfg->ThreadGuardDelay) cfg->ThreadGuardDelay = 1000;
		HANDLE hThreadGuard = ArtThreading::CreateProtectedThread(&ThreadGuard::ThreadScanner, cfg);
		cfg->OwnThreads.push_back(hThreadGuard);
	}
	return ac_info;
}