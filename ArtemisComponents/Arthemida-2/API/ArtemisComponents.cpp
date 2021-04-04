/*
    Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC & holmes0
*/
#include ".../../../../Arthemida-2/API/ArtemisComponents.h"
using namespace ArtComponent;
ArtemisIncapsulator::ArtemisIncapsulator()
{
#ifdef ARTEMIS_DEBUG
	Utils::LogInFile(ARTEMIS_LOG, "[ArtemisIncapsulator] Called the second generation constructor!\n");
#endif
}
ArtemisIncapsulator::~ArtemisIncapsulator()
{
#ifdef ARTEMIS_DEBUG
	Utils::LogInFile(ARTEMIS_LOG, "[ArtemisIncapsulator] Called the second generation destructor!\n");
#endif
}
IArtemisInterface* IArtemisInterface::i_art = nullptr;
ArtemisConfig* IArtemisInterface::g_cfg = nullptr;
IArtemisInterface* IArtemisInterface::CreateInstance(ArtemisConfig* cfg)
{
	if (cfg == nullptr) return nullptr;
	i_art = dynamic_cast<IArtemisInterface*>(new ArtemisIncapsulator());
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
#include "../../Arthemida-2/ArtModules/ThreadScanner.h"
#include "../../Arthemida-2/ArtModules/AntiFakeLaunch.h"
#include "../../Arthemida-2/ArtModules/ModuleScanner.h"
#include "../../Arthemida-2/ArtModules/MemoryScanner.h"
#include "../../Arthemida-2/ArtModules/MemoryGuard.h"
#include "../../Arthemida-2/ArtModules/HeuristicScanner.h"
#include "../../Arthemida-2/ArtModules/CServiceMon.h"
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
	typedef DWORD(__stdcall* LPFN_GetMappedFileNameA)(HANDLE hProcess, LPVOID lpv, LPCSTR lpFilename, DWORD nSize);
	cfg->lpGetMappedFileNameA = (LPFN_GetMappedFileNameA)GetProcAddress(LoadLibraryA("psapi.dll"), "GetMappedFileNameA");
	if (cfg->lpGetMappedFileNameA == nullptr)
	{
#ifdef ARTEMIS_DEBUG
		Utils::LogInFile(ARTEMIS_LOG, "[ERROR] Can`t obtain export from psapi.dll for GetMappedFileNameA.\n");
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
	if (cfg->DetectFakeLaunch) // Детект лаунчера (должен запускаться в первую очередь)
	{
		ConfirmLegitLaunch(cfg);
	}
	if (cfg->DetectThreads) // Детект сторонних потоков
	{
		if (!cfg->ThreadScanDelay) cfg->ThreadScanDelay = 1000;
		if (!cfg->ExcludedThreads.empty()) cfg->ExcludedThreads.clear(); // [Не настраивается юзером] Очистка на случай повторной инициализации с тем же cfg
		std::thread AsyncScanner(ScanForDllThreads, cfg);
		AsyncScanner.detach(); // Запуск асинхронного cканера безымянных потоков которые используются читерами для обхода детекта мануал мап сканнера
	}
	if (cfg->DetectModules) // Детект сторонних модулей
	{
		if (!cfg->ModuleScanDelay) cfg->ModuleScanDelay = 1000;
		if (!cfg->ExcludedModules.empty()) cfg->ExcludedModules.clear(); // [Не настраивается юзером] Очистка на случай повторной инициализации с тем же cfg
		std::thread AsyncScanner(ModuleScanner, cfg);
		AsyncScanner.detach(); // Создание и запуск асинхронного потока сканера модулей процесса
	}
	if (cfg->DetectManualMap) // Детект мануал маппинга
	{
		if (!cfg->MemoryScanDelay) cfg->MemoryScanDelay = 1000;
		if (!cfg->ExcludedImages.empty()) cfg->ExcludedImages.clear();
		std::thread MmapThread(MemoryScanner, cfg);
		MmapThread.detach(); // Запуск асинхронного cканнера для поиска смапленных образов DLL-библиотек
	}
	if (cfg->DetectMemoryPatch) // запускаем наш сканнер детектов по адресу возврата с защитой памяти от модификаций
	{
		if (!cfg->HooksList.empty()) cfg->HooksList.clear();
		if (!cfg->MemoryGuardScanDelay) cfg->MemoryGuardScanDelay = 1000;
		std::thread MemThread(MemoryGuardScanner, cfg);
		MemThread.detach();
	}
	if (cfg->DetectBySignature) // скан на сигнатуры читов
	{
		if (!cfg->ExcludedSigAddresses.empty()) cfg->ExcludedSigAddresses.clear();
		if (!cfg->PatternScanDelay) cfg->PatternScanDelay = 1000;
		std::thread SignatureThread(SigScanner, cfg);
		SignatureThread.detach();
	}
	if (cfg->ServiceMon)
	{
		if (!cfg->ServiceMonDelay) cfg->ServiceMonDelay = 1000;
		CServiceMon servmon;
		servmon.Initialize().detach();
	}
	return ac_info;
}