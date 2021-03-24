/*
    Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC & holmes0

	<TASK> TODO:
	Первый этап >>>
	+ Вырезан APC обработчик с гэйм-хуками, архитектура проекта переписана под API в ООП стиле на абстрактных классах.
	+ Переписан алгоритм определения запуска с fake-лаунчера на более надежный и стабильный
	- Модульный сканнер ныне определяет любые виды нелегальных типов динамических библиотек, загруженные посредством LoadLibrary/Ех/LdrLoadDLL. или же Ргоху-DLL`ки.
	- Обновление сигнатур в сканнере для поиска популярных GUI библиотек особо часто возлюбленными читоделами. (Активный поиск, циклическим режимом)
	- Пополнение списка гейм-хуков для защиты от новых разновидностей читов, включая функции которые могут поспособствовать инжекту клиентского Lua-кода или же скрипта. (ручные проверки в коде client.dll)
	- Защита против остановки потоков сканнеров античита или прерывания еще каких либо его потоков по любой причине, с автоматическим перезапуском.
	- Парсер активных сервисов любого вида без цифровых подписей с последующей остановкой службы 2-ого кольца или же драйвера-ядра/мини-фильтра на время игрового сеанса.
*/
#include ".../../../../Arthemida-2/API/ArtemisComponents.h"
using namespace ArtComponent;
ArtemisFiller::ArtemisFiller() 
{
#ifdef ARTEMIS_DEBUG
	Utils::LogInFile(ARTEMIS_LOG, "[ArtemisFiller] Called the third generation constructor!\n");
#endif
}
ArtemisFiller::~ArtemisFiller() 
{
#ifdef ARTEMIS_DEBUG
	Utils::LogInFile(ARTEMIS_LOG, "[ArtemisFiller] Called the third generation destructor!\n");
#endif
}
IArtemisInterface* IArtemisInterface::i_art = nullptr;
ArtemisConfig* IArtemisInterface::g_cfg = nullptr;
bool IArtemisInterface::WasReloaded = false;
IArtemisInterface* IArtemisInterface::CreateInstance(ArtemisConfig* cfg)
{
	if (cfg == nullptr) return nullptr;
	i_art = static_cast<IArtemisInterface*>(new ArtemisFiller());
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
#include "../../Arthemida-2/ArtModules/SigScanner.h"
#include "../../Arthemida-2/ArtModules/CServiceMon.h"
IArtemisInterface* __stdcall IArtemisInterface::InstallArtemisMonitor(ArtemisConfig* cfg)
{
#ifdef ARTEMIS_DEBUG
	if (!WasReloaded) DeleteFileA(ARTEMIS_LOG);
	else WasReloaded = false;
#endif
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
		HMODULE hPsapi = LoadLibraryA("psapi.dll"); // Загрузка нужной системной библиотеки для последующего получения из нее функции
		cfg->lpGetMappedFileNameA = (LPFN_GetMappedFileNameA)GetProcAddress(hPsapi, "GetMappedFileNameA"); // Получение функции GetMappedFileNameA из загруженной библиотеки (Таков необходим для совместимости на Win Vista & XP т.к там эта функция не хранится в экспортах другого модуля)
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