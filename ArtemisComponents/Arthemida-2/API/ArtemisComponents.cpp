/*
    Artemis-2 for MTA Province
	Target Platform: x32-x86 (Wow64)
	Project by NtKernelMC & holmes0

	<TASK> TODO:
	Первый этап >>>
	+ Вырезан APC обработчик с гэйм-хуками, архитектура проекта переписана под API в ООП стиле на абстрактных классах.
	- Модульный сканнер ныне определяет любые виды нелегальных типов динамических библиотек, загруженные посредством LoadLibrary/Ех/LdrLoadDLL. или же Ргоху-DLL`ки.
	- Обновление сигнатур в сканнере для поиска популярных GUI библиотек особо часто возлюбленными читоделами. (Активный поиск, циклическим режимом)
	- Пополнение списка гейм-хуков для защиты от новых разновидностей читов, включая функции которые могут поспособствовать инжекту клиентского Lua-кода или же скрипта. (ручные проверки в коде client.dll)
	- Защита против остановки потоков сканнеров античита или прерывания еще каких либо его потоков по любой причине, с автоматическим перезапуском.
	- Парсер активных сервисов любого вида без цифровых подписей с последующей остановкой службы 2-ого кольца или же драйвера-ядра/мини-фильтра на время игрового сеанса.

	-- Внеплановая работа
	> Переписать детект запуска с фейк лаунчера либо починить имеющийся (не работает из-за старого бага!)
	> Допереносить в API на новую архитектуру остальные модули и сходу обрезать все лишнее со старой версии
	> Допилить режим безопасного отключения античита с остановкой всех потоков сканнеров
	> Защитить контролирующие API функции античита от выключения защиты через вызов в памяти
	> Улучшить сканнер аномальных потоков через хук в нтдлл на BaseThreadInitThunk (Не профукает запуск любого потока)
	> Заменить сканнер сигнатур либо модернизировать текущий для безопасного траверса памяти, как модулей так и VAD`ов
	> Провести более глубокую инкапсуляцию работы API и упростить эксплуатацию с помощью выборочной автоматизации настроек
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
void ArtemisFiller::ReleaseInstance() 
{ 
#ifdef ARTEMIS_DEBUG
	Utils::LogInFile(ARTEMIS_LOG, "[ReleaseInstance] Processing unloading routine...\n");
#endif
	delete this; 
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
IArtemisInterface* IArtemisInterface::GetInstance() { return i_art; }
/////////////////////////// Protection Modules //////////////////////////////////////////////////////////////
#include "../../Arthemida-2/ArtModules/ThreadScanner.h"
#include "../../Arthemida-2/ArtModules/AntiFakeLaunch.h"
IArtemisInterface* __stdcall IArtemisInterface::SwitchArtemisMonitor(ArtemisConfig* cfg, bool selector)
{
#ifdef ARTEMIS_DEBUG
	if (!WasReloaded) DeleteFileA(ARTEMIS_LOG);
	else WasReloaded = false;
	Utils::LogInFile(ARTEMIS_LOG, "[Artemis-2] AntiCheat -> Switch command on: %d\n", (BYTE)selector);
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
		//std::thread AsyncScanner(&ModuleScanner, cfg);
		//AsyncScanner.detach(); // Создание и запуск асинхронного потока сканера модулей процесса
	}
	if (cfg->DetectManualMap) // Детект мануал маппинга
	{
		if (!cfg->MemoryScanDelay) cfg->MemoryScanDelay = 1000;
		//std::thread MmapThread(&MemoryScanner, cfg);
		//MmapThread.detach(); // Запуск асинхронного cканнера для поиска смапленных образов DLL-библиотек
	}
	if (cfg->DetectPatterns)
	{
		if (!cfg->PatternScanDelay) cfg->PatternScanDelay = 1000;
		//std::thread SignatureThread(&SigScanner, cfg);
		//SignatureThread.detach();
	}
	return ac_info;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
// Метод отключения античита (жизненно необходим для его перезапуска)
bool DisableArthemidaAC(ART_LIB::ArtemisLibrary::ArtemisConfig* cfg)
{
	if (GameHooks::DeleteGameHooks()) // Снимает и игровые хуки и APC диспетчер!
	{
#ifdef ARTEMIS_DEBUG
		if (!WasReloaded) Utils::LogInFile(ARTEMIS_LOG, "Artemis-2 AntiCheat unloaded.\n");
		else Utils::LogInFile(ARTEMIS_LOG, "Reloading Artemis-2 AntiCheat...\n");
#endif
		return true;
	}
	return false;
}

// Метод для удобного перезапуска античита
ART_LIB::ArtemisLibrary* __cdecl ReloadArtemis2(ART_LIB::ArtemisLibrary::ArtemisConfig* cfg)
{
	if (cfg == nullptr) return nullptr; 
	WasReloaded = true;
	if (DisableArtemis())
	{
		ART_LIB::ArtemisLibrary* art_lib = alInitializeArtemis(cfg);
		return art_lib; // Возращаем указатель на оригинал содержащий настройки античита
	}
	return nullptr; // Возращаем нулевой указатель если не удалось безопасно перезапустить античит
}
*/