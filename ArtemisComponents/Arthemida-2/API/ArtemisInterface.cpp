/*
    Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC & holmes0
*/
#include "../ArtUtils/Utils.h"
#include "ArtemisInterface.h"
std::vector<HANDLE> ArtemisConfig::OwnThreads;
CArtemisReal* CArtemisReal::s_pInstance = nullptr;
CArtemisReal::CArtemisReal(ArtemisConfig* cfg, HMODULE hCurrentModule)
{
    m_pConfig = cfg;
	if (cfg != nullptr)
	{
		if (cfg->CurrProc == nullptr) cfg->CurrProc = GetCurrentProcess();
        if (cfg->hSelfModule == 0) cfg->hSelfModule = (HANDLE)hCurrentModule;
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

    s_pInstance = this;
}

/////////////////////////// Protection Modules //////////////////////////////////////////////////////////////
#include "../ArtModules/ArtThreading.h"
#include "../ArtModules/HeuristicScanner.h"
#include "../ArtModules/ThreadScanner.h"
#include "../ArtModules/AntiFakeLaunch.h"
#include "../ArtModules/ModuleScanner.h"
#include "../ArtModules/MemoryScanner.h"
#include "../ArtModules/MemoryGuard.h"
#include "../ArtModules/CServiceMon.h"
void tmp_servmon_stubfunc(CServiceMon* pServiceMon)
{
	pServiceMon->MonitorCycle();
}
bool CArtemisReal::InstallArtemisMonitor()
{
    printf("InstallArtemisMonitor CFG: 0x%08X\n", (DWORD)m_pConfig);
    if (m_pConfig == nullptr)
	{
#ifdef ARTEMIS_DEBUG
        Utils::LogInFile(ARTEMIS_LOG, "[ERROR] Invalid pointer in config argument! cfg: 0x%X\n", m_pConfig);
#endif
		return false;
	}
    if (m_pConfig->callback == nullptr)
	{
#ifdef ARTEMIS_DEBUG
		Utils::LogInFile(ARTEMIS_LOG, "[ERROR] Unknown address in callback argument! callback is nullptr.\n");
#endif
		return false;
	}
    Utils::BuildModuledMemoryMap(m_pConfig->CurrProc);            // Заполняем список изначально загруженными модулями
	DWORD tmpTID = 0xFFFFFF;
	if (m_pConfig->DetectFakeLaunch)            // Детект лаунчера (должен запускаться в первую очередь)
	{
        ConfirmLegitLaunch(m_pConfig);
	}
    if (m_pConfig->DetectThreads)            // Детект сторонних потоков
	{
        if (!m_pConfig->ThreadScanDelay)
            m_pConfig->ThreadScanDelay = 1000;
        if (!m_pConfig->ExcludedThreads.empty())
            m_pConfig->ExcludedThreads.clear(); 
		HANDLE hThreadScanner = ArtThreading::CreateProtectedThread(&ScanForDllThreads, m_pConfig);
        m_pConfig->OwnThreads.push_back(hThreadScanner);
	}
    if (m_pConfig->DetectModules)            // Детект сторонних модулей
	{
        if (!m_pConfig->ModuleScanDelay)
            m_pConfig->ModuleScanDelay = 1000;
        if (!m_pConfig->ExcludedModules.empty())
            m_pConfig->ExcludedModules.clear(); 
		ModuleScanner(m_pConfig);
	}
    if (m_pConfig->DetectManualMap)            // Детект мануал маппинга
	{
        if (!m_pConfig->MemoryScanDelay)
            m_pConfig->MemoryScanDelay = 1000;
        if (!m_pConfig->ExcludedImages.empty())
            m_pConfig->ExcludedImages.clear();
        HANDLE hMmapScanner = ArtThreading::CreateProtectedThread(&MemoryScanner, m_pConfig);            // Запуск асинхронного cканнера для поиска смапленных образов DLL-библиотек
        m_pConfig->OwnThreads.push_back(hMmapScanner);
	}
    if (m_pConfig->ServiceMon)            // on dev
	{
        if (!m_pConfig->ServiceMonDelay)
            m_pConfig->ServiceMonDelay = 1000;
		try
		{
            HANDLE hServmon = CServiceMon::GetInstance().Initialize(m_pConfig, &tmp_servmon_stubfunc);
            m_pConfig->OwnThreads.push_back(hServmon);
		} catch (std::exception e)
		{
#ifdef ARTEMIS_DEBUG
			printf("[CRITICAL] Service monitor launch failed! Message: %s\n", e.what());
#endif
		}
	}
    if (m_pConfig->MemoryGuard)
	{
        if (!m_pConfig->MemoryGuardScanDelay)
            m_pConfig->MemoryGuardScanDelay = 1000;
        HANDLE hMemoryGuard = ArtThreading::CreateProtectedThread(&MemoryGuardScanner, m_pConfig);
        m_pConfig->OwnThreads.push_back(hMemoryGuard);
	}
    if (m_pConfig->ThreadGuard)
	{
        if (!m_pConfig->ThreadGuardDelay)
            m_pConfig->ThreadGuardDelay = 1000;
        HANDLE hThreadGuard = ArtThreading::CreateProtectedThread(&ThreadGuard::ThreadScanner, m_pConfig);
        m_pConfig->OwnThreads.push_back(hThreadGuard);
	}
	return true;
}
