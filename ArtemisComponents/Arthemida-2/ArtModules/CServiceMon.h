/*
    Artemis-2 for MTA Province
    Target Platform: x32-x86
    Project by NtKernelMC
*/
#pragma once
#ifndef CSERVICEMON_H
#define CSERVICEMON_H
// CAUTION! Still remaining on development.
#include <Windows.h>
#include <thread>
#include <string>
#include <map>
#include <vector>

class CServiceMon
{
public:
    struct SServiceInfo
    {
        std::wstring            wsFilePath = L"";;
        std::wstring            wsDisplayName = L"";
        bool                    EmptyVersionInfo = true;
        SERVICE_STATUS_PROCESS  sspStatus { 0 };
    };
    std::thread Initialize();
    std::multimap<std::wstring, SServiceInfo> GetAllServices();
private:
    void MonitorCycle();
    SC_HANDLE m_hSCManager;
};

void CServiceMon::MonitorCycle()
{
#ifdef ARTEMIS_DEBUG
    Utils::LogInFile(ARTEMIS_LOG, 
    "[INFO] Created async thread for CServiceMon::MonitorCycle! Thread id: %d\n", GetCurrentThreadId());
#endif
    static bool RUN = false; // ! DEBUG - ONE TIME RUN
    std::multimap<std::wstring, SServiceInfo> mmServices;
    while (true)
    {
        if (RUN) break;
        try
        {
            mmServices = std::move(GetAllServices());
        } catch (std::exception e)
        {
            printf("GetAllServices threw exception: %s\nLast error: %d\nMonitor interrupted.\n", e.what(), GetLastError());
            break;
        }

        for (const auto& x : mmServices)
        {
            wprintf(L"Name: %s | Path: %s\n", x.first.c_str(), x.second.wsFilePath.c_str());
        }

        RUN = true; // ! DEBUG - ONE TIME RUN
    }
}

std::thread CServiceMon::Initialize()
{
    m_hSCManager = OpenSCManagerW(NULL, SERVICES_ACTIVE_DATABASEW, SC_MANAGER_ENUMERATE_SERVICE);
    if (!m_hSCManager) throw std::exception("OpenSCManagerW failed.");
    return std::thread(&CServiceMon::MonitorCycle, this);
}

std::multimap<std::wstring, CServiceMon::SServiceInfo> CServiceMon::GetAllServices()
{
    DWORD dwBytesNeeded = 0, dwServiceCount = 0, dwResumeHandle = 0;
    std::multimap<std::wstring, SServiceInfo> mmServicesResult;
    BOOL enm = EnumServicesStatusExW(m_hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_KERNEL_DRIVER,
    SERVICE_STATE_ALL, NULL, 0, &dwBytesNeeded, &dwServiceCount, &dwResumeHandle, NULL);
    if (!enm || GetLastError() == ERROR_MORE_DATA)
    {
        std::vector<unsigned char> buffer(dwBytesNeeded, 0);
        if (EnumServicesStatusExW(m_hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_KERNEL_DRIVER, SERVICE_STATE_ALL,
        reinterpret_cast<LPBYTE>(buffer.data()), dwBytesNeeded, &dwBytesNeeded, &dwServiceCount, 0, 0))
        {
            printf("Service count: %d\n", dwServiceCount);
            LPENUM_SERVICE_STATUS_PROCESSW eSSP = reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESSW>(buffer.data());
            for (DWORD i = 0; i < dwServiceCount; i++)
            {
                SServiceInfo SSP; if (eSSP == nullptr) continue;
                SSP.wsDisplayName = eSSP[i].lpDisplayName;
                SSP.sspStatus = eSSP[i].ServiceStatusProcess;
                // get path
                DWORD dwConfigBytesNeeded = 0x0, cbBufSize = 0x0;
                LPQUERY_SERVICE_CONFIGW lpSC = nullptr;
                SC_HANDLE hService = OpenServiceW(m_hSCManager, eSSP[i].lpServiceName, SERVICE_QUERY_CONFIG);
                if (!hService)
                {
                    printf("[SKIP] OpenService FAILED! Iteration: %d | Service: %wS\n", i, eSSP[i].lpDisplayName);
                    continue;
                }
                if (!QueryServiceConfigW(hService, NULL, 0, &dwConfigBytesNeeded)) continue;
                if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
                {
                    cbBufSize = dwConfigBytesNeeded;
                    lpSC = (LPQUERY_SERVICE_CONFIGW)LocalAlloc(LMEM_FIXED, cbBufSize);
                    if (lpSC == nullptr) continue;
                }
                else
                {
                    printf("[SKIP] QueryServiceConfig FAILED 1! Iteration: %d | Service: %wS\n", i, eSSP[i].lpDisplayName);
                    continue;
                }
                if (!QueryServiceConfigW(hService, lpSC, cbBufSize, &dwConfigBytesNeeded))
                {
                    printf("[SKIP] QueryServiceConfig FAILED 2! Iteration: %d | Service: %wS\n", i, eSSP[i].lpDisplayName);
                    continue;
                }
                if (lpSC != nullptr)
                {
                    SSP.wsFilePath = lpSC->lpBinaryPathName;
                    LocalFree(lpSC);
                    mmServicesResult.insert({ eSSP[i].lpServiceName, SSP });
                }
            }
        }
        else throw std::exception("EnumServicesStatusExW failed 2.");
    }
    else throw std::exception("EnumServicesStatusExW failed 1.");
    return mmServicesResult;
}
#endif