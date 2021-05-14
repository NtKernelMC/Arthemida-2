/*
    Artemis-2 for MTA Province
    Target Platform: x32-x86
    Project by NtKernelMC & holmes0
*/

/**
* Assignee: holmes0
* Done: Service parser
*       Native path handler
*       Buffered file pattern scanner
*       Failure handling
* 
* In progress:
*       Optimization: prevent rescanning by keeping fast hash table of files
*       Enhancement: grant services scanning priority by known names
*       Enhancement: analyze digital signatures of files
*/
#pragma once
#ifndef CSERVICEMON_H
#define CSERVICEMON_H

#include <Windows.h>
#include <thread>
#include <string>
#include <map>
#include <vector>
//#include "..\ArtUtils\Utils.h"

class CServiceMon
{
public:
    struct SServiceInfo
    {
        std::wstring            wsFilePath = L"";
        std::wstring            wsDisplayName = L"";
        bool                    EmptyVersionInfo = true;
        SERVICE_STATUS_PROCESS  sspStatus { 0 };
    };
    std::thread Initialize(ArtemisConfig* cfg);
    std::multimap<std::wstring, SServiceInfo> GetAllServices();
private:
    void MonitorCycle();
    SC_HANDLE m_hSCManager;

    ArtemisConfig* m_pArtConfig;

    typedef NTSTATUS(__stdcall* pNtCreateFile)(
        PHANDLE              FileHandle,
        ACCESS_MASK          DesiredAccess,
        POBJECT_ATTRIBUTES   ObjectAttributes,
        PIO_STATUS_BLOCK     IoStatusBlock,
        PLARGE_INTEGER       AllocationSize,
        ULONG                FileAttributes,
        ULONG                ShareAccess,
        ULONG                CreateDisposition,
        ULONG                CreateOptions,
        PVOID                EaBuffer,
        ULONG                EaLength);
    
    pNtCreateFile m_pNtCreateFile;
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
        
        for (auto& sc : mmServices)
        {
            std::wstring wstrSub = sc.second.wsFilePath.substr(0, 8);
            if (Utils::w_findStringIC(wstrSub, L"System32") || Utils::w_findStringIC(wstrSub, L"SysWOW64"))
            {
                sc.second.wsFilePath.insert(0, L"\\SystemRoot\\");
            }

            HANDLE hFile = 0;
            UNICODE_STRING uszFileName;
            uszFileName.Length = (USHORT)(sc.second.wsFilePath.size() * sizeof(wchar_t));
            uszFileName.MaximumLength = (USHORT)(sc.second.wsFilePath.size() * sizeof(wchar_t) + sizeof(UNICODE_NULL));
            uszFileName.Buffer = (PWCHAR)(sc.second.wsFilePath.c_str());

            OBJECT_ATTRIBUTES objectAttributes;
            InitializeObjectAttributes(&objectAttributes, &uszFileName, OBJ_CASE_INSENSITIVE, 0, 0);
            IO_STATUS_BLOCK ioStatusBlock;
            NTSTATUS ntStatus = m_pNtCreateFile(&hFile, FILE_READ_DATA | SYNCHRONIZE, &objectAttributes, &ioStatusBlock, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
            if (ntStatus != 0)
            {
                continue;
            }

            LARGE_INTEGER liSize;
            GetFileSizeEx(hFile, &liSize);
            if (liSize.QuadPart > (1024 * 1024 * 1024)) // 1 GB
            {
                wprintf(L"\nName: %s | Path: %s\n", sc.first.c_str(), sc.second.wsFilePath.c_str());
                printf("File size exceeds 1GB, skipping in favor of speed\n");
                CloseHandle(hFile);
                continue;
            }
            
            SigScan::FileScanResult fileScanResult;
            for (auto& x : m_pArtConfig->IllegalDriverPatterns)
            {
                //wprintf(L"Scanning %s for ", sc.first.c_str());
                //printf("%s\n", x.first.c_str());

                fileScanResult = SigScan::FindPatternFileWin(hFile, std::get<0>(x.second).c_str(), std::get<1>(x.second).c_str());
                if (fileScanResult == SigScan::FSCAN_STATUS_FAIL)
                {
                    //wprintf(L"\nName: %s | Path: %s\n", sc.first.c_str(), sc.second.wsFilePath.c_str());
                    //printf("File scan failed\n");
                    CloseHandle(hFile);
                    break;
                }
                else if (fileScanResult == SigScan::FSCAN_STATUS_FOUND)
                {
                    ARTEMIS_DATA artDetectData;
                    artDetectData.type = DetectionType::ART_ILLEGAL_SERVICE;
                    artDetectData.HackName = x.first;
                    artDetectData.filePath = Utils::CvWideToAnsi(sc.second.wsFilePath);
                    m_pArtConfig->callback(&artDetectData);
                }
            }

            CloseHandle(hFile);
        }

        RUN = true; // ! DEBUG - ONE TIME RUN
    }
}

std::thread CServiceMon::Initialize(ArtemisConfig* cfg)
{
    m_hSCManager = OpenSCManagerW(NULL, SERVICES_ACTIVE_DATABASEW, SC_MANAGER_ENUMERATE_SERVICE);
    if (!m_hSCManager) throw std::exception("OpenSCManagerW failed.");

    m_pNtCreateFile = (pNtCreateFile)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateFile");
    if (m_pNtCreateFile == nullptr) throw std::exception("Failed to obtain NtCreateFile address.");

    m_pArtConfig = cfg;

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
                DWORD dwConfigBytesNeeded = 0x0;
                QUERY_SERVICE_CONFIGW* lpSC = nullptr;
                
                SC_HANDLE hService = OpenServiceW(m_hSCManager, eSSP[i].lpServiceName, SERVICE_QUERY_CONFIG);
                if (!hService)
                {
                    printf("[SKIP] OpenService FAILED! Iteration: %d | Service: %wS\n", i, eSSP[i].lpDisplayName);
                    continue;
                }
                
                QueryServiceConfigW(hService, NULL, 0, &dwConfigBytesNeeded);
                if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) continue;
                
                try { 
                    lpSC = (QUERY_SERVICE_CONFIGW*)new unsigned char[dwConfigBytesNeeded]; 
                } catch (std::bad_alloc e) {
                    printf("[SKIP] Bad alloc exception! Requested size: %d | Iteration: %d | Service: %wS\nMessage: %s\n", dwConfigBytesNeeded, i, eSSP[i].lpDisplayName, e.what()); 
                    continue;
                }

                if (!QueryServiceConfigW(hService, lpSC, dwConfigBytesNeeded, &dwConfigBytesNeeded))
                {
                    printf("[SKIP] QueryServiceConfig FAILED 2! Iteration: %d | Service: %wS\n", i, eSSP[i].lpDisplayName);
                    delete[] lpSC;
                    continue;
                }
                
                SSP.wsFilePath.reserve(wcslen(lpSC->lpBinaryPathName) + 12); // +12 - ������ ��� ����� ������������ ������������� \SystemRoot\ � ������, ����� �� ������� ������� �� ����������� � ����������� � �������
                SSP.wsFilePath = lpSC->lpBinaryPathName;
                delete[] lpSC;
                mmServicesResult.insert({ eSSP[i].lpServiceName, SSP });
            }
        }
        else throw std::exception("EnumServicesStatusExW failed 2.");
    }
    else throw std::exception("EnumServicesStatusExW failed 1.");
    return mmServicesResult;
}
#endif