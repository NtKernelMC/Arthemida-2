/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        mods/deathmatch/logic/CServer.h
 *  PURPOSE:     Header for server class
 *
 *  Multi Theft Auto is available from http://www.multitheftauto.com/
 *
 *****************************************************************************/

#pragma once

#include "CDynamicLibrary.h"
#include <list>
#include <string>

class CServer
{
public:
    CServer();
    ~CServer();

    void DoPulse();

    bool Start(const char* szConfig);
    bool Stop();
    bool IsStarted();
    bool IsRunning() { return m_pLibrary != NULL; };
    bool IsReady() { return m_bIsReady; };

    int GetLastError() { return m_iLastError; };

    bool Send(const char* szString);

    const std::string& GetPassword() { return m_strPassword; };
    void               SetPassword(const char* szPassword) { m_strPassword = szPassword; };

private:
    static DWORD WINAPI Thread_EntryPoint(LPVOID pThis);
    unsigned long       Thread_Run();

    bool   m_bIsReady;
    HANDLE m_hThread;
    CDynamicLibrary* volatile m_pLibrary;
    CCriticalSection m_CriticalSection;
    SString          m_strServerRoot;
    SString          m_strDLLFile;
    SString          m_strConfig;

    int m_iLastError;

    std::string m_strPassword;

    static CCriticalSection       m_OutputCC;
    static std::list<std::string> m_OutputQueue;

    static void AddServerOutput(const char* szOutput);
};
