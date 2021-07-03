/*
	Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC & holmes0
*/
#pragma once
#include <Windows.h>
#include "ArtemisTypes.h"

using namespace ArtemisData;

class CArtemisInterface
{
public:
	virtual ArtemisConfig* GetConfig() = 0;
    virtual bool MemoryGuardBeginHook(void* pTarget) = 0;
    virtual bool MemoryGuardEndHook(void* pTarget) = 0;
};

class CArtemisReal : public CArtemisInterface
{
public:
    CArtemisReal(ArtemisConfig* cfg, HMODULE hCurrentModule);

    bool InstallArtemisMonitor();
    ArtemisConfig* GetConfig() { return m_pConfig; };
    static CArtemisReal* GetInstance() { return s_pInstance; }

    // Memory guard
    bool MemoryGuardBeginHook(void* pTarget);
    bool MemoryGuardEndHook(void* pTarget);

private:
    ArtemisConfig*     m_pConfig = nullptr;
    static CArtemisReal* s_pInstance;
};
