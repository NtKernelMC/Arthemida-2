/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        core/CSetCursorPosHook.cpp
 *  PURPOSE:     Cursor position setting hook
 *
 *  Multi Theft Auto is available from http://www.multitheftauto.com/
 *
 *****************************************************************************/

#include "StdInc.h"
#include "detours/include/detours.h"

template <>
CSetCursorPosHook* CSingleton<CSetCursorPosHook>::m_pSingleton = NULL;

CSetCursorPosHook::CSetCursorPosHook()
{
    WriteDebugEvent("CSetCursorPosHook::CSetCursorPosHook");

    m_bCanCall = true;
    m_pfnSetCursorPos = NULL;
}

CSetCursorPosHook::~CSetCursorPosHook()
{
    WriteDebugEvent("CSetCursorPosHook::~CSetCursorPosHook");

    if (m_pfnSetCursorPos != NULL)
    {
        RemoveHook();
    }
}

void CSetCursorPosHook::ApplyHook()
{
    // Hook SetCursorPos
    PBYTE func = DetourFindFunction("User32.dll", "SetCursorPos");
    g_pCore->GetArtemis()->MemoryGuardBeginHook(func);
    m_pfnSetCursorPos =
        reinterpret_cast<pSetCursorPos>(DetourFunction(func, reinterpret_cast<PBYTE>(API_SetCursorPos)));
    g_pCore->GetArtemis()->MemoryGuardEndHook(func);
}

void CSetCursorPosHook::RemoveHook()
{
    // Remove hook
    if (m_pfnSetCursorPos)
    {
        g_pCore->GetArtemis()->MemoryGuardBeginHook(m_pfnSetCursorPos);
        DetourRemove(reinterpret_cast<PBYTE>(m_pfnSetCursorPos), reinterpret_cast<PBYTE>(API_SetCursorPos));
        g_pCore->GetArtemis()->MemoryGuardEndHook(m_pfnSetCursorPos);
    }

    // Reset variables
    m_pfnSetCursorPos = NULL;
    m_bCanCall = true;
}

void CSetCursorPosHook::DisableSetCursorPos()
{
    m_bCanCall = false;
}

void CSetCursorPosHook::EnableSetCursorPos()
{
    m_bCanCall = true;
}

bool CSetCursorPosHook::IsSetCursorPosEnabled()
{
    return m_bCanCall;
}

BOOL CSetCursorPosHook::CallSetCursorPos(int X, int Y)
{
    if (m_pfnSetCursorPos == NULL)
    {
        // We should never get here, but if we do, attempt to call
        // an imported SetCursorPos.
        return SetCursorPos(X, Y);
    }
    else
    {
        return m_pfnSetCursorPos(X, Y);
    }
}

BOOL WINAPI CSetCursorPosHook::API_SetCursorPos(int X, int Y)
{
    CSetCursorPosHook* pThis;

    // Get self-pointer.
    pThis = CSetCursorPosHook::GetSingletonPtr();

    // Check to see if this function should be called properly.
    if ((pThis->m_bCanCall) && (pThis->m_pfnSetCursorPos != NULL))
    {
        return pThis->m_pfnSetCursorPos(X, Y);
    }

    return FALSE;
}
