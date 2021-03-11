/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *               (Shared logic for modifications)
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        mods/shared_logic/CClientDummy.cpp
 *  PURPOSE:     Dummy entity class
 *
 *****************************************************************************/

#include "StdInc.h"

CClientDummy::CClientDummy(CClientManager* pManager, ElementID ID, const char* szTypeName) : ClassInit(this), CClientEntity(ID)
{
    SetTypeName(szTypeName);

    m_pManager = pManager;
    if (pManager)
    {
        m_pGroups = pManager->GetGroups();

        if (m_pGroups)
        {
            m_pGroups->AddToList(this);
        }
    }
    else
    {
        m_pGroups = NULL;
    }
}

CClientDummy::~CClientDummy()
{
    Unlink();
}

void CClientDummy::Unlink()
{
    if (m_pGroups)
    {
        m_pGroups->RemoveFromList(this);
    }
}
