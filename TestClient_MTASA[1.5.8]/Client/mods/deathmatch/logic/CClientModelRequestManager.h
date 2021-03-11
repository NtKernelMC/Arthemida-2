/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *               (Shared logic for modifications)
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        mods/shared_logic/CClientModelRequestManager.h
 *  PURPOSE:     Entity model streaming manager class
 *
 *****************************************************************************/

class CClientModelRequestManager;

#pragma once

#include "CClientCommon.h"
#include "CClientEntity.h"
#include <list>

struct SClientModelRequest
{
    CModelInfo*    pModel;
    CClientEntity* pEntity;
    CElapsedTime   requestTimer;
};

class CClientModelRequestManager
{
    friend class CClientManager;

public:
    CClientModelRequestManager();
    ~CClientModelRequestManager();

    bool        IsLoaded(unsigned short usModelID);
    bool        IsRequested(CModelInfo* pModelInfo);
    bool        HasRequested(CClientEntity* pRequester);
    CModelInfo* GetRequestedModelInfo(CClientEntity* pRequester);

    bool RequestBlocking(unsigned short usModelID, const char* szTag);

    bool Request(unsigned short usModelID, CClientEntity* pRequester);
    void Cancel(CClientEntity* pRequester, bool bAllowQueue);

private:
    void DoPulse();
    bool GetRequestEntry(CClientEntity* pRequester, std::list<SClientModelRequest*>::iterator& iter);

    bool                            m_bDoingPulse;
    std::list<SClientModelRequest*> m_Requests;
    std::list<CClientEntity*>       m_CancelQueue;
};
