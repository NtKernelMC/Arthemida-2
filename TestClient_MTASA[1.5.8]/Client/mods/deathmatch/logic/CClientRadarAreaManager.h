/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *               (Shared logic for modifications)
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        mods/shared_logic/CClientRadarAreaManager.h
 *  PURPOSE:     Radar area entity manager class header
 *
 *****************************************************************************/

#pragma once

#include "CClientRadarArea.h"
#include <list>

class CClientRadarAreaManager
{
    friend class CClientManager;
    friend class CClientRadarArea;
    friend class CClientGame;

public:
    CClientRadarAreaManager(CClientManager* pManager);
    ~CClientRadarAreaManager();

    CClientRadarArea* Create(ElementID ID);

    void Delete(CClientRadarArea* pRadarArea);
    void DeleteAll();

    std::list<CClientRadarArea*>::const_iterator IterBegin() { return m_List.begin(); };
    std::list<CClientRadarArea*>::const_iterator IterEnd() { return m_List.end(); };

    static CClientRadarArea* Get(ElementID ID);

    unsigned short GetDimension() { return m_usDimension; };
    void           SetDimension(unsigned short usDimension);

private:
    void DoPulse();
    void DoPulse(bool bRender);

    void AddToList(CClientRadarArea* pRadarArea) { m_List.push_back(pRadarArea); };
    void RemoveFromList(CClientRadarArea* pRadarArea);

private:
    CClientManager* m_pManager;

    std::list<CClientRadarArea*> m_List;
    bool                         m_bDontRemoveFromList;
    unsigned short               m_usDimension;
};
