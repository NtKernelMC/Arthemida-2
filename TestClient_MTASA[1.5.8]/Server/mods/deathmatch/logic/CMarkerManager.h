/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        mods/deathmatch/logic/CMarkerManager.h
 *  PURPOSE:     Marker entity manager class
 *
 *  Multi Theft Auto is available from http://www.multitheftauto.com/
 *
 *****************************************************************************/

class CMarkerManager;

#pragma once

#include "CColManager.h"
#include "CMarker.h"
#include <list>

class CMarkerManager
{
    friend class CMarker;

public:
    CMarkerManager(CColManager* pColManager);
    ~CMarkerManager() { DeleteAll(); };

    CMarker* Create(CElement* pParent);
    CMarker* CreateFromXML(CElement* pParent, CXMLNode& Node, CEvents* pEvents);
    void     DeleteAll();

    unsigned int Count() { return static_cast<unsigned int>(m_Markers.size()); };
    bool         Exists(CMarker* pMarker);

    list<CMarker*>::const_iterator IterBegin() { return m_Markers.begin(); };
    list<CMarker*>::const_iterator IterEnd() { return m_Markers.end(); };

    static int           StringToType(const char* szString);
    static bool          TypeToString(unsigned int uiType, char* szString);
    static unsigned char StringToIcon(const char* szString);
    static bool          IconToString(unsigned char ucIcon, char* szString);

private:
    void AddToList(CMarker* pMarker) { m_Markers.push_back(pMarker); };
    void RemoveFromList(CMarker* pMarker);

    CColManager*   m_pColManager;
    list<CMarker*> m_Markers;
};
