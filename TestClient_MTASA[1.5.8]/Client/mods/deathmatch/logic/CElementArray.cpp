/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *               (Shared logic for modifications)
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        mods/shared_logic/CElementArray.cpp
 *  PURPOSE:     Element array class
 *
 *****************************************************************************/

#include <StdInc.h>

using namespace std;

SFixedArray<CClientEntity*, MAX_SERVER_ELEMENTS + MAX_CLIENT_ELEMENTS> CElementIDs::m_Elements;
CStack<ElementID, MAX_CLIENT_ELEMENTS - 2>                             CElementIDs::m_ClientStack;

void CElementIDs::Initialize()
{
    memset(&m_Elements[0], 0, sizeof(m_Elements));
}

CClientEntity* CElementIDs::GetElement(ElementID ID)
{
    if (ID < MAX_SERVER_ELEMENTS + MAX_CLIENT_ELEMENTS)
    {
        return m_Elements[ID.Value()];
    }

    /*
    #ifdef MTA_DEBUG
        assert ( 0 );
    #endif
    */
    return NULL;
}

void CElementIDs::SetElement(ElementID ID, CClientEntity* pEntity)
{
    if (ID < MAX_SERVER_ELEMENTS + MAX_CLIENT_ELEMENTS)
        m_Elements[ID.Value()] = pEntity;
#ifdef MTA_DEBUG
    else
        assert(0);
#endif
}

ElementID CElementIDs::PopClientID()
{
    // Pop an unique ID
    ElementID ID;

    if (m_ClientStack.Pop(ID) && ID != INVALID_ELEMENT_ID)
    {
        // Make it at the beginning after server range ends
        return ID.Value() + MAX_SERVER_ELEMENTS;
    }

    // Return it
    return INVALID_ELEMENT_ID;
}

void CElementIDs::PushClientID(ElementID ID)
{
    // Not invalid?
    if (ID != INVALID_ELEMENT_ID)
    {
        // It's in the server element ID range, put it down to client
        ID = ID.Value() - MAX_SERVER_ELEMENTS;
        m_ClientStack.Push(ID);
    }
}
