/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *               (Shared logic for modifications)
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        mods/shared_logic/CClientDisplay.cpp
 *  PURPOSE:     Text display class
 *
 *****************************************************************************/

#include <StdInc.h>

CClientDisplay::CClientDisplay(CClientDisplayManager* pDisplayManager, unsigned long ulID)
{
    m_pDisplayManager = pDisplayManager;
    m_ulID = ulID;

    m_ulExpirationTime = 0;
    m_bVisible = true;
    m_Color = SColorRGBA(255, 255, 255, 255);

    m_pDisplayManager->AddToList(this);
}

CClientDisplay::~CClientDisplay()
{
    // Remove us from the manager
    m_pDisplayManager->RemoveFromList(this);
}

void CClientDisplay::SetColorAlpha(unsigned char ucAlpha)
{
    m_Color.A = ucAlpha;
}