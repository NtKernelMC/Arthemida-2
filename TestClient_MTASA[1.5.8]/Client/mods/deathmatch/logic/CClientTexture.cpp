/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *               (Shared logic for modifications)
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        mods/shared_logic/CClientTexture.cpp
 *  PURPOSE:
 *
 *****************************************************************************/

#include <StdInc.h>

////////////////////////////////////////////////////////////////
//
// CClientTexture::CClientTexture
//
//
//
////////////////////////////////////////////////////////////////
CClientTexture::CClientTexture(CClientManager* pManager, ElementID ID, CTextureItem* pTextureItem) : ClassInit(this), CClientMaterial(pManager, ID)
{
    SetTypeName("texture");
    m_pRenderItem = pTextureItem;
}
