/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *               (Shared logic for modifications)
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        mods/shared_logic/CClientMaterial.h
 *  PURPOSE:
 *
 *****************************************************************************/

class CClientMaterial : public CClientRenderElement
{
    DECLARE_CLASS(CClientMaterial, CClientRenderElement)
public:
    CClientMaterial(CClientManager* pManager, ElementID ID) : ClassInit(this), CClientRenderElement(pManager, ID) {}

    CMaterialItem* GetMaterialItem() { return (CMaterialItem*)m_pRenderItem; }
};
