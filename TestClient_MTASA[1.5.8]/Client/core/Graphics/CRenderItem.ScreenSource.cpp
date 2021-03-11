/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        core/CRenderItem.ScreenSource.cpp
 *  PURPOSE:
 *
 *****************************************************************************/

#include "StdInc.h"

////////////////////////////////////////////////////////////////
//
// CScreenSourceItem::PostConstruct
//
//
//
////////////////////////////////////////////////////////////////
void CScreenSourceItem::PostConstruct(CRenderItemManager* pManager, uint uiSizeX, uint uiSizeY)
{
    Super::PostConstruct(pManager);
    m_uiSizeX = uiSizeX;
    m_uiSizeY = uiSizeY;
    m_uiSurfaceSizeX = uiSizeX;
    m_uiSurfaceSizeY = uiSizeY;

    // Initial creation of d3d data
    CreateUnderlyingData();
}

////////////////////////////////////////////////////////////////
//
// CScreenSourceItem::PreDestruct
//
//
//
////////////////////////////////////////////////////////////////
void CScreenSourceItem::PreDestruct()
{
    ReleaseUnderlyingData();
    Super::PreDestruct();
}

////////////////////////////////////////////////////////////////
//
// CScreenSourceItem::IsValid
//
// Check underlying data is present
//
////////////////////////////////////////////////////////////////
bool CScreenSourceItem::IsValid()
{
    return m_pD3DTexture && m_pD3DRenderTargetSurface;
}

////////////////////////////////////////////////////////////////
//
// CScreenSourceItem::OnLostDevice
//
// Release device stuff
//
////////////////////////////////////////////////////////////////
void CScreenSourceItem::OnLostDevice()
{
    ReleaseUnderlyingData();
}

////////////////////////////////////////////////////////////////
//
// CScreenSourceItem::OnResetDevice
//
// Recreate device stuff
//
////////////////////////////////////////////////////////////////
void CScreenSourceItem::OnResetDevice()
{
    CreateUnderlyingData();
}

////////////////////////////////////////////////////////////////
//
// CScreenSourceItem::CreateUnderlyingData
//
//
//
////////////////////////////////////////////////////////////////
void CScreenSourceItem::CreateUnderlyingData()
{
    assert(!m_pD3DRenderTargetSurface);
    assert(!m_pD3DTexture);

    for (uint i = 0; i < 4; i++)
    {
        // 1st try -  i == 0  - 32 bit target
        // 2nd try -  i == 1  - 16 bit target
        //            i == 1  - EvictManagedResources
        // 3rd try -  i == 2  - 32 bit target
        // 4th try -  i == 3  - 16 bit target
        D3DFORMAT Format = i & 1 ? D3DFMT_R5G6B5 : D3DFMT_X8R8G8B8;
        if (SUCCEEDED(
                m_pDevice->CreateTexture(m_uiSizeX, m_uiSizeY, 1, D3DUSAGE_RENDERTARGET, Format, D3DPOOL_DEFAULT, (IDirect3DTexture9**)&m_pD3DTexture, NULL)))
            break;

        // c'mon
        if (i == 1)
            m_pDevice->EvictManagedResources();
    }

    // Check texture created
    if (!m_pD3DTexture)
        return;

    // Get the render target surface here for convenience
    ((IDirect3DTexture9*)m_pD3DTexture)->GetSurfaceLevel(0, &m_pD3DRenderTargetSurface);

    // Update surface size, although it probably will be unchanged
    D3DSURFACE_DESC desc;
    m_pD3DRenderTargetSurface->GetDesc(&desc);
    m_uiSurfaceSizeX = desc.Width;
    m_uiSurfaceSizeY = desc.Height;

    // Clear incase it gets used before first copy
    m_pDevice->ColorFill(m_pD3DRenderTargetSurface, NULL, 0x00000000);

    m_iMemoryKBUsed = CRenderItemManager::CalcD3DResourceMemoryKBUsage(m_pD3DRenderTargetSurface);
}

////////////////////////////////////////////////////////////////
//
// CScreenSourceItem::ReleaseUnderlyingData
//
//
//
////////////////////////////////////////////////////////////////
void CScreenSourceItem::ReleaseUnderlyingData()
{
    SAFE_RELEASE(m_pD3DRenderTargetSurface)
    SAFE_RELEASE(m_pD3DTexture)
}
