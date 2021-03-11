/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        core/CRenderItem.DxFont.cpp
 *  PURPOSE:
 *
 *****************************************************************************/

#include "StdInc.h"
#include "utils/XFont.h"

////////////////////////////////////////////////////////////////
//
// CDxFontItem::PostConstruct
//
//
//
////////////////////////////////////////////////////////////////
void CDxFontItem::PostConstruct(CRenderItemManager* pManager, const SString& strFullFilePath, uint uiSize, bool bBold, DWORD ulQuality)
{
    Super::PostConstruct(pManager);
    m_strFullFilePath = strFullFilePath;

    // Initial creation of d3d data
    CreateUnderlyingData(uiSize, bBold, ulQuality);
}

////////////////////////////////////////////////////////////////
//
// CDxFontItem::PreDestruct
//
//
//
////////////////////////////////////////////////////////////////
void CDxFontItem::PreDestruct()
{
    ReleaseUnderlyingData();
    Super::PreDestruct();
}

////////////////////////////////////////////////////////////////
//
// CDxFontItem::IsValid
//
// Check underlying data is present
//
////////////////////////////////////////////////////////////////
bool CDxFontItem::IsValid()
{
    return m_pFntNormal != NULL;
}

////////////////////////////////////////////////////////////////
//
// CDxFontItem::OnLostDevice
//
// Release device stuff
//
////////////////////////////////////////////////////////////////
void CDxFontItem::OnLostDevice()
{
    m_pFntNormal->OnLostDevice();
}

////////////////////////////////////////////////////////////////
//
// CDxFontItem::OnResetDevice
//
// Recreate device stuff
//
////////////////////////////////////////////////////////////////
void CDxFontItem::OnResetDevice()
{
    m_pFntNormal->OnResetDevice();
}

////////////////////////////////////////////////////////////////
//
// CDxFontItem::CreateUnderlyingData
//
//
//
////////////////////////////////////////////////////////////////
void CDxFontItem::CreateUnderlyingData(uint uiSize, bool bBold, DWORD ulQuality)
{
    assert(!m_pFntNormal);

    uiSize = (uiSize < 5) ? 5 : ((uiSize > 150) ? 150 : uiSize);

    // Create the D3DX fonts
    FONT_PROPERTIES sFontProps;
    if (GetFontProperties(LPCTSTR(m_strFullFilePath.c_str()), &sFontProps))
        CCore::GetSingleton().GetGraphics()->LoadAdditionalDXFont(m_strFullFilePath, sFontProps.csName, static_cast<int>(std::floor(uiSize * 1.75f)), bBold,
                                                                  ulQuality, &m_pFntNormal);

    if (!m_pFntNormal)
        return;

    // Memory usage - complete guess
    int iCharHeight = CCore::GetSingleton().GetGraphics()->GetDXFontHeight(1, m_pFntNormal);
    int iCharWidth = CCore::GetSingleton().GetGraphics()->GetDXTextExtent("A", 1, m_pFntNormal);
    int iNumChars = 256;
    int iBodgeFactor = 1;
    int iBPP = 32;
    int iMemoryUsed = iCharHeight * iCharWidth * iBPP / 8 * iNumChars * iBodgeFactor;
    m_iMemoryKBUsed = iMemoryUsed / 1024;
}

////////////////////////////////////////////////////////////////
//
// CDxFontItem::ReleaseUnderlyingData
//
//
//
////////////////////////////////////////////////////////////////
void CDxFontItem::ReleaseUnderlyingData()
{
    // Release the D3DX font data
    CCore::GetSingleton().GetGraphics()->DestroyAdditionalDXFont(m_strFullFilePath, m_pFntNormal);
}
