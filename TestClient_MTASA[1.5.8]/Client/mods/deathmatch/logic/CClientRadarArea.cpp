/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *               (Shared logic for modifications)
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        mods/shared_logic/CClientRadarArea.cpp
 *  PURPOSE:     Radar area entity class
 *
 *****************************************************************************/

#include <StdInc.h>

CClientRadarArea::CClientRadarArea(class CClientManager* pManager, ElementID ID) : ClassInit(this), CClientEntity(ID)
{
    // Init
    m_pManager = pManager;
    m_pRadarAreaManager = pManager->GetRadarAreaManager();
    m_Color = SColorRGBA(255, 255, 255, 255);
    m_bFlashing = false;
    m_ulFlashCycleStart = 0;
    m_bStreamedIn = true;

    SetTypeName("radararea");

    // Make sure we're visible/invisible according to our dimension
    RelateDimension(m_pRadarAreaManager->GetDimension());

    // Add us to the manager's list
    m_pRadarAreaManager->AddToList(this);
}

CClientRadarArea::~CClientRadarArea()
{
    // Remove us from the manager's list
    Unlink();
}

void CClientRadarArea::Unlink()
{
    m_pRadarAreaManager->RemoveFromList(this);
}

void CClientRadarArea::DoPulse()
{
    DoPulse(true);
}

void CClientRadarArea::DoPulse(bool bRender)
{
    #define RADAR_FLASH_CYCLETIME 1000

    // Suppose to show?
    if (m_bStreamedIn)
    {
        // If it's flashing, calculate a new alpha
        SColor color = m_Color;

        if (m_bFlashing)
        {
            // Time to start a new cycle?
            unsigned long ulCurrentTime = CClientTime::GetTime();
            if (m_ulFlashCycleStart == 0)
            {
                m_ulFlashCycleStart = ulCurrentTime;
            }
            // Time to end the cycle and start a new?
            else if (ulCurrentTime >= m_ulFlashCycleStart + RADAR_FLASH_CYCLETIME)
            {
                m_ulFlashCycleStart = ulCurrentTime;
            }

            // Calculate the alpha based on the last cycle time and the cycle intervals
            // We're in the fade in part of the cycle?
            if (ulCurrentTime >= m_ulFlashCycleStart + RADAR_FLASH_CYCLETIME / 2)
            {
                // Calculate the alpha-factor
                m_fAlphaFactor = static_cast<float>(ulCurrentTime - m_ulFlashCycleStart - RADAR_FLASH_CYCLETIME / 2) / (RADAR_FLASH_CYCLETIME / 2);
            }
            else
            {
                // Calculate the alpha-factor
                m_fAlphaFactor = 1.0f - static_cast<float>(ulCurrentTime - m_ulFlashCycleStart) / (RADAR_FLASH_CYCLETIME / 2);
            }

            // Multiply the alpha-factor with the alpha we're supposed to have to find what alpha to use and set it
            color.A = static_cast<unsigned char>(m_fAlphaFactor * static_cast<float>(color.A));
        }

        // Only render the radar area if we are told to
        if (bRender)
        {
            // Enforce X1 > X2 and Y2 > Y1
            // Fix for #0005888
            float fX1 = m_vecPosition.fX + m_vecSize.fX;
            float fX2 = m_vecPosition.fX;
            float fY1 = m_vecPosition.fY;
            float fY2 = m_vecPosition.fY + m_vecSize.fY;

            if (m_vecSize.fX < 0)
                std::swap(fX1, fX2);
            if (m_vecSize.fY < 0)
                std::swap(fY1, fY2);

            // Draw it
            g_pGame->GetRadar()->DrawAreaOnRadar(fX1, fY1, fX2, fY2, color);
        }
    }
}

void CClientRadarArea::SetDimension(unsigned short usDimension)
{
    m_usDimension = usDimension;
    RelateDimension(m_pRadarAreaManager->GetDimension());
}

void CClientRadarArea::RelateDimension(unsigned short usDimension)
{
    m_bStreamedIn = (usDimension == m_usDimension);
}
