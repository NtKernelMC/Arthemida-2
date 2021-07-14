/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        mods/deathmatch/logic/CTransferBox.h
 *  PURPOSE:     Header for transfer box class
 *
 *  Multi Theft Auto is available from http://www.multitheftauto.com/
 *
 *****************************************************************************/

#pragma once

#define TRANSFERBOX_FRAMES  10
#define TRANSFERBOX_DELAY   50

#include "CClientCommon.h"
#include <gui/CGUI.h>

class CTransferBox
{
public:
    enum Type
    {
        NORMAL,
        PACKET,
        MAX_TYPES
    };

    CTransferBox();
    virtual ~CTransferBox();

    void Show();
    void Hide();

    void SetInfo(double dDownloadSizeNow, CTransferBox::Type eTransferType = CTransferBox::NORMAL);

    void DoPulse();

    bool OnCancelClick(CGUIElement* pElement);

    bool IsVisible() { return m_pWindow->IsVisible(); };

    void AddToTotalSize(double dSize) { m_dTotalSize += dSize; };

private:
    CGUIWindow*                                       m_pWindow;
    SFixedArray<CGUIStaticImage*, TRANSFERBOX_FRAMES> m_pIcon;
    CGUILabel*                                        m_pInfo;
    CGUIProgressBar*                                  m_pProgress;

    bool m_bMultipleDownloads;

    unsigned int m_uiVisible;
    CElapsedTime m_AnimTimer;
    double       m_dTotalSize;

    SString m_strTransferText[Type::MAX_TYPES];
};
