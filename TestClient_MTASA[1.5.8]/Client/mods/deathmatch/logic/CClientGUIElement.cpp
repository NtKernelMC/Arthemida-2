/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *               (Shared logic for modifications)
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        mods/shared_logic/CClientGUIElement.cpp
 *  PURPOSE:     GUI wrapper entity class
 *
 *****************************************************************************/

#include "StdInc.h"

using std::list;

extern CClientGame* g_pClientGame;

CClientGUIElement::CClientGUIElement(CClientManager* pManager, CLuaMain* pLuaMain, CGUIElement* pCGUIElement, ElementID ID) : ClassInit(this), CClientEntity(ID)
{
    m_pManager = pManager;
    m_pGUIManager = pManager->GetGUIManager();
    m_pCGUIElement = pCGUIElement;
    m_pLuaMain = pLuaMain;
    m_pFontElement = NULL;

    // Store the this-pointer in the userdata variable
    CGUI_SET_CCLIENTGUIELEMENT(pCGUIElement, this);

    // Generate the CGUI type name variable
    switch (m_pCGUIElement->GetType())
    {
        case CGUI_BUTTON:
            m_strCGUITypeName = "button";
            break;
        case CGUI_CHECKBOX:
            m_strCGUITypeName = "checkbox";
            break;
        case CGUI_EDIT:
            m_strCGUITypeName = "edit";
            break;
        case CGUI_GRIDLIST:
            m_strCGUITypeName = "gridlist";
            break;
        case CGUI_LABEL:
            m_strCGUITypeName = "label";
            break;
        case CGUI_MEMO:
            m_strCGUITypeName = "memo";
            break;
        case CGUI_PROGRESSBAR:
            m_strCGUITypeName = "progressbar";
            break;
        case CGUI_RADIOBUTTON:
            m_strCGUITypeName = "radiobutton";
            break;
        case CGUI_STATICIMAGE:
            m_strCGUITypeName = "staticimage";
            break;
        case CGUI_TAB:
            m_strCGUITypeName = "tab";
            break;
        case CGUI_TABPANEL:
            m_strCGUITypeName = "tabpanel";
            break;
        case CGUI_WINDOW:
            m_strCGUITypeName = "window";
            break;
        case CGUI_SCROLLPANE:
            m_strCGUITypeName = "scrollpane";
            break;
        case CGUI_SCROLLBAR:
            m_strCGUITypeName = "scrollbar";
            break;
        case CGUI_COMBOBOX:
            m_strCGUITypeName = "combobox";
            break;
        case CGUI_WEBBROWSER:
            m_strCGUITypeName = "browser";
            break;
        default:
            m_strCGUITypeName = "unknown";
            break;
    }
    SetTypeName(SString("gui-%s", *m_strCGUITypeName));

    // Add us to the list in the manager
    m_pGUIManager->Add(this);
}

CClientGUIElement::~CClientGUIElement()
{
    // Remove us from the list in the manager
    Unlink();

    if (m_pCGUIElement)
        delete m_pCGUIElement;
}

void CClientGUIElement::Unlink()
{
    // Detach from any custom font
    if (m_pFontElement)
        SetFont("", NULL);

    m_pGUIManager->Remove(this);
}

void CClientGUIElement::SetEvents(const char* szFunc1, const char* szFunc2)
{
    if (szFunc1 && strlen(szFunc1) < MAX_EVENT_NAME)
        _strCallbackFunc1 = szFunc1;

    if (szFunc2 && strlen(szFunc2) < MAX_EVENT_NAME)
        _strCallbackFunc2 = szFunc2;
}

bool CClientGUIElement::_CallbackEvent1(CGUIElement* pCGUIElement)
{
    CLuaArguments Arg;
    if (pCGUIElement)
    {
        CClientGUIElement* pElement = m_pGUIManager->Get(pCGUIElement);
        if (pElement)
        {
            Arg.PushElement(pElement);
            pElement->CallEvent(_strCallbackFunc1, Arg, true);
            return true;
        }
    }
    return false;
}

bool CClientGUIElement::_CallbackEvent2(CGUIElement* pCGUIElement)
{
    CLuaArguments Arg;
    if (pCGUIElement)
    {
        CClientGUIElement* pElement = m_pGUIManager->Get(pCGUIElement);
        if (pElement)
        {
            Arg.PushElement(pElement);
            pElement->CallEvent(_strCallbackFunc2, Arg, true);
            return true;
        }
    }
    return false;
}

//
// Get which font name and font element we are using now
//
SString CClientGUIElement::GetFont(CClientGuiFont** ppFontElement)
{
    *ppFontElement = m_pFontElement;
    return GetCGUIElement()->GetFont();
}

//
// Change font
//
bool CClientGUIElement::SetFont(const SString& strInFontName, CClientGuiFont* pFontElement)
{
    SString strFontName = strInFontName;

    if (pFontElement)
        strFontName = pFontElement->GetCEGUIFontName();
    else if (strFontName.empty())
        strFontName = "default-normal";

    if (GetCGUIElement()->SetFont(strFontName))
    {
        if (m_pFontElement)
            m_pFontElement->NotifyGUIElementDetach(this);
        m_pFontElement = pFontElement;
        if (m_pFontElement)
            m_pFontElement->NotifyGUIElementAttach(this);
        return true;
    }
    return false;
}

//
// Change call propagation behaviour (overrides CClientEntity::SetCallPropagationEnabled)
void CClientGUIElement::SetCallPropagationEnabled(bool bEnabled)
{
    CClientEntity::SetCallPropagationEnabled(bEnabled);

    for (CFastList<CClientEntity*>::iterator iter = m_Children.begin(); iter != m_Children.end(); ++iter)
    {
        if ((*iter)->GetType() == CCLIENTGUI)
        {
            CClientGUIElement* pGUIElement = static_cast<CClientGUIElement*>(*iter);
            pGUIElement->GetCGUIElement()->SetInheritsAlpha(bEnabled);
        }
    }
}
