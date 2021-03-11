/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *               (Shared logic for modifications)
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        mods/shared_logic/CClientEffect.cpp
 *  PURPOSE:     Effect entity class
 *
 *****************************************************************************/
#include "StdInc.h"

CClientEffect::CClientEffect(CClientManager* pManager, CFxSystem* pFx, SString strEffectName, ElementID ID) : ClassInit(this), CClientEntity(ID)
{
    m_pFxSystem = pFx;
    m_pManager = pManager;
    m_pManager->GetEffectManager()->AddToList(this);
    SetTypeName("effect");

    m_pFxSystem->PlayAndKill();
    m_strEffectName = strEffectName;
    m_fMaxDensity = pFx->GetEffectDensity() * 2;
}

CClientEffect::~CClientEffect()
{
    Unlink();
}

void CClientEffect::Unlink()
{
    m_pManager->GetEffectManager()->RemoveFromList(this);

    if (m_pFxSystem != NULL)
    {
        g_pGame->GetFxManager()->DestroyFxSystem(m_pFxSystem);
        m_pFxSystem = NULL;
    }
}

void CClientEffect::GetPosition(CVector& vecPosition) const
{
    m_pFxSystem->GetPosition(vecPosition);
}

void CClientEffect::SetPosition(const CVector& vecPosition)
{
    m_pFxSystem->SetPosition(vecPosition);
}

bool CClientEffect::GetMatrix(CMatrix& matrix) const
{
    m_pFxSystem->GetMatrix(matrix);
    return true;
}

bool CClientEffect::SetMatrix(const CMatrix& matrix)
{
    m_pFxSystem->SetMatrix(matrix);
    return true;
}

void CClientEffect::SetEffectSpeed(float fSpeed)
{
    m_pFxSystem->SetEffectSpeed(fSpeed);
}

float CClientEffect::GetEffectSpeed() const
{
    return m_pFxSystem->GetEffectSpeed();
}

bool CClientEffect::SetEffectDensity(float fDensity)
{
    if (fDensity >= 0.0f && fDensity <= 2.0f)
    {
        m_pFxSystem->SetEffectDensity(Clamp(0.0f, fDensity, m_fMaxDensity));
        return true;
    }
    return false;
}

float CClientEffect::GetEffectDensity() const
{
    return m_pFxSystem->GetEffectDensity();
}

void CClientEffect::SetDrawDistance(float fDrawDistance)
{
    m_pFxSystem->SetDrawDistance(fDrawDistance);
}

float CClientEffect::GetDrawDistance() const
{
    return m_pFxSystem->GetDrawDistance();
}

void CClientEffect::SetRotationRadians(const CVector& vecRotation)
{
    CMatrix matrix;
    GetMatrix(matrix);
    g_pMultiplayer->ConvertEulerAnglesToMatrix(matrix, vecRotation.fX, vecRotation.fY, vecRotation.fZ);
    SetMatrix(matrix);
}

void CClientEffect::GetRotationRadians(CVector& vecRotation) const
{
    CMatrix matrix;
    GetMatrix(matrix);
    g_pMultiplayer->ConvertMatrixToEulerAngles(matrix, vecRotation.fX, vecRotation.fY, vecRotation.fZ);
}
