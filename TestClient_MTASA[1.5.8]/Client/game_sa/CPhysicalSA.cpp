/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        game_sa/CPhysicalSA.cpp
 *  PURPOSE:     Physical object entity
 *
 *  Multi Theft Auto is available from http://www.multitheftauto.com/
 *
 *****************************************************************************/

#include "StdInc.h"

CRect* CPhysicalSAInterface::GetBoundRect_(CRect* pRect)
{
    CVector boundCentre;
    CEntitySAInterface::GetBoundCentre(&boundCentre);
    float fRadius = CModelInfoSAInterface::GetModelInfo(m_nModelIndex)->pColModel->boundingBox.fRadius;
    *pRect = CRect(boundCentre.fX - fRadius, boundCentre.fY - fRadius, boundCentre.fX + fRadius, boundCentre.fY + fRadius);
    pRect->FixIncorrectTopLeft();            // Fix #1613: custom map collision crashes in CPhysical class (infinite loop)
    return pRect;
}

void CPhysicalSAInterface::StaticSetHooks()
{
    HookInstall(0x5449B0, &CPhysicalSAInterface::GetBoundRect_);
}

void CPhysicalSA::RestoreLastGoodPhysicsState()
{
    CEntitySA::RestoreLastGoodPhysicsState();

    CVector vecDefault;
    SetTurnSpeed(&vecDefault);
    SetMoveSpeed(&vecDefault);

    CPhysicalSAInterface* pInterface = (CPhysicalSAInterface*)this->GetInterface();
    pInterface->m_pad4d = 0;
    pInterface->m_fDamageImpulseMagnitude = 0;
    pInterface->m_vecCollisionImpactVelocity = CVector();
    pInterface->m_vecCollisionPosition = CVector();
}

CVector* CPhysicalSA::GetMoveSpeed(CVector* vecMoveSpeed)
{
    GetMoveSpeedInternal(vecMoveSpeed);
    if (!IsValidPosition(*vecMoveSpeed))
    {
        RestoreLastGoodPhysicsState();
        GetMoveSpeedInternal(vecMoveSpeed);
    }
    return vecMoveSpeed;
}

CVector* CPhysicalSA::GetTurnSpeed(CVector* vecTurnSpeed)
{
    GetTurnSpeedInternal(vecTurnSpeed);
    if (!IsValidPosition(*vecTurnSpeed))
    {
        RestoreLastGoodPhysicsState();
        GetTurnSpeedInternal(vecTurnSpeed);
    }
    return vecTurnSpeed;
}

CVector* CPhysicalSA::GetMoveSpeedInternal(CVector* vecMoveSpeed)
{
    DEBUG_TRACE("CVector * CPhysicalSA::GetMoveSpeed(CVector * vecMoveSpeed)");
    DWORD dwFunc = FUNC_GetMoveSpeed;
    DWORD dwThis = (DWORD)((CPhysicalSAInterface*)this->GetInterface());
    DWORD dwReturn = 0;
    _asm
    {
        mov     ecx, dwThis
        call    dwFunc
        mov     dwReturn, eax
    }
    MemCpyFast(vecMoveSpeed, (void*)dwReturn, sizeof(CVector));
    return vecMoveSpeed;
}

CVector* CPhysicalSA::GetTurnSpeedInternal(CVector* vecTurnSpeed)
{
    DEBUG_TRACE("CVector * CPhysicalSA::GetTurnSpeed(CVector * vecTurnSpeed)");
    DWORD dwFunc = FUNC_GetTurnSpeed;
    DWORD dwThis = (DWORD)((CPhysicalSAInterface*)this->GetInterface());
    DWORD dwReturn = 0;
    _asm
    {
        mov     ecx, dwThis
        call    dwFunc
        mov     dwReturn, eax
    }
    MemCpyFast(vecTurnSpeed, (void*)dwReturn, sizeof(CVector));
    return vecTurnSpeed;
}

VOID CPhysicalSA::SetMoveSpeed(CVector* vecMoveSpeed)
{
    DEBUG_TRACE("VOID CPhysicalSA::SetMoveSpeed(CVector * vecMoveSpeed)");
    DWORD dwFunc = FUNC_GetMoveSpeed;
    DWORD dwThis = (DWORD)((CPhysicalSAInterface*)this->GetInterface());
    DWORD dwReturn = 0;

    _asm
    {
        mov     ecx, dwThis
        call    dwFunc
        mov     dwReturn, eax
    }
    MemCpyFast((void*)dwReturn, vecMoveSpeed, sizeof(CVector));

    if (GetInterface()->nType == ENTITY_TYPE_OBJECT)
    {
        AddToMovingList();
        SetStatic(false);
    }
}

VOID CPhysicalSA::SetTurnSpeed(CVector* vecTurnSpeed)
{
    DEBUG_TRACE("VOID CPhysicalSA::SetTurnSpeed(CVector * vecTurnSpeed)");

    ((CPhysicalSAInterface*)this->GetInterface())->m_vecAngularVelocity = *vecTurnSpeed;

    if (GetInterface()->nType == ENTITY_TYPE_OBJECT)
    {
        AddToMovingList();
        SetStatic(false);
    }
}

float CPhysicalSA::GetMass()
{
    return ((CPhysicalSAInterface*)this->GetInterface())->m_fMass;
}

void CPhysicalSA::SetMass(float fMass)
{
    ((CPhysicalSAInterface*)this->GetInterface())->m_fMass = fMass;
}

float CPhysicalSA::GetTurnMass()
{
    return ((CPhysicalSAInterface*)this->GetInterface())->m_fTurnMass;
}

void CPhysicalSA::SetTurnMass(float fTurnMass)
{
    ((CPhysicalSAInterface*)this->GetInterface())->m_fTurnMass = fTurnMass;
}

float CPhysicalSA::GetAirResistance()
{
    return ((CPhysicalSAInterface*)this->GetInterface())->m_fAirResistance;
}

void CPhysicalSA::SetAirResistance(float fAirResistance)
{
    ((CPhysicalSAInterface*)this->GetInterface())->m_fAirResistance = fAirResistance;
}

float CPhysicalSA::GetElasticity()
{
    return ((CPhysicalSAInterface*)this->GetInterface())->m_fElasticity;
}

void CPhysicalSA::SetElasticity(float fElasticity)
{
    ((CPhysicalSAInterface*)this->GetInterface())->m_fElasticity = fElasticity;
}

float CPhysicalSA::GetBuoyancyConstant()
{
    return ((CPhysicalSAInterface*)this->GetInterface())->m_fBuoyancyConstant;
}

void CPhysicalSA::SetBuoyancyConstant(float fBuoyancyConstant)
{
    ((CPhysicalSAInterface*)this->GetInterface())->m_fBuoyancyConstant = fBuoyancyConstant;
}

void CPhysicalSA::GetCenterOfMass(CVector & vecCenterOfMass)
{
    vecCenterOfMass = ((CPhysicalSAInterface*)this->GetInterface())->m_vecCenterOfMass;
}


void CPhysicalSA::SetCenterOfMass(CVector & vecCenterOfMass)
{
    ((CPhysicalSAInterface*)this->GetInterface())->m_vecCenterOfMass = vecCenterOfMass;
}

VOID CPhysicalSA::ProcessCollision()
{
    DEBUG_TRACE("VOID CPhysicalSA::ProcessCollision()");
    DWORD dwFunc = FUNC_ProcessCollision;
    DWORD dwThis = (DWORD)this->GetInterface();

    _asm
    {
        mov     ecx, dwThis
        call    dwFunc
    }
}

void CPhysicalSA::AddToMovingList()
{
    DWORD dwFunc = FUNC_CPhysical_AddToMovingList;
    DWORD dwThis = (DWORD)GetInterface();

    _asm
    {
        mov     ecx, dwThis
        call    dwFunc
    }
}

float CPhysicalSA::GetDamageImpulseMagnitude()
{
    return ((CPhysicalSAInterface*)this->GetInterface())->m_fDamageImpulseMagnitude;
}

void CPhysicalSA::SetDamageImpulseMagnitude(float fMagnitude)
{
    ((CPhysicalSAInterface*)this->GetInterface())->m_fDamageImpulseMagnitude = fMagnitude;
}

CEntity* CPhysicalSA::GetDamageEntity()
{
    CEntitySAInterface* pInterface = ((CPhysicalSAInterface*)this->GetInterface())->m_pCollidedEntity;
    if (pInterface)
    {
        CPools* pPools = pGame->GetPools();
        return pPools->GetEntity((DWORD*)pInterface);
    }
    return nullptr;
}

void CPhysicalSA::SetDamageEntity(CEntity* pEntity)
{
    CEntitySA* pEntitySA = dynamic_cast<CEntitySA*>(pEntity);
    if (pEntitySA)
        ((CPhysicalSAInterface*)this->GetInterface())->m_pCollidedEntity = pEntitySA->GetInterface();
}

void CPhysicalSA::ResetLastDamage()
{
    ((CPhysicalSAInterface*)this->GetInterface())->m_fDamageImpulseMagnitude = 0.0f;
    ((CPhysicalSAInterface*)this->GetInterface())->m_pCollidedEntity = NULL;
}

CEntity* CPhysicalSA::GetAttachedEntity()
{
    CEntitySAInterface* pInterface = ((CPhysicalSAInterface*)this->GetInterface())->m_pAttachedEntity;
    if (pInterface)
    {
        CPools* pPools = pGame->GetPools();
        return pPools->GetEntity((DWORD*)pInterface);
    }
    return nullptr;
}

void CPhysicalSA::AttachEntityToEntity(CPhysical& Entity, const CVector& vecPosition, const CVector& vecRotation)
{
    DEBUG_TRACE("void CPhysicalSA::AttachEntityToEntity(CPhysical& Entity, const CVector& vecPosition, const CVector& vecRotation)");

    try
    {
        CPhysicalSA& EntitySA = dynamic_cast<CPhysicalSA&>(Entity);
        DWORD        dwEntityInterface = (DWORD)EntitySA.GetInterface();

        InternalAttachEntityToEntity(dwEntityInterface, &vecPosition, &vecRotation);
    }
    catch (...)
    {
        DEBUG_TRACE("Invalid Entity argument detected");
    }
}

void CPhysicalSA::DetachEntityFromEntity(float fUnkX, float fUnkY, float fUnkZ, bool bUnk)
{
    DEBUG_TRACE("void CPhysicalSA::DetachEntityFromEntity(float fUnkX, float fUnkY, float fUnk, bool bUnk)");
    DWORD dwFunc = FUNC_DetatchEntityFromEntity;
    DWORD dwThis = (DWORD)this->GetInterface();

    // DetachEntityFromEntity appears to crash when there's no entity attached (0x544403, bug 2350)
    // So do a NULL check here
    if (((CPhysicalSAInterface*)this->GetInterface())->m_pAttachedEntity == NULL)
        return;

    _asm
    {
        push    bUnk
        push    fUnkZ
        push    fUnkY
        push    fUnkX
        mov     ecx, dwThis
        call    dwFunc
    }
}

bool CPhysicalSA::InternalAttachEntityToEntity(DWORD dwEntityInterface, const CVector* vecPosition, const CVector* vecRotation)
{
    DEBUG_TRACE("bool CPhysicalSA::AttachEntityToEntity(CPhysical * entityToAttach, CVector * vecPosition, CVector * vecRotation)");
    DWORD dwFunc = FUNC_AttachEntityToEntity;
    DWORD dwThis = (DWORD)this->GetInterface();
    DWORD dwReturn = 0;
    _asm
    {
        mov     ecx, vecRotation
        push    [ecx+8]
        push    [ecx+4]
        push    [ecx]
        mov     ecx, vecPosition
        push    [ecx+8]
        push    [ecx+4]
        push    [ecx]
        push    dwEntityInterface
        mov     ecx, dwThis
        call    dwFunc
        mov     dwReturn, eax
    }
    return (dwReturn != NULL);
}

void CPhysicalSA::GetAttachedOffsets(CVector& vecPosition, CVector& vecRotation)
{
    CPhysicalSAInterface* pInterface = (CPhysicalSAInterface*)this->GetInterface();
    if (pInterface->m_pAttachedEntity)
    {
        vecPosition = pInterface->m_vecAttachedOffset;
        vecRotation = pInterface->m_vecAttachedRotation;
    }
}

void CPhysicalSA::SetAttachedOffsets(CVector& vecPosition, CVector& vecRotation)
{
    CPhysicalSAInterface* pInterface = (CPhysicalSAInterface*)this->GetInterface();
    if (pInterface->m_pAttachedEntity)
    {
        pInterface->m_vecAttachedOffset = vecPosition;
        pInterface->m_vecAttachedRotation = vecRotation;
    }
}

float CPhysicalSA::GetLighting()
{
    CPhysicalSAInterface* pInterface = (CPhysicalSAInterface*)this->GetInterface();
    return pInterface->m_fLighting;
}

void CPhysicalSA::SetLighting(float fLighting)
{
    CPhysicalSAInterface* pInterface = (CPhysicalSAInterface*)this->GetInterface();
    pInterface->m_fLighting = fLighting;
}

void CPhysicalSA::SetFrozen(bool bFrozen)
{
    CPhysicalSAInterface* pInterface = (CPhysicalSAInterface*)this->GetInterface();

    pInterface->bDontApplySpeed = bFrozen;
    // Don't enable friction for static objects
    pInterface->bDisableFriction = (bFrozen || pInterface->m_fMass >= PHYSICAL_MAXMASS);
}
