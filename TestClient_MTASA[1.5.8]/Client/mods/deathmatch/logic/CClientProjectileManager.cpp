/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *               (Shared logic for modifications)
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        mods/shared_logic/CClientProjectileManager.cpp
 *  PURPOSE:     Projectile entity manager class
 *
 *****************************************************************************/

#include "StdInc.h"

using std::list;

CClientProjectileManager* g_pProjectileManager = NULL;

/* This class is used to manage/control projectiles created from game-layer hooks.
   Projectile creation should eventually be server-requested.
*/
CClientProjectileManager::CClientProjectileManager(CClientManager* pManager)
{
    CClientEntityRefManager::AddEntityRefs(ENTITY_REF_DEBUG(this, "CClientProjectileManager"), &m_pCreator, &m_pLastCreated, NULL);

    g_pProjectileManager = this;
    m_pManager = pManager;

    m_bIsLocal = false;
    m_pCreator = NULL;

    m_bCreating = false;
    m_pLastCreated = NULL;
}

CClientProjectileManager::~CClientProjectileManager()
{
    RemoveAll();
    if (g_pProjectileManager == this)
        g_pProjectileManager = NULL;
    CClientEntityRefManager::RemoveEntityRefs(0, &m_pCreator, &m_pLastCreated, NULL);
}

void CClientProjectileManager::DoPulse()
{
    CElementDeleter*                   pElementDeleter = g_pClientGame->GetElementDeleter();
    CClientProjectile*                 pProjectile = NULL;
    list<CClientProjectile*>           cloneList = m_List;
    list<CClientProjectile*>::iterator iter = cloneList.begin();
    for (; iter != cloneList.end(); ++iter)
    {
        pProjectile = *iter;

        // Is this projectile still active?
        if (pProjectile->IsActive())
        {
            pProjectile->DoPulse();
        }
    }
}

void CClientProjectileManager::RemoveAll()
{
    list<CClientProjectile*>           cloneList = m_List;
    list<CClientProjectile*>::iterator iter = cloneList.begin();
    for (; iter != cloneList.end(); ++iter)
    {
        delete *iter;
    }
    m_List.clear();
}

bool CClientProjectileManager::Exists(CClientProjectile* pProjectile)
{
    list<CClientProjectile*>::iterator iter = m_List.begin();
    for (; iter != m_List.end(); iter++)
    {
        if (*iter == pProjectile)
        {
            return true;
        }
    }
    return false;
}

CClientProjectile* CClientProjectileManager::Get(CEntitySAInterface* pProjectile)
{
    int iCount = m_List.size();
    assert(iCount <= 32);
    list<CClientProjectile*>::iterator iter = m_List.begin();
    for (; iter != m_List.end(); iter++)
    {
        if ((*iter)->GetGameEntity()->GetInterface() == pProjectile)
        {
            return (*iter);
        }
    }
    return NULL;
}

void CClientProjectileManager::RemoveFromList(CClientProjectile* pProjectile)
{
    m_List.remove(pProjectile);
}

bool CClientProjectileManager::Hook_StaticProjectileAllow(CEntity* pGameCreator, eWeaponType weaponType, CVector* origin, float fForce, CVector* target,
                                                          CEntity* targetEntity)
{
    return g_pProjectileManager->Hook_ProjectileAllow(pGameCreator, weaponType, origin, fForce, target, targetEntity);
}

bool CClientProjectileManager::Hook_ProjectileAllow(CEntity* pGameCreator, eWeaponType weaponType, CVector* origin, float fForce, CVector* target,
                                                    CEntity* targetEntity)
{
    // Called before projectile creation, we need to decide to allow or cancel it here

    // Is this a local projectile?
    CClientPlayer* pLocalPlayer = m_pManager->GetPlayerManager()->GetLocalPlayer();

    CPools* pPools = g_pGame->GetPools();

    // Store the creator/local variables for the next stage
    m_pCreator = pGameCreator ? pPools->GetClientEntity((DWORD*)pGameCreator->GetInterface()) : nullptr;
    m_bIsLocal = (m_pCreator == pLocalPlayer || (pLocalPlayer->GetOccupiedVehicleSeat() == 0 && m_pCreator == pLocalPlayer->GetOccupiedVehicle()));

    return (m_bCreating || m_bIsLocal);
}

void CClientProjectileManager::Hook_StaticProjectileCreation(CEntity* pGameCreator, CProjectile* pGameProjectile, CProjectileInfo* pProjectileInfo,
                                                             eWeaponType weaponType, CVector* origin, float fForce, CVector* target, CEntity* pGameTarget)
{
    g_pProjectileManager->Hook_ProjectileCreation(pGameCreator, pGameProjectile, pProjectileInfo, weaponType, origin, fForce, target, pGameTarget);
}

void CClientProjectileManager::Hook_ProjectileCreation(CEntity* pGameCreator, CProjectile* pGameProjectile, CProjectileInfo* pProjectileInfo,
                                                       eWeaponType weaponType, CVector* origin, float fForce, CVector* target, CEntity* pGameTarget)
{
    // Called on projectile construction (projectile doesn't actually exist until the next frame)
    /* Projectiles:
    WEAPONTYPE_GRENADE, WEAPONTYPE_TEARGAS, WEAPONTYPE_MOLOTOV,
    WEAPONTYPE_REMOTE_SATCHEL_CHARGE, WEAPONTYPE_ROCKET, WEAPONTYPE_ROCKET_HS,
    WEAPONTYPE_FLARE, WEAPONTYPE_FREEFALL_BOMB */

    CPools*        pPools = g_pGame->GetPools();
    CClientEntity* pTarget = pGameTarget ? pPools->GetClientEntity((DWORD*)pGameTarget->GetInterface()) : nullptr;
    m_pLastCreated = new CClientProjectile(m_pManager, pGameProjectile, pProjectileInfo, m_pCreator, pTarget, weaponType, origin, target, fForce, m_bIsLocal);
}

CClientProjectile* CClientProjectileManager::Create(CClientEntity* pCreator, eWeaponType eWeapon, CVector& vecOrigin, float fForce, CVector* target,
                                                    CClientEntity* pTargetEntity)
{
    m_bCreating = true;
    m_pLastCreated = NULL;
    CEntity* pGameCreator = pCreator->GetGameEntity();
    CEntity* pGameTargetEntity = NULL;
    if (pTargetEntity)
        pGameTargetEntity = pTargetEntity->GetGameEntity();
    if (pGameCreator)
    {
        // Peds and players
        if (pCreator->GetType() == CCLIENTPED || pCreator->GetType() == CCLIENTPLAYER)
        {
            CPed* pPed = dynamic_cast<CPed*>(pGameCreator);
            if (pPed)
                pPed->AddProjectile(eWeapon, vecOrigin, fForce, target, pGameTargetEntity);
        }
        // Vehicles
        else if (pCreator->GetType() == CCLIENTVEHICLE)
        {
            CVehicle* pVehicle = dynamic_cast<CVehicle*>(pGameCreator);
            if (pVehicle)
                pVehicle->AddProjectile(eWeapon, vecOrigin, fForce, target, pGameTargetEntity);
        }
    }
    m_bCreating = false;
    return m_pLastCreated;
}
