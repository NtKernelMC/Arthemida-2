/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *               (Shared logic for modifications)
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        mods/shared_logic/CClientPedManager.cpp
 *  PURPOSE:     Ped entity manager class
 *
 *****************************************************************************/

#include "StdInc.h"

using std::list;
using std::vector;

CClientPedManager::CClientPedManager(CClientManager* pManager)
{
    m_pManager = pManager;
    m_bRemoveFromList = true;
}

CClientPedManager::~CClientPedManager()
{
    DeleteAll();
}

void CClientPedManager::DeleteAll()
{
    m_bRemoveFromList = false;
    vector<CClientPed*>::iterator iter = m_List.begin();
    for (; iter != m_List.end(); iter++)
    {
        delete *iter;
    }
    m_List.clear();
    m_bRemoveFromList = true;
}

void CClientPedManager::DoPulse(bool bDoStandardPulses)
{
    CClientPed* pPed = NULL;
    // Loop through our streamed-in peds
    vector<CClientPed*>           List = m_StreamedIn;
    vector<CClientPed*>::iterator iter = List.begin();
    for (; iter != List.end(); ++iter)
    {
        pPed = *iter;
        // We should have a game ped here
        assert(pPed->GetGamePlayer());
        pPed->StreamedInPulse(bDoStandardPulses);
    }
}


CClientPed* CClientPedManager::Get(ElementID ID, bool bCheckPlayers)
{
    // Grab the element with the given id. Check its type.
    CClientEntity* pEntity = CElementIDs::GetElement(ID);
    if (pEntity && (pEntity->GetType() == CCLIENTPED || (bCheckPlayers && pEntity->GetType() == CCLIENTPLAYER)))
    {
        return static_cast<CClientPed*>(pEntity);
    }

    return NULL;
}

bool CClientPedManager::Exists(CClientPed* pPed)
{
    // Is it in our list?
    vector<CClientPed*>::iterator iter = m_List.begin();
    for (; iter != m_List.end(); iter++)
    {
        if (*iter == pPed)
            return true;
    }

    // Nope
    return false;
}

void CClientPedManager::RemoveFromList(CClientPed* pPed)
{
    if (m_bRemoveFromList)
    {
        ListRemove(m_List, pPed);
    }
}

void CClientPedManager::OnCreation(CClientPed* pPed)
{
    // Check not already in the list to avoid multiple calls to pPed->StreamedInPulse() later
    if (!ListContains(m_StreamedIn, pPed))
        m_StreamedIn.push_back(pPed);
}

void CClientPedManager::OnDestruction(CClientPed* pPed)
{
    ListRemove(m_StreamedIn, pPed);
}

void CClientPedManager::RestreamPeds(unsigned short usModel)
{
    g_pClientGame->GetModelCacheManager()->OnRestreamModel(usModel);

    // Store the affected vehicles
    CClientPed*                              pPed;
    std::vector<CClientPed*>::const_iterator iter = IterBegin();
    for (; iter != IterEnd(); iter++)
    {
        pPed = *iter;

        // Streamed in and same vehicle ID?
        if (pPed->IsStreamedIn() && pPed->GetModel() == usModel)
        {
            // Stream it out for a while until streamed decides to stream it
            // back in eventually
            pPed->StreamOutForABit();
            // Hack fix for Players not unloading.
            if (IS_PLAYER(pPed))
            {
                // Awesome hack skills + 1, change him to another model while we unload for the lulz
                // Translation: My hack level has increased to ninety eight and we need to wait a frame before reloading the model ID in question so that the
                // custom model unloads properly. To do this we set him to CJ (Impossible to mod to my knowledge) and then set him back in CPed::StreamedInPulse
                pPed->SetModel(0, true);
            }
        }
    }
}
void CClientPedManager::RestreamWeapon(unsigned short usModel)
{
    eWeaponSlot eSlot = (eWeaponSlot)GetWeaponSlotFromModel(usModel);
    // Store the affected vehicles
    CClientPed*                              pPed;
    std::vector<CClientPed*>::const_iterator iter = IterBegin();
    for (; iter != IterEnd(); iter++)
    {
        pPed = *iter;

        // Streamed in and same vehicle ID?
        if (pPed->IsStreamedIn() && pPed->GetWeapon(eSlot) && pPed->GetWeapon(eSlot)->GetInfo(WEAPONSKILL_STD)->GetModel() == usModel)
        {
            // Awesome hack skills + 1, change him to another model while we unload for the lulz
            // Translation: My hack level has increased to ninety nine and we need to wait a frame before reloading the model ID in question so that the custom
            // model unloads properly. To do this we take away the weapon and give it back in CPed::StreamedInPulse ergo reloading the model info
            pPed->StreamOutWeaponForABit(eSlot);
        }
    }
}

unsigned short CClientPedManager::GetWeaponSlotFromModel(DWORD dwModel)
{
    switch (dwModel)
    {
        case 0:
        case 331:
        {
            return 0;
        }
        case 333:
        case 334:
        case 335:
        case 336:
        case 337:
        case 338:
        case 339:
        case 341:
        {
            return 1;
        }
        case 346:
        case 347:
        case 348:
        {
            return 2;
        }
        case 349:
        case 350:
        case 351:
        {
            return 3;
        }
        case 352:
        case 353:
        case 372:
        {
            return 4;
        }
        case 355:
        case 356:
        {
            return 5;
        }
        case 357:
        case 358:
        {
            return 6;
        }
        case 359:
        case 360:
        case 361:
        case 362:
        {
            return 7;
        }
        case 342:
        case 343:
        case 344:
        case 363:
        {
            return 8;
        }
        case 365:
        case 366:
        case 367:
        {
            return 9;
        }
        case 321:
        case 322:
        case 323:
        case 325:
        case 326:
        {
            return 10;
        }
        case 368:
        case 369:
        case 371:
        {
            return 11;
        }
        case 364:
        {
            return 12;
        }
    }

    return 0;
}

bool CClientPedManager::IsValidWeaponModel(DWORD dwModel)
{
    switch (dwModel)
    {
        case 0:
        case 321:            // Regular_Dildo
        case 322:            // Vibrator
        case 323:            // White_Dildo
                             //    324    // Vibrator_unused
        case 325:            // Flowers
        case 326:            // Cane
                             //    327
                             //    328
                             //    329
                             //    330
        case 331:            // Brass_Knuckles
                             //    332
        case 333:            // Golf_Club
        case 334:            // Night_Strick
        case 335:            // Knife
        case 336:            // Baseball_Bat
        case 337:            // Shovel
        case 338:            // Pool_Cue
        case 339:            // Katana
                             //    340
        case 341:            // Chainsaw
        case 342:            // Grenade
        case 343:            // Tear_Gas
        case 344:            // Molotov_Cocktail
                             //    345    // Missile
        case 346:            // Pistol
        case 347:            // Silenced_Pistol
        case 348:            // Desert_Eagle
        case 349:            // Shotgun
        case 350:            // Sawn-Off_Shotgun
        case 351:            // Combat_Shotgun
        case 352:            // Uzi
        case 353:            // MP5
                             //    354    // Hydra_Flare
        case 355:            // AK47
        case 356:            // M4
        case 357:            // Country_Rifle
        case 358:            // Sniper_Rifle
        case 359:            // Rocket_Launcher
        case 360:            // Heat_Seeking_Rocket_Launcher
        case 361:            // Flamethrower
        case 362:            // Minigun
        case 363:            // Satchel_Charge
        case 364:            // Detonator
        case 365:            // Spray_Can
        case 366:            // Fire_Extinguisher
        case 367:            // Camera
        case 368:            // Night_Vision_Goggles
        case 369:            // Infra-Red_Goggles
        //    370   // Jet_Pack
        case 371:            // Parachute
        case 372:            // Tec-9
        {
            return true;
        }
    }

    return false;
}
