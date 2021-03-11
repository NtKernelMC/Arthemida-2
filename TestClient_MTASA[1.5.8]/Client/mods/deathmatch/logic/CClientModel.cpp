/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto
 *               (Shared logic for modifications)
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        mods/deathmatch/logic/CClientModel.h
 *  PURPOSE:     Model handling class
 *
 *****************************************************************************/

#include "StdInc.h"

CClientModel::CClientModel(CClientManager* pManager, int iModelID, eClientModelType eModelType)
{
    m_pManager = pManager;
    m_iModelID = iModelID;
    m_eModelType = eModelType;
}

CClientModel::~CClientModel(void)
{
    Deallocate();
}

bool CClientModel::Allocate(ushort usParentID)
{
    m_bAllocatedByUs = true;

    CModelInfo* pModelInfo = g_pGame->GetModelInfo(m_iModelID, true);

    // Allocate only on free IDs
    if (pModelInfo->IsValid())
        return false;

    switch (m_eModelType)
    {
        case eClientModelType::PED:
            pModelInfo->MakePedModel("PSYCHO");
            break;
        case eClientModelType::OBJECT:
            if (g_pClientGame->GetObjectManager()->IsValidModel(usParentID))
            {
                pModelInfo->MakeObjectModel(usParentID);
                return true;
            }
            break;
        case eClientModelType::VEHICLE:
            if (g_pClientGame->GetVehicleManager()->IsValidModel(usParentID))
            {
                pModelInfo->MakeVehicleAutomobile(usParentID);
                return true;
            }
            break;
        default:
            return false;
    }
    return false;
}

bool CClientModel::Deallocate(void)
{
    if (!m_bAllocatedByUs)
        return false;
    CModelInfo* pModelInfo = g_pGame->GetModelInfo(m_iModelID, true);
    if (!pModelInfo || !pModelInfo->IsValid())
        return false;
    pModelInfo->DeallocateModel();
    SetParentResource(nullptr);
    return true;
}

void CClientModel::RestoreEntitiesUsingThisModel()
{
    auto unloadModelsAndCallEvents = [&](auto iterBegin, auto iterEnd, unsigned short usParentID, auto setElementModelLambda) {
        for (auto iter = iterBegin; iter != iterEnd; iter++)
        {
            auto& element = **iter;

            if (element.GetModel() != m_iModelID)
                continue;

            if (element.IsStreamedIn())
                element.StreamOutForABit();

            setElementModelLambda(element);

            CLuaArguments Arguments;
            Arguments.PushNumber(m_iModelID);
            Arguments.PushNumber(usParentID);
            element.CallEvent("onClientElementModelChange", Arguments, true);
        }
    };

    switch (m_eModelType)
    {
        case eClientModelType::PED:
        {
            // If some ped is using this ID, change him to CJ
            CClientPedManager* pPedManager = g_pClientGame->GetManager()->GetPedManager();

            unloadModelsAndCallEvents(pPedManager->IterBegin(), pPedManager->IterEnd(), 0, [](auto& element) { element.SetModel(0); });
            break;
        }
        case eClientModelType::OBJECT:
        {
            const auto&    objects = &g_pClientGame->GetManager()->GetObjectManager()->GetObjects();
            unsigned short usParentID = g_pGame->GetModelInfo(m_iModelID)->GetParentID();

            unloadModelsAndCallEvents(objects->begin(), objects->end(), usParentID, [=](auto& element) { element.SetModel(usParentID); });

            // Restore COL
            g_pClientGame->GetManager()->GetColModelManager()->RestoreModel(m_iModelID);
            break;
        }
        case eClientModelType::VEHICLE:
        {
            CClientVehicleManager* pVehicleManager = g_pClientGame->GetManager()->GetVehicleManager();
            unsigned short         usParentID = g_pGame->GetModelInfo(m_iModelID)->GetParentID();

            unloadModelsAndCallEvents(pVehicleManager->IterBegin(), pVehicleManager->IterEnd(), usParentID,
                                      [=](auto& element) { element.SetModelBlocking(usParentID, 255, 255); });
            break;
        }
    }

    // Restore DFF/TXD
    g_pClientGame->GetManager()->GetDFFManager()->RestoreModel(m_iModelID);
}
