/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        game_sa/CMonsterTruckSA.cpp
 *  PURPOSE:     Monster truck vehicle entity
 *
 *  Multi Theft Auto is available from http://www.multitheftauto.com/
 *
 *****************************************************************************/

#include "StdInc.h"

CMonsterTruckSA::CMonsterTruckSA(CMonsterTruckSAInterface* monstertruck) : CAutomobileSA(monstertruck)
{
    DEBUG_TRACE("CMonsterTruckSA::CMonsterTruckSA( CMonsterTruckSAInterface * monstertruck )");
    this->m_pInterface = monstertruck;
}

CMonsterTruckSA::CMonsterTruckSA(eVehicleTypes dwModelID, unsigned char ucVariation, unsigned char ucVariation2)
    : CAutomobileSA(dwModelID, ucVariation, ucVariation2)
{
    DEBUG_TRACE("CMonsterTruckSA::CMonsterTruckSA( eVehicleTypes dwModelID ):CVehicleSA( dwModelID )");
}
