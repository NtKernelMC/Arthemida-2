/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        sdk/game/CBoat.h
 *  PURPOSE:     Boat vehicle interface
 *
 *  Multi Theft Auto is available from http://www.multitheftauto.com/
 *
 *****************************************************************************/

#pragma once

#include "CVehicle.h"

class CBoat : public virtual CVehicle
{
public:
    virtual ~CBoat(){};

    virtual CBoatHandlingEntry* GetBoatHandlingData() = 0;
    virtual void                SetBoatHandlingData(CBoatHandlingEntry* pHandling) = 0;
};
