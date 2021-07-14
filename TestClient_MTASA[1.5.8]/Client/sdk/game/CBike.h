/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        sdk/game/CBike.h
 *  PURPOSE:     Bike vehicle entity interface
 *
 *  Multi Theft Auto is available from http://www.multitheftauto.com/
 *
 *****************************************************************************/

#pragma once

#include "CVehicle.h"

class CBike : public virtual CVehicle
{
public:
    virtual ~CBike(){};

    // virtual void PlaceOnRoadProperly ( void )=0;
};
