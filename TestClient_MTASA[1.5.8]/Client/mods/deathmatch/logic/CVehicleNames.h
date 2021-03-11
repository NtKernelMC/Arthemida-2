/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *               (Shared logic for modifications)
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        mods/shared_logic/CVehicleNames.h
 *  PURPOSE:     Vehicle names class header
 *
 *****************************************************************************/

#pragma once

class CVehicleNames
{
public:
    static bool IsValidModel(unsigned long ulModel);
    static bool IsModelTrailer(unsigned long ulModel);

    static const char*  GetVehicleName(unsigned long ulModel);
    static unsigned int GetVehicleModel(const char* szName);

    static const char* GetVehicleTypeName(unsigned long ulModel);
};
