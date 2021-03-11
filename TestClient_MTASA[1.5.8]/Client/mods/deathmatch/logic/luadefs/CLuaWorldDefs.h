/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto
 *  LICENSE:     See LICENSE in the top level directory
 *
 *  Multi Theft Auto is available from http://www.multitheftauto.com/
 *
 *****************************************************************************/

#pragma once
#include "CLuaDefs.h"

class CLuaWorldDefs : public CLuaDefs
{
public:
    static void LoadFunctions();

    LUA_DECLARE(GetTime);
    LUA_DECLARE(GetGroundPosition);
    LUA_DECLARE(GetRoofPosition);
    LUA_DECLARE(ProcessLineOfSight);
    LUA_DECLARE(IsLineOfSightClear);
    LUA_DECLARE(GetWorldFromScreenPosition);
    LUA_DECLARE(GetScreenFromWorldPosition);
    LUA_DECLARE(GetWeather);
    LUA_DECLARE(GetZoneName);
    LUA_DECLARE(GetGravity);
    LUA_DECLARE(GetGameSpeed);
    LUA_DECLARE(GetMinuteDuration);
    LUA_DECLARE(GetWaveHeight);
    LUA_DECLARE(IsGarageOpen);
    LUA_DECLARE(GetGaragePosition);
    LUA_DECLARE(GetGarageSize);
    LUA_DECLARE(GetGarageBoundingBox);
    LUA_DECLARE(IsWorldSpecialPropertyEnabled);
    LUA_DECLARE(GetBlurLevel);
    LUA_DECLARE(GetTrafficLightState);
    LUA_DECLARE(AreTrafficLightsLocked);
    LUA_DECLARE(GetJetpackMaxHeight);
    LUA_DECLARE(GetAircraftMaxHeight);
    LUA_DECLARE(GetAircraftMaxVelocity);
    LUA_DECLARE(GetOcclusionsEnabled);

    LUA_DECLARE(SetTime);
    LUA_DECLARE(GetSkyGradient);
    LUA_DECLARE(SetSkyGradient);
    LUA_DECLARE(ResetSkyGradient);
    LUA_DECLARE(GetHeatHaze);
    LUA_DECLARE(SetHeatHaze);
    LUA_DECLARE(ResetHeatHaze);
    LUA_DECLARE(SetWeather);
    LUA_DECLARE(SetWeatherBlended);
    LUA_DECLARE(SetGravity);
    LUA_DECLARE(SetGameSpeed);
    LUA_DECLARE(SetMinuteDuration);
    LUA_DECLARE(SetWaveHeight);
    LUA_DECLARE(SetGarageOpen);
    LUA_DECLARE(SetWorldSpecialPropertyEnabled);
    LUA_DECLARE(SetBlurLevel);
    LUA_DECLARE(ResetBlurLevel);
    LUA_DECLARE(SetJetpackMaxHeight);
    LUA_DECLARE(SetCloudsEnabled);
    LUA_DECLARE(GetCloudsEnabled);
    LUA_DECLARE(SetTrafficLightState);
    LUA_DECLARE(SetTrafficLightsLocked);
    LUA_DECLARE(GetWindVelocity);
    LUA_DECLARE(SetWindVelocity);
    LUA_DECLARE(ResetWindVelocity);
    LUA_DECLARE(GetInteriorSoundsEnabled);
    LUA_DECLARE(SetInteriorSoundsEnabled);
    LUA_DECLARE(GetInteriorFurnitureEnabled);
    LUA_DECLARE(SetInteriorFurnitureEnabled);
    LUA_DECLARE(GetRainLevel);
    LUA_DECLARE(SetRainLevel);
    LUA_DECLARE(ResetRainLevel);
    LUA_DECLARE(GetFarClipDistance);
    LUA_DECLARE(SetFarClipDistance);
    LUA_DECLARE(ResetFarClipDistance);
    LUA_DECLARE(GetNearClipDistance);
    LUA_DECLARE(SetNearClipDistance);
    LUA_DECLARE(ResetNearClipDistance);
    LUA_DECLARE(GetVehiclesLODDistance);
    LUA_DECLARE(SetVehiclesLODDistance);
    LUA_DECLARE(ResetVehiclesLODDistance);
    LUA_DECLARE(GetPedsLODDistance);
    LUA_DECLARE(SetPedsLODDistance);
    LUA_DECLARE(ResetPedsLODDistance);
    LUA_DECLARE(GetFogDistance);
    LUA_DECLARE(SetFogDistance);
    LUA_DECLARE(ResetFogDistance);
    LUA_DECLARE(GetSunColor);
    LUA_DECLARE(SetSunColor);
    LUA_DECLARE(ResetSunColor);
    LUA_DECLARE(GetSunSize);
    LUA_DECLARE(SetSunSize);
    LUA_DECLARE(ResetSunSize);
    LUA_DECLARE(RemoveWorldBuilding);
    LUA_DECLARE(RestoreWorldBuildings);
    LUA_DECLARE(RestoreWorldBuilding);
    LUA_DECLARE(SetAircraftMaxHeight);
    LUA_DECLARE(SetAircraftMaxVelocity);
    LUA_DECLARE(SetOcclusionsEnabled);
    LUA_DECLARE(CreateSWATRope);
    LUA_DECLARE(SetBirdsEnabled);
    LUA_DECLARE(GetBirdsEnabled);
    LUA_DECLARE(SetPedTargetingMarkerEnabled);
    LUA_DECLARE(IsPedTargetingMarkerEnabled);
    LUA_DECLARE(SetMoonSize);
    LUA_DECLARE(GetMoonSize);
    LUA_DECLARE(ResetMoonSize);
    LUA_DECLARE(SetFPSLimit);
    LUA_DECLARE(GetFPSLimit);

    LUA_DECLARE(CreateExplosion);

    static bool ResetColorFilter();
    static bool SetColorFilter(uchar ucPass0Red, uchar ucPass0Green, uchar ucPass0Blue, uchar ucPass0Alpha,
        uchar ucPass1Red, uchar ucPass1Green, uchar ucPass1Blue, uchar ucPass1Alpha);
};
