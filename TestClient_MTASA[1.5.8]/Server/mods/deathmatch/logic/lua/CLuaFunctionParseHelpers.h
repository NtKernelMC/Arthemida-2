/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *               (Shared logic for modifications)
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        MTA10_Server/mods/deathmatch/logic/lua/CLuaFunctionParseHelpers.h
 *  PURPOSE:
 *
 *****************************************************************************/
#pragma once
#include "CElementIDs.h"
#include "CConsoleClient.h"

// Forward declare enum reflection stuff
enum eLuaType
{
};
DECLARE_ENUM(eLuaType);
DECLARE_ENUM(TrafficLight::EColor);
DECLARE_ENUM(TrafficLight::EState);
DECLARE_ENUM(CEasingCurve::eType);
DECLARE_ENUM(eWeaponType);
DECLARE_ENUM(eWeaponProperty);
DECLARE_ENUM(eWeaponSkill);
DECLARE_ENUM(eWeaponState);
DECLARE_ENUM(eWeaponFlags);
DECLARE_ENUM(CAccessControlListRight::ERightType);
DECLARE_ENUM(CElement::EElementType);
DECLARE_ENUM(CAccountPassword::EAccountPasswordType);
DECLARE_ENUM_CLASS(ESyncType);

enum eHudComponent
{
    HUD_AMMO,
    HUD_WEAPON,
    HUD_HEALTH,
    HUD_BREATH,
    HUD_ARMOUR,
    HUD_MONEY,
    HUD_VEHICLE_NAME,
    HUD_AREA_NAME,
    HUD_RADAR,
    HUD_CLOCK,
    HUD_RADIO,
    HUD_WANTED,
    HUD_CROSSHAIR,
    HUD_ALL,
};
DECLARE_ENUM(eHudComponent);

// class -> class type
typedef int        eEntityType;
inline eEntityType GetClassType(CElement*)
{
    return -1;
}
inline eEntityType GetClassType(class CPlayer*)
{
    return CElement::PLAYER;
}
inline eEntityType GetClassType(class CVehicle*)
{
    return CElement::VEHICLE;
}
inline eEntityType GetClassType(class CBlip*)
{
    return CElement::BLIP;
}
inline eEntityType GetClassType(class CObject*)
{
    return CElement::OBJECT;
}
inline eEntityType GetClassType(class CPickup*)
{
    return CElement::PICKUP;
}
inline eEntityType GetClassType(class CRadarArea*)
{
    return CElement::RADAR_AREA;
}
inline eEntityType GetClassType(class CMarker*)
{
    return CElement::MARKER;
}
inline eEntityType GetClassType(class CTeam*)
{
    return CElement::TEAM;
}
inline eEntityType GetClassType(class CPed*)
{
    return CElement::PED;
}
inline eEntityType GetClassType(class CColShape*)
{
    return CElement::COLSHAPE;
}
inline eEntityType GetClassType(class CDummy*)
{
    return CElement::DUMMY;
}
inline eEntityType GetClassType(class CScriptFile*)
{
    return CElement::SCRIPTFILE;
}
inline eEntityType GetClassType(class CWater*)
{
    return CElement::WATER;
}
inline eEntityType GetClassType(class CDatabaseConnectionElement*)
{
    return CElement::DATABASE_CONNECTION;
}
inline eEntityType GetClassType(class CCustomWeapon*)
{
    return CElement::WEAPON;
}

// class -> class name
inline SString GetClassTypeName(CElement*)
{
    return "element";
}
inline SString GetClassTypeName(CClient*)
{
    return "client";
}
inline SString GetClassTypeName(CPlayer*)
{
    return "player";
}
inline SString GetClassTypeName(CVehicle*)
{
    return "vehicle";
}
inline SString GetClassTypeName(CBlip*)
{
    return "blip";
}
inline SString GetClassTypeName(CObject*)
{
    return "object";
}
inline SString GetClassTypeName(CPickup*)
{
    return "pickup";
}
inline SString GetClassTypeName(CRadarArea*)
{
    return "radararea";
}
inline SString GetClassTypeName(CMarker*)
{
    return "marker";
}
inline SString GetClassTypeName(CTeam*)
{
    return "team";
}
inline SString GetClassTypeName(CPed*)
{
    return "ped";
}
inline SString GetClassTypeName(CRemoteCall*)
{
    return "remotecall";
}
inline SString GetClassTypeName(CColShape*) {
    return "colshape";
}
inline SString GetClassTypeName(CDummy*)
{
    return "dummy";
}
inline SString GetClassTypeName(CScriptFile*)
{
    return "scriptfile";
}
inline SString GetClassTypeName(CWater*)
{
    return "water";
}
inline SString GetClassTypeName(CDatabaseConnectionElement*)
{
    return "db-connection";
}

inline SString GetClassTypeName(CResource*)
{
    return "resource-data";
}
inline SString GetClassTypeName(CXMLNode*)
{
    return "xml-node";
}
inline SString GetClassTypeName(CLuaTimer*)
{
    return "lua-timer";
}
inline SString GetClassTypeName(CAccount*)
{
    return "account";
}
inline SString GetClassTypeName(CDbJobData*)
{
    return "db-query";
}
inline SString GetClassTypeName(CAccessControlList*)
{
    return "acl";
}
inline SString GetClassTypeName(CAccessControlListGroup*)
{
    return "acl-group";
}
inline SString GetClassTypeName(CCustomWeapon*)
{
    return "weapon";
}
inline SString GetClassTypeName(CBan*)
{
    return "ban";
}
inline SString GetClassTypeName(CTextItem*)
{
    return "text-item";
}
inline SString GetClassTypeName(CTextDisplay*)
{
    return "text-display";
}
inline SString GetClassTypeName(CLuaVector2D*)
{
    return "vector2";
}
inline SString GetClassTypeName(CLuaVector3D*)
{
    return "vector3";
}
inline SString GetClassTypeName(CLuaVector4D*)
{
    return "vector4";
}
inline SString GetClassTypeName(CLuaMatrix*)
{
    return "matrix";
}

//
// CResource from userdata
//
template <class T>
CResource* UserDataCast(CResource*, void* ptr, lua_State*)
{
    return g_pGame->GetResourceManager()->GetResourceFromScriptID(reinterpret_cast<unsigned long>(ptr));
}

//
// CXMLNode from userdata
//
template <class T>
CXMLNode* UserDataCast(CXMLNode*, void* ptr, lua_State*)
{
    return g_pServerInterface->GetXML()->GetNodeFromID(reinterpret_cast<unsigned long>(ptr));
}

//
// CLuaTimer from userdata
//
template <class T>
CLuaTimer* UserDataCast(CLuaTimer*, void* ptr, lua_State* luaVM)
{
    CLuaMain* pLuaMain = g_pGame->GetLuaManager()->GetVirtualMachine(luaVM);
    if (pLuaMain)
    {
        return pLuaMain->GetTimerManager()->GetTimerFromScriptID(reinterpret_cast<unsigned long>(ptr));
    }
    return NULL;
}

//
// CAccount from userdata
//
template <class T>
CAccount* UserDataCast(CAccount*, void* ptr, lua_State* luaVM)
{
    return g_pGame->GetAccountManager()->GetAccountFromScriptID(reinterpret_cast<unsigned long>(ptr));
}

//
// CDbJobData from userdata
//
template <class T>
CDbJobData* UserDataCast(CDbJobData*, void* ptr, lua_State*)
{
    return g_pGame->GetDatabaseManager()->GetQueryFromId(reinterpret_cast<SDbJobId>(ptr));
}

//
// CAccessControlList from userdata
//
template <class T>
CAccessControlList* UserDataCast(CAccessControlList*, void* ptr, lua_State*)
{
    return g_pGame->GetACLManager()->GetACLFromScriptID(reinterpret_cast<unsigned long>(ptr));
}

//
// CAccessControlListGroup from userdata
//
template <class T>
CAccessControlListGroup* UserDataCast(CAccessControlListGroup*, void* ptr, lua_State*)
{
    return g_pGame->GetACLManager()->GetGroupFromScriptID(reinterpret_cast<unsigned long>(ptr));
}

//
// CTextItem from userdata
//
template <class T>
CTextItem* UserDataCast(CTextItem*, void* ptr, lua_State* luaVM)
{
    CLuaMain* pLuaMain = g_pGame->GetLuaManager()->GetVirtualMachine(luaVM);
    if (pLuaMain)
    {
        return pLuaMain->GetTextItemFromScriptID(reinterpret_cast<unsigned long>(ptr));
    }
    return NULL;
}

//
// CTextDisplay from userdata
//
template <class T>
CTextDisplay* UserDataCast(CTextDisplay*, void* ptr, lua_State* luaVM)
{
    CLuaMain* pLuaMain = g_pGame->GetLuaManager()->GetVirtualMachine(luaVM);
    if (pLuaMain)
    {
        return pLuaMain->GetTextDisplayFromScriptID(reinterpret_cast<unsigned long>(ptr));
    }
    return NULL;
}

//
// CBan from userdata
//
template <class T>
CBan* UserDataCast(CBan*, void* ptr, lua_State*)
{
    return g_pGame->GetBanManager()->GetBanFromScriptID(reinterpret_cast<unsigned long>(ptr));
}

//
// CLuaVector2D from userdata
//
template <class T>
CLuaVector2D* UserDataCast(CLuaVector2D*, void* ptr, lua_State* luaVM)
{
    return CLuaVector2D::GetFromScriptID(reinterpret_cast<unsigned long>(ptr));
}

//
// CLuaVector3D from userdata
//
template <class T>
CLuaVector3D* UserDataCast(CLuaVector3D*, void* ptr, lua_State* luaVM)
{
    return CLuaVector3D::GetFromScriptID(reinterpret_cast<unsigned long>(ptr));
}

//
// CLuaVector4D from userdata
//
template <class T>
CLuaVector4D* UserDataCast(CLuaVector4D*, void* ptr, lua_State* luaVM)
{
    return CLuaVector4D::GetFromScriptID(reinterpret_cast<unsigned long>(ptr));
}

//
// CLuaMatrix from userdata
//
template <class T>
CLuaMatrix* UserDataCast(CLuaMatrix*, void* ptr, lua_State* luaVM)
{
    return CLuaMatrix::GetFromScriptID(reinterpret_cast<unsigned long>(ptr));
}

//
// CElement from userdata
//
template <class T>
CElement* UserDataCast(CElement*, void* ptr, lua_State*)
{
    ElementID ID = TO_ELEMENTID(ptr);
    CElement* pElement = CElementIDs::GetElement(ID);
    if (!pElement || pElement->IsBeingDeleted() || (pElement->GetType() != GetClassType((T*)0) && GetClassType((T*)0) != -1))
        return NULL;
    return pElement;
}

//
// CPed from userdata
//
// Will now properly convert CPlayers to CPeds
template <class T>
CPed* UserDataCast(CPed*, void* ptr, lua_State*)
{
    ElementID ID = TO_ELEMENTID(ptr);
    CElement* pElement = CElementIDs::GetElement(ID);
    if (!pElement || pElement->IsBeingDeleted() || (pElement->GetType() != CElement::PED && pElement->GetType() != CElement::PLAYER))
        return NULL;
    return (CPed*)pElement;
}

//
// CRemoteCall from userdata
//
template <class T>
CRemoteCall* UserDataCast(CRemoteCall*, void* ptr, lua_State*)
{
    CRemoteCall* pRemoteCall = (CRemoteCall*)ptr;

    if (pRemoteCall && g_pGame->GetRemoteCalls()->CallExists(pRemoteCall))
        return pRemoteCall;

    return nullptr;
}

//
// CPlayer from userdata
//
// Disallows conversion of CPeds to CPlayers
//
template <class T>
CPlayer* UserDataCast(CPlayer*, void* ptr, lua_State*)
{
    ElementID ID = TO_ELEMENTID(ptr);
    CElement* pElement = CElementIDs::GetElement(ID);
    if (!pElement || pElement->IsBeingDeleted() || (pElement->GetType() != CElement::PLAYER))
        return NULL;
    return (CPlayer*)pElement;
}

// CClient from CConsoleClient or a CPlayer
template <class T>
CClient* UserDataCast(CClient*, void* ptr, lua_State*)
{
    ElementID ID = TO_ELEMENTID(ptr);
    CElement* pElement = CElementIDs::GetElement(ID);
    if (!pElement || pElement->IsBeingDeleted())
        return nullptr;

    CClient* pClient = nullptr;
    if (pElement->GetType() == CElement::PLAYER)
        pClient = reinterpret_cast<CPlayer*>(pElement);
    else if (pElement->GetType() == CElement::CONSOLE)
        pClient = reinterpret_cast<CConsoleClient*>(pElement);

    return pClient;
}

//
// CElement ( something )
//
// Returns true if T is the same class as the one wrapped by pElement
template <class T>
bool CheckWrappedUserDataType(CElement*& pElement, SString& strErrorExpectedType)
{
    // Not used server side (yet)
    strErrorExpectedType = GetClassTypeName((T*)0);
    return false;
}

//
// Get element from ID and ensure type is what is expected
//
template <class T>
T* GetElementFromId(ElementID elementId)
{
    CElement* pElement = CElementIDs::GetElement(elementId);
    if (!pElement || pElement->IsBeingDeleted() || (pElement->GetType() != GetClassType((T*)0) && GetClassType((T*)0) != -1))
        return NULL;
    return (T*)pElement;
}

class CScriptArgReader;
SString GetUserDataClassName(void* ptr, lua_State* luaVM, bool bFindElementType = true);
void    MixedReadResourceString(CScriptArgReader& argStream, SString& strOutResourceName);
void    MixedReadResourceString(CScriptArgReader& argStream, CResource*& pOutResource);
bool    StringToBool(const SString& strText);
void    MinServerReqCheck(CScriptArgReader& argStream, const char* szVersionReq, const char* szReason);
void    ReadPregFlags(CScriptArgReader& argStream, pcrecpp::RE_Options& pOptions);
bool    ReadMatrix(lua_State* luaVM, uint uiArgIndex, CMatrix& outMatrix);

//
// Resource access helpers
//
enum class eResourceModifyScope
{
    NONE,
    SINGLE_RESOURCE,
    EVERY_RESOURCE,
};

eResourceModifyScope GetResourceModifyScope(CResource* pThisResource, CResource* pOtherResource);
void                 CheckCanModifyOtherResource(CScriptArgReader& argStream, CResource* pThisResource, CResource* pOtherResource);
void                 CheckCanModifyOtherResources(CScriptArgReader& argStream, CResource* pThisResource, std::initializer_list<CResource*> resourceList);
void CheckCanAccessOtherResourceFile(CScriptArgReader& argStream, CResource* pThisResource, CResource* pOtherResource, const SString& strAbsPath,
                                     bool* pbReadOnly = nullptr);

//
// Other misc helpers
//
bool IsWeaponPropertyFlag(eWeaponProperty weaponProperty);
uint GetWeaponPropertyFlagBit(eWeaponProperty weaponProperty);
