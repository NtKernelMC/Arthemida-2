/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *               (Shared logic for modifications)
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        mods/shared_logic/lua/CLuaFunctionDefs.Event.cpp
 *  PURPOSE:     Lua function definitions class
 *
 *****************************************************************************/

#include "StdInc.h"

int CLuaFunctionDefs::AddEvent(lua_State* luaVM)
{
    //  bool addEvent ( string eventName [, bool allowRemoteTrigger = false ] )
    SString strName;
    bool    bAllowRemoteTrigger;

    CScriptArgReader argStream(luaVM);
    argStream.ReadString(strName);
    argStream.ReadBool(bAllowRemoteTrigger, false);

    if (!argStream.HasErrors())
    {
        // Grab our virtual machine
        CLuaMain* pLuaMain = m_pLuaManager->GetVirtualMachine(luaVM);
        if (pLuaMain)
        {
            // Do it
            if (CStaticFunctionDefinitions::AddEvent(*pLuaMain, strName, bAllowRemoteTrigger))
            {
                lua_pushboolean(luaVM, true);
                return 1;
            }
        }
    }
    else
        m_pScriptDebugging->LogCustom(luaVM, argStream.GetFullErrorMessage());

    // Failed
    lua_pushboolean(luaVM, false);
    return 1;
}

int CLuaFunctionDefs::AddEventHandler(lua_State* luaVM)
{
    //  bool addEventHandler ( string eventName, element attachedTo, function handlerFunction [, bool getPropagated = true, string priority = "normal" ] )
    SString         strName;
    CClientEntity*  pEntity;
    CLuaFunctionRef iLuaFunction;
    bool            bPropagated;
    SString         strPriority;

    CScriptArgReader argStream(luaVM);
    argStream.ReadString(strName);
    argStream.ReadUserData(pEntity);
    argStream.ReadFunction(iLuaFunction);
    argStream.ReadBool(bPropagated, true);
    argStream.ReadString(strPriority, "normal");
    argStream.ReadFunctionComplete();

    // Check if strPriority has a number as well. e.g. name+1 or name-1.32
    float              fPriorityMod = 0;
    EEventPriorityType eventPriority;
    {
        uint iPos = strPriority.find_first_of("-+");
        if (iPos != SString::npos)
        {
            fPriorityMod = (float)atof(strPriority.SubStr(iPos));
            strPriority = strPriority.Left(iPos);
        }

        if (!StringToEnum(strPriority, eventPriority))
            argStream.SetTypeError(GetEnumTypeName(eventPriority), 5);            // priority is argument #5
    }

    if (!argStream.HasErrors())
    {
        // Grab our virtual machine
        CLuaMain* pLuaMain = m_pLuaManager->GetVirtualMachine(luaVM);
        if (pLuaMain)
        {
            // Check if the handle is in use
            if (pEntity->GetEventManager()->HandleExists(pLuaMain, strName, iLuaFunction))
            {
                argStream.SetCustomError(SString("'%s' with this function is already handled", *strName));
            }
            else
            {
                // Do it
                if (CStaticFunctionDefinitions::AddEventHandler(*pLuaMain, strName, *pEntity, iLuaFunction, bPropagated, eventPriority, fPriorityMod))
                {
                    lua_pushboolean(luaVM, true);
                    return 1;
                }
            }
        }
    }
    if (argStream.HasErrors())
        m_pScriptDebugging->LogCustom(luaVM, argStream.GetFullErrorMessage());

    // Failed
    lua_pushboolean(luaVM, false);
    return 1;
}

int CLuaFunctionDefs::RemoveEventHandler(lua_State* luaVM)
{
    //  bool removeEventHandler ( string eventName, element attachedTo, function functionVar )
    SString         strName;
    CClientEntity*  pEntity;
    CLuaFunctionRef iLuaFunction;

    CScriptArgReader argStream(luaVM);
    argStream.ReadString(strName);
    argStream.ReadUserData(pEntity);
    argStream.ReadFunction(iLuaFunction);
    argStream.ReadFunctionComplete();

    if (!argStream.HasErrors())
    {
        // Grab our virtual machine
        CLuaMain* pLuaMain = m_pLuaManager->GetVirtualMachine(luaVM);
        if (pLuaMain)
        {
            // Do it
            if (CStaticFunctionDefinitions::RemoveEventHandler(*pLuaMain, strName, *pEntity, iLuaFunction))
            {
                lua_pushboolean(luaVM, true);
                return 1;
            }
        }
    }
    else
        m_pScriptDebugging->LogCustom(luaVM, argStream.GetFullErrorMessage());

    // Failed
    lua_pushboolean(luaVM, false);
    return 1;
}

int CLuaFunctionDefs::GetEventHandlers(lua_State* luaVM)
{
    //  table getEventHandlers ( string eventName, element attachedTo )
    SString        strName;
    CClientEntity* pElement;

    CScriptArgReader argStream(luaVM);
    argStream.ReadString(strName);
    argStream.ReadUserData(pElement);

    if (!argStream.HasErrors())
    {
        // Grab our virtual machine
        CLuaMain* pLuaMain = m_pLuaManager->GetVirtualMachine(luaVM);
        if (pLuaMain)
        {
            // Create a new table
            lua_newtable(luaVM);

            pElement->GetEventManager()->GetHandles(pLuaMain, (const char*)strName, luaVM);

            return 1;
        }
    }
    else
        m_pScriptDebugging->LogCustom(luaVM, argStream.GetFullErrorMessage());

    // Failed
    lua_pushboolean(luaVM, false);
    return 1;
}

int CLuaFunctionDefs::TriggerEvent(lua_State* luaVM)
{
    //  bool triggerEvent ( string eventName, element baseElement, [ var argument1, ... ] )
    SString        strName;
    CClientEntity* pEntity;
    CLuaArguments  Arguments;

    CScriptArgReader argStream(luaVM);
    argStream.ReadString(strName);
    argStream.ReadUserData(pEntity);
    argStream.ReadLuaArguments(Arguments);

    if (!argStream.HasErrors())
    {
        // Trigger it
        bool bWasCancelled;
        if (CStaticFunctionDefinitions::TriggerEvent(strName, *pEntity, Arguments, bWasCancelled))
        {
            lua_pushboolean(luaVM, !bWasCancelled);
            return 1;
        }
    }
    else
        m_pScriptDebugging->LogCustom(luaVM, argStream.GetFullErrorMessage());

    // Error
    lua_pushnil(luaVM);
    return 1;
}

int CLuaFunctionDefs::TriggerServerEvent(lua_State* luaVM)
{
    //  bool triggerServerEvent ( string event, element theElement, [arguments...] )
    SString        strName;
    CClientEntity* pCallWithEntity;
    CLuaArguments  Arguments;

    CScriptArgReader argStream(luaVM);
    argStream.ReadString(strName);
    argStream.ReadUserData(pCallWithEntity);
    argStream.ReadLuaArguments(Arguments);

    if (!argStream.HasErrors())
    {
        if (!pCallWithEntity->IsLocalEntity())
        {
            if (CStaticFunctionDefinitions::TriggerServerEvent(strName, *pCallWithEntity, Arguments))
            {
                lua_pushboolean(luaVM, true);
            }
            else
            {
                lua_pushboolean(luaVM, false);

                // Show a warning for clientside elements in the argument chain
                for (uint i = 0; i < Arguments.Count(); ++i)
                {
                    CLuaArgument* pArgument = Arguments[i];

                    if (!pArgument)
                        continue;

                    if (pArgument->GetType() != LUA_TLIGHTUSERDATA && pArgument->GetType() != LUA_TUSERDATA)
                        continue;

                    CClientEntity* pEntity = pArgument->GetElement();

                    if (pEntity && !pEntity->IsLocalEntity())
                        continue;

                    // Extra arguments begin at argument 3
                    if (pEntity)
                    {
                        m_pScriptDebugging->LogError(luaVM, "clientside element '%s' at argument %u @ 'triggerServerEvent'", 
                                                     pEntity->GetTypeName().c_str(), i + 3);
                    }
                    else
                    {
                        m_pScriptDebugging->LogError(luaVM, "userdata at argument %u @ 'triggerServerEvent'", i + 3);
                    }
                }
            }

            return 1;
        }

        argStream.SetCustomError("element is clientside", "Bad source element");
    }
    
    if (argStream.HasErrors())
        m_pScriptDebugging->LogCustom(luaVM, argStream.GetFullErrorMessage());

    lua_pushboolean(luaVM, false);
    return 1;
}

int CLuaFunctionDefs::CancelEvent(lua_State* luaVM)
{
    // Cancel it
    if (CStaticFunctionDefinitions::CancelEvent(true))
    {
        lua_pushboolean(luaVM, true);
        return 1;
    }

    // Failed
    lua_pushboolean(luaVM, false);
    return 1;
}

int CLuaFunctionDefs::WasEventCancelled(lua_State* luaVM)
{
    // Return whether the last event was cancelled or not
    lua_pushboolean(luaVM, CStaticFunctionDefinitions::WasEventCancelled());
    return 1;
}

int CLuaFunctionDefs::TriggerLatentServerEvent(lua_State* luaVM)
{
    //  int triggerLatentServerEvent ( string event, [int bandwidth=5000,] [bool persist=false,] element theElement, [arguments...] )
    SString        strName;
    int            iBandwidth;
    bool           bPersist;
    CClientEntity* pCallWithEntity;
    CLuaArguments  Arguments;

    CScriptArgReader argStream(luaVM);
    argStream.ReadString(strName);
    argStream.ReadIfNextCouldBeNumber(iBandwidth, 5000);
    argStream.ReadIfNextIsBool(bPersist, false);
    argStream.ReadUserData(pCallWithEntity);
    argStream.ReadLuaArguments(Arguments);

    if (!argStream.HasErrors())
    {
        // Get resource details if transfer should be stopped when resource stops
        CLuaMain* pLuaMain = NULL;
        ushort    usResourceNetId = 0xFFFF;
        if (!bPersist)
        {
            pLuaMain = m_pLuaManager->GetVirtualMachine(luaVM);
            if (pLuaMain)
            {
                CResource* pResource = pLuaMain->GetResource();
                if (pResource)
                {
                    usResourceNetId = pResource->GetNetID();
                }
            }
        }

        // Trigger it
        if (CStaticFunctionDefinitions::TriggerLatentServerEvent(strName, *pCallWithEntity, Arguments, iBandwidth, pLuaMain, usResourceNetId))
        {
            lua_pushboolean(luaVM, true);
            return 1;
        }
    }
    else
        m_pScriptDebugging->LogCustom(luaVM, argStream.GetFullErrorMessage());

    // Failed
    lua_pushboolean(luaVM, false);
    return 1;
}

int CLuaFunctionDefs::GetLatentEventHandles(lua_State* luaVM)
{
    //  table getLatentEventHandles ()
    CScriptArgReader argStream(luaVM);

    if (!argStream.HasErrors())
    {
        std::vector<uint> resultList;
        g_pClientGame->GetLatentTransferManager()->GetSendHandles(0, resultList);

        lua_createtable(luaVM, 0, resultList.size());
        for (uint i = 0; i < resultList.size(); i++)
        {
            lua_pushnumber(luaVM, i + 1);
            lua_pushnumber(luaVM, resultList[i]);
            lua_settable(luaVM, -3);
        }
        return 1;
    }
    else
        m_pScriptDebugging->LogCustom(luaVM, argStream.GetFullErrorMessage());

    // Failed
    lua_pushboolean(luaVM, false);
    return 1;
}

int CLuaFunctionDefs::GetLatentEventStatus(lua_State* luaVM)
{
    //  int start,end = getLatentEventStatus ( int handle )
    int iHandle;

    CScriptArgReader argStream(luaVM);
    argStream.ReadNumber(iHandle);

    if (!argStream.HasErrors())
    {
        SSendStatus sendStatus;
        if (g_pClientGame->GetLatentTransferManager()->GetSendStatus(0, iHandle, &sendStatus))
        {
            lua_createtable(luaVM, 0, 4);

            lua_pushstring(luaVM, "tickStart");
            lua_pushinteger(luaVM, sendStatus.iStartTimeMsOffset);
            lua_settable(luaVM, -3);

            lua_pushstring(luaVM, "tickEnd");
            lua_pushinteger(luaVM, sendStatus.iEndTimeMsOffset);
            lua_settable(luaVM, -3);

            lua_pushstring(luaVM, "totalSize");
            lua_pushinteger(luaVM, sendStatus.iTotalSize);
            lua_settable(luaVM, -3);

            lua_pushstring(luaVM, "percentComplete");
            lua_pushnumber(luaVM, sendStatus.dPercentComplete);
            lua_settable(luaVM, -3);
            return 1;
        }
    }
    else
        m_pScriptDebugging->LogCustom(luaVM, argStream.GetFullErrorMessage());

    // Failed
    lua_pushboolean(luaVM, false);
    return 1;
}

int CLuaFunctionDefs::CancelLatentEvent(lua_State* luaVM)
{
    //  bool cancelLatentEvent ( int handle )
    int iHandle;

    CScriptArgReader argStream(luaVM);
    argStream.ReadNumber(iHandle);

    if (!argStream.HasErrors())
    {
        if (g_pClientGame->GetLatentTransferManager()->CancelSend(0, iHandle))
        {
            lua_pushboolean(luaVM, true);
            return 1;
        }
    }
    else
        m_pScriptDebugging->LogCustom(luaVM, argStream.GetFullErrorMessage());

    // Failed
    lua_pushboolean(luaVM, false);
    return 1;
}
