/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *               (Shared logic for modifications)
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        mods/shared_logic/lua/CLuaFunctions.h
 *  PURPOSE:     Lua functions class header
 *
 *****************************************************************************/

class CLuaCFunctions;

#pragma once

#include "LuaCommon.h"
#include <string>

class CLuaCFunction
{
public:
    CLuaCFunction(const char* szName, lua_CFunction f, bool bRestricted);

    lua_CFunction GetFunctionAddress() const { return m_Function; };

    const char*    GetFunctionName() const { return m_strName.c_str(); };
    void           SetFunctionName(const char* szName) { m_strName = szName ? szName : ""; };
    const SString& GetName() { return m_strName; }

    bool IsRestricted() { return m_bRestricted; };

private:
    lua_CFunction m_Function;
    SString       m_strName;
    bool          m_bRestricted;
};

class CLuaCFunctions
{
public:
    static CLuaCFunction* AddFunction(const char* szName, lua_CFunction f, bool bRestricted = false);

    static CLuaCFunction* GetFunction(const char* szName, lua_CFunction f);
    static CLuaCFunction* GetFunction(const char* szName);
    static CLuaCFunction* GetFunction(lua_CFunction f);
    static const char*    GetFunctionName(lua_CFunction f, bool& bRestricted);
    static bool           IsNotFunction(lua_CFunction f);

    static bool IsRestricted(const char* szName);

    static void RegisterFunctionsWithVM(lua_State* luaVM);

    static void RemoveAllFunctions();
};
