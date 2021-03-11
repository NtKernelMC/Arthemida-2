/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        Shared/mods/logic/luadefs/CLuaCryptDefs.h
 *
 *  Multi Theft Auto is available from http://www.multitheftauto.com/
 *
 *****************************************************************************/

#pragma once
#include "luadefs/CLuaDefs.h"
#include <optional>
#include <variant>

class CLuaCryptDefs : public CLuaDefs
{
public:
    static void LoadFunctions();

    static std::string Md5(std::string strMd5);

    static std::string Hash(EHashFunctionType hashFunction, std::string strSourceData);

    static std::string TeaEncode(std::string str, std::string key);
    static std::string TeaDecode(std::string str, std::string key);
    static std::string Base64encode(std::string str);
    static std::string Base64decode(std::string str);
    LUA_DECLARE(PasswordHash);
    static std::string Sha256(std::string strSourceData);
    LUA_DECLARE(PasswordVerify);
    LUA_DECLARE(EncodeString);
    LUA_DECLARE(DecodeString);
};
