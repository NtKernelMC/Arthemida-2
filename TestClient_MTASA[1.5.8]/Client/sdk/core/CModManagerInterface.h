/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        sdk/core/CModManagerInterface.h
 *  PURPOSE:     Game mod manager interface
 *
 *  Multi Theft Auto is available from http://www.multitheftauto.com/
 *
 *****************************************************************************/

#pragma once

class CClientBase;

class CModManagerInterface
{
public:
    virtual void RequestLoad(const char* szModName, const char* szArguments) = 0;
    virtual void RequestLoadDefault(const char* szArguments) = 0;
    virtual void RequestUnload() = 0;

    virtual bool         IsLoaded() = 0;
    virtual CClientBase* GetCurrentMod() = 0;
};
