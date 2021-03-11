/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        mods/deathmatch/logic/packets/CConsoleEchoPacket.cpp
 *  PURPOSE:     Console message echo packet class
 *
 *  Multi Theft Auto is available from http://www.multitheftauto.com/
 *
 *****************************************************************************/

#include "StdInc.h"

bool CConsoleEchoPacket::Write(NetBitStreamInterface& BitStream) const
{
    // Not too short?
    size_t sizeMessage = m_strMessage.length();
    if (sizeMessage >= MIN_CONSOLEECHO_LENGTH)
    {
        // Write the string
        BitStream.WriteStringCharacters(m_strMessage, sizeMessage);
        return true;
    }

    return false;
}
