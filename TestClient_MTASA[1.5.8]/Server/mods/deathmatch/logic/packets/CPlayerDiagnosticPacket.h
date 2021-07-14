/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        mods/deathmatch/logic/packets/CPlayerDiagnosticPacket.h
 *  PURPOSE:
 *
 *  Multi Theft Auto is available from http://www.multitheftauto.com/
 *
 *****************************************************************************/

#pragma once

class CPlayerDiagnosticPacket : public CPacket
{
public:
    ePacketID     GetPacketID() const { return PACKET_ID_PLAYER_DIAGNOSTIC; };
    unsigned long GetFlags() const { return 0; };            // Not used

    bool Read(NetBitStreamInterface& BitStream);

    uint    m_uiLevel;
    SString m_strMessage;
};
