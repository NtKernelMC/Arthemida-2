/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        mods/deathmatch/logic/CLanBroadcast.h
 *  PURPOSE:     LAN server broadcasting class
 *
 *  Multi Theft Auto is available from http://www.multitheftauto.com/
 *
 *****************************************************************************/

class CLanBroadcastDLL;

#pragma once

#include <Common.h>
#include <iostream>
#include <string>
#include <sstream>

#ifdef WIN32
    #include <conio.h>
#else
    #include <sys/socket.h>
    #include <sys/stat.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #define closesocket close
#endif

class CLanBroadcast
{
public:
    CLanBroadcast(unsigned short usServerPort);
    ~CLanBroadcast();

    void DoPulse();

    unsigned short GetPort() { return SERVER_LIST_BROADCAST_PORT; };

private:
    unsigned int m_Socket;
    sockaddr_in  m_SockAddr;

    std::string m_strClientMessage;
    std::string m_strServerMessage;
};
