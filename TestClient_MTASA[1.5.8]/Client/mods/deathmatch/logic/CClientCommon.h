/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto
 *               (Shared logic for modifications)
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        mods/logic/CClientCommon.h
 *  PURPOSE:     Common definitions
 *
 *****************************************************************************/

#pragma once

// Defines the maximum amount of mimics (fake players)
#define MAX_MIMICS                      50

// Defines the maximum amount of real players
#define MAX_NET_PLAYERS_REAL            250

// Defines the maximum amount of players inside the game (includes mimics)
#define MAX_NET_PLAYERS                 (MAX_NET_PLAYERS_REAL + MAX_MIMICS)

// Defines the min/max size for the player nick (who the hell came up with 22?)
#define MIN_PLAYER_NICK_LENGTH          1
#define MAX_PLAYER_NICK_LENGTH          22

// Defines the min/max size for the player nametag (who the hell came up with 22?)
#define MIN_PLAYER_NAMETAG_LENGTH       1
#define MAX_PLAYER_NAMETAG_LENGTH       64

#define MAX_TEAM_NAME_LENGTH            255

// Defines the minimum fade time for a transfer
#define MIN_TRANSFER_TIME               1500

// Defines the maximum size for a player name
//#define MAX_PLAYER_NAME_LENGTH        32

// Defines the maximum size for a HTTP Download URL
#define MAX_HTTP_DOWNLOAD_URL           512

// Defines the maximum size for a HTTP Download URL (with file / directory information appended)
#define MAX_HTTP_DOWNLOAD_URL_WITH_FILE 768

enum eHTTPDownloadType
{
    HTTP_DOWNLOAD_DISABLED = 0,
    HTTP_DOWNLOAD_ENABLED_PORT,
    HTTP_DOWNLOAD_ENABLED_URL
};

#define CHATCOLOR_DEFAULT   235, 221, 178
#define CHATCOLOR_INFO      255, 100, 100

// Interfaces to Blue
extern CCoreInterface* g_pCore;
extern CGame*          g_pGame;
extern CMultiplayer*   g_pMultiplayer;
extern CNet*           g_pNet;
