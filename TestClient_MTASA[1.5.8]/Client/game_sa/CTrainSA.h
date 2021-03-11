/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        game_sa/CTrainSA.h
 *
 *  Multi Theft Auto is available from http://www.multitheftauto.com/
 *
 *****************************************************************************/

#pragma once
#include "CVehicleSA.h"
#include "CDoorSA.h"

namespace eTrainNode
{
    enum
    {
        NONE = 0,
        DOOR_LF = 1,
        DOOR_RF = 2,
        WHEEL_RF1 = 3,
        WHEEL_RF2 = 4,
        WHEEL_RF3 = 5,
        WHEEL_RB1 = 6,
        WHEEL_RB2 = 7,
        WHEEL_RB3 = 8,
        WHEEL_LF1 = 9,
        WHEEL_LF2 = 10,
        WHEEL_LF3 = 11,
        WHEEL_LB1 = 12,
        WHEEL_LB2 = 13,
        WHEEL_LB3 = 14,
        BOGIE_FRONT = 15,
        BOGIE_REAR = 16,
        NUM_NODES
    };
};

enum class eTrainPassengersGenerationState : unsigned char
{
    QUERY_NUM_PASSENGERS_TO_LEAVE = 0,
    TELL_PASSENGERS_TO_LEAVE = 1,
    QUERY_NUM_PASSENGERS_TO_ENTER = 2,
    TELL_PASSENGERS_TO_ENTER = 3,
    GENERATION_FINISHED = 4
};

class CTrainSAInterface : public CVehicleSAInterface
{
public:
    short m_ucTrackNodeID;

private:
    char _pad1[2];

public:
    float m_fTrainSpeed;                   // 1.0 - train derails
    float m_fTrainRailDistance;            // Distance along rail starting from first rail node (determines train position when on rails)
    float m_fDistanceToNextCarriage;
    float m_fTrainGas;              // gas pedal pressed: 255.0, moving forward: 0.0, moving back: -255.0
    float m_fTrainBrake;            // 255.0 - braking
    union
    {
        struct
        {
            unsigned short b01 : 1;                          // initialised with 1
            unsigned short bStoppedAtStation : 1;            // Only the first created train on the chain gets this set to true, others get it set to false.
            unsigned short bPassengersCanEnterAndLeave : 1;
            unsigned short bIsTheChainEngine : 1;            // front carriage
            unsigned short bIsLastCarriage : 1;
            unsigned short bMissionTrain : 1;
            unsigned short bClockwiseDirection : 1;
            unsigned short bStopsAtStations : 1;

            unsigned short bIsDerailed : 1;
            unsigned short bForceSlowDown : 1;
            unsigned short bIsStreakModel : 1;
        } trainFlags;
    };

private:
    char _pad5BA[2];

public:
    int           m_uiLastTimeUpdated;
    unsigned char m_ucRailTrackID;

private:
    char _pad5C1[3];

public:
    int                             m_nTimeWhenCreated;
    short                           field_5C8;            // initialized with 0, not referenced
    eTrainPassengersGenerationState m_nPassengersGenerationState;
    unsigned char                   m_nNumPassengersToLeave : 4;            // 0 to 4
    unsigned char                   m_nNumPassengersToEnter : 4;            // 0 to 4
    CPedSAInterface*                m_pTemporaryPassenger;                  // we tell peds to enter train and then delete them
    CTrainSAInterface*              m_prevCarriage;
    CTrainSAInterface*              m_nextCarriage;
    CDoorSAInterface                m_aDoors[MAX_DOORS];
    RwFrame*                        m_aTrainNodes[eTrainNode::NUM_NODES];
};
static_assert(sizeof(CTrainSAInterface) == 0x6AC, "Invalid size for CTrainSAInterface");
