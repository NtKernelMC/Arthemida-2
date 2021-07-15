/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        game_sa/CFxSystemSA.h
 *  PURPOSE:     Game effects interface
 *
 *  Multi Theft Auto is available from http://www.multitheftauto.com/
 *
 *****************************************************************************/

#pragma once

#include <game/CFxSystem.h>

#define FUNC_FxSystem_c__AddParticle            0x004AA440
#define FUNC_FxSystem_c__AttachToBone           0x004AA400
#define FUNC_FxSystem_c__CopyParentMatrix       0x004AA890
#define FUNC_FxSystem_c__DoFxAudio              0x004AAC90
#define FUNC_FxSystem_c__EnablePrim             0x004AA610
#define FUNC_FxSystem_c__Exit                   0x004AA840
#define FUNC_FxSystem_c__GetBoundingSphereWld   0x004AAAD0
#define FUNC_FxSystem_c__GetCompositeMatrix     0x007F18F0
#define FUNC_FxSystem_c__GetPlayStatus          0x004AA900
#define FUNC_FxSystem_c__Init                   0x004AA750
#define FUNC_FxSystem_c__IsVisible              0x004AAF30
#define FUNC_FxSystem_c__Kill                   0x004AA3F0
#define FUNC_FxSystem_c__Play                   0x004AA2F0
#define FUNC_FxSystem_c__PlayAndKill            0x004AA3D0
#define FUNC_FxSystem_c__SetConstTime           0x004AA6C0
#define FUNC_FxSystem_c__SetLocalParticles      0x004AA910
#define FUNC_FxSystem_c__SetMatrix              0x004AA630
#define FUNC_FxSystem_c__SetOffsetPos           0x004AA660
#define FUNC_FxSystem_c__SetRateMult            0x004AA6F0
#define FUNC_FxSystem_c__Stop                   0x004AA390
#define FUNC_FxSystem_c__Update                 0x004AAF70
#define VAR_FxSystemUpdateCullDistMultiplier            0x4AB032
#define VAR_FxCreateParticleCullDistMultiplierA         0x4A4247
#define VAR_FxCreateParticleCullDistMultiplierB         0x4A4255
#define FX_SYSTEM_UPDATE_CULL_DIST_MULTIPLIER_DEFAULT   ( 1 / 256.f )
#define FX_CREATE_PARTICLE_CULL_DIST_MULTIPLIER_DEFAULT ( 1 / 64.f )

class CAEFireAudioEntitySAInterface
{
public:
    // this derives from CAEAudioEntity
    // todo: reverse this structure and CAEAudioEntity
    std::int32_t pad1[0x21];

    void* audio;            // 0x84 // TODO: Reverse what this __exactly__ is
};
static_assert(sizeof(CAEFireAudioEntitySAInterface) == 0x88, "Invalid size for CAEFireAudioEntitySAInterface");

class CFxSystemBPSAInterface;
class CFxSystemSAInterface            // Internal SA Name: FxSystem_c
{
public:
    // Based upon ListItem_c
    CFxSystemSAInterface* pPrevious;            // 0x00
    CFxSystemSAInterface* pNext;                // 0x04

    // Actual members
    CFxSystemBPSAInterface*       pBlueprint;                    // 0x08
    RwMatrix*                     pmatUnknown;                   // 0x10
    RwMatrix                      matPosition;                   // 0x0C
    char                          cPlayStatus;                   // 0x50
    char                          cUnknownFlag;                  // 0x51
    char                          cConstTime;                    // 0x52
    char                          pad;                           // 0x53
    int                           unk2[2];                       // 0x54
    short                         sConstTimeMult;                // 0x5C
    short                         sRateMult;                     // 0x5E (This controls how often the effect is renewed)
    short                         sTimeMult;                     // 0x60 (This controls how fast the effect plays)
    char                          cFlags;                        // 0x62
    char                          pad2;                          // 0x63
    int                           unk3;                          // 0x64
    CVector                       vecVelocity;                   // 0x68
    void*                         pSphere;                       // 0x74
    void**                        ppParticleEmitters;            // 0x78 (Array of particle emitters, amount is defined by the blueprint)
    CAEFireAudioEntitySAInterface audioEntity;                   // 0x7C
};
static_assert(sizeof(CFxSystemSAInterface) == 0x104, "Invalid size for CFxSystemSAInterface");

class CFxSystemSA : public CFxSystem
{
public:
    CFxSystemSA(CFxSystemSAInterface* pInterface);
    ~CFxSystemSA();

    void PlayAndKill();

    void  SetEffectSpeed(float fSpeed);
    float GetEffectSpeed();

    void  SetEffectDensity(float fDensity);
    float GetEffectDensity();

    void GetPosition(CVector& vecPos);
    void SetPosition(const CVector& vecPos);

    void GetMatrix(CMatrix& matrix);
    void SetMatrix(const CMatrix& matrix);

    void  SetDrawDistance(float fDrawDistance);
    float GetDrawDistance();
    bool  HasCustomDrawDistance();

    void* GetInterface() { return (void*)m_pInterface; }

    static void StaticSetHooks();

protected:
    CFxSystemSAInterface* m_pInterface;
    float                 m_fDrawDistance;
};

// FxEmitter stuff
class CFxEmitterBPSAInterface
{
public:
    void*  vtbl;                          // 0x00
    char   pad[0x34];                     // 0x04
    ushort usFadeNearDistance;            // 0x38
    ushort usFadeFarDistance;             // 0x3A
    // TODO the rest
};

class CFxEmitterSAInterface
{
public:
    void*                    vtbl;                  // 0x00
    CFxEmitterBPSAInterface* pBlueprint;            // 0x04
    CFxSystemSAInterface*    pOwner;                // 0x08
    // TODO the rest
};
