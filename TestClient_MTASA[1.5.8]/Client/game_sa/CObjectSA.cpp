/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        game_sa/CObjectSA.cpp
 *  PURPOSE:     Object entity
 *
 *  Multi Theft Auto is available from http://www.multitheftauto.com/
 *
 *****************************************************************************/

#include "StdInc.h"

//#define MTA_USE_BUILDINGS_AS_OBJECTS

static void CObject_PreRender(CObjectSAInterface* objectInterface)
{
    SClientEntity<CObjectSA>* objectEntity = pGame->GetPools()->GetObject((DWORD*)objectInterface);
    if (objectEntity && objectEntity->pEntity)
        objectEntity->pEntity->SetPreRenderRequired(true);
}

const std::uintptr_t RETURN_CCObject_PreRender = 0x59FD56;
static void _declspec(naked) HOOK_CCObject_PreRender()
{
    __asm
    {
        push ecx
        call CObject_PreRender
        pop  ecx
        sub  esp, 10h
        push esi
        mov  esi, ecx
        jmp  RETURN_CCObject_PreRender
    }
}

void CObjectSA::StaticSetHooks()
{
    // Patch CObject::PreRender. We don't want the scaling code to execute
    // We'll scale the object entity matrix after onClientPedsProcessed event
    // 5E       - pop asi
    // 83 C4 10 - add esp, 0x10
    // C3       - ret
    std::uint8_t bytes[5] = {0x5E, 0x83, 0xC4, 0x10, 0xC3};
    MemCpy((void*)0x59FE0E, bytes, sizeof(bytes));
    HookInstall(0x59FD50, HOOK_CCObject_PreRender);
}

// GTA uses this to pass to CFileLoader::LoadObjectInstance the info it wants to load
struct CFileObjectInstance
{
    float x;
    float y;
    float z;
    float rx;
    float ry;
    float rz;
    float rr;            // = 1
    DWORD modelId;
    DWORD areaNumber;
    long  flags;            // = -1
};

CObjectSA::CObjectSA(CObjectSAInterface* objectInterface)
{
    DEBUG_TRACE("CObjectSA::CObjectSA(CObjectSAInterface * objectInterface)");
    this->SetInterface(objectInterface);
    m_ucAlpha = 255;

    // Setup some flags
    this->BeingDeleted = FALSE;
    this->DoNotRemoveFromGame = FALSE;

    if (m_pInterface)
    {
        ResetScale();
        CheckForGangTag();
        m_pInterface->bStreamingDontDelete = true;
    }
}

CObjectSA::CObjectSA(DWORD dwModel, bool bBreakingDisabled)
{
    DEBUG_TRACE("CObjectSA::CObjectSA( DWORD dwModel )");

    CWorldSA* world = (CWorldSA*)pGame->GetWorld();

    DWORD dwThis = 0;

#ifdef MTA_USE_BUILDINGS_AS_OBJECTS

    DWORD               dwFunc = 0x538090;            // CFileLoader__LoadObjectInstance
    CFileObjectInstance fileLoader;
    MemSetFast(&fileLoader, 0, sizeof(CFileObjectInstance));
    fileLoader.modelId = dwModel;
    fileLoader.rr = 1;
    fileLoader.areaNumber = 0;
    fileLoader.flags = -1;

    _asm
    {
        push    0
        lea     ecx, fileLoader
        push    ecx
        call    dwFunc
        add     esp, 8
        mov     dwThis, eax
    }

    this->SetInterface((CEntitySAInterface*)dwThis);

    MemPutFast<DWORD>(0xBCC0E0, dwThis);
    MemPutFast<DWORD>(0xBCC0D8, 1);

    dwFunc = 0x404DE0;            // CIplStore__SetupRelatedIpls
    DWORD dwTemp = 0;
    char  szTemp[255];
    strcpy(szTemp, "moo");

    _asm
    {
        push    0xBCC0E0
        push    -1
        lea     eax, szTemp
        push    eax
        call    dwFunc
        add     esp, 0xC
        mov     dwTemp, eax
    }

    dwFunc = 0x5B51E0;            // AddBuildingInstancesToWorld
    _asm
    {
        push    dwTemp
        call    dwFunc
        add     esp, 4
    }

    dwFunc = 0x405110;            // CIplStore__RemoveRelatedIpls
    _asm
    {
        push    -1
        call    dwFunc
        add     esp, 4
    }

    // VITAL to get colmodels to appear
    // this gets the level for a colmodel (colmodel+40)
    dwFunc = 0x4107A0;
    _asm
    {
        mov     eax, dwModel

        push    ecx
        mov     ecx, dword ptr[ARRAY_ModelInfo]
        mov     eax, dword ptr[ecx + eax*4]
        pop     ecx

        mov     eax, [eax+20]
        movzx   eax, byte ptr [eax+40]
        push    eax
        call    dwFunc
        add     esp, 4
    }

#else

    DWORD CObjectCreate = FUNC_CObject_Create;
    DWORD dwObjectPtr = 0;
    _asm
    {
        push    1
        push    dwModel
        call    CObjectCreate
        add     esp, 8
        mov     dwObjectPtr, eax
    }
    if (dwObjectPtr)
    {
        this->SetInterface((CEntitySAInterface*)dwObjectPtr);

        world->Add(m_pInterface, CObject_Constructor);

        // Setup some flags
        this->BeingDeleted = FALSE;
        this->DoNotRemoveFromGame = FALSE;
        MemPutFast<BYTE>(dwObjectPtr + 316, 6);
        if (bBreakingDisabled)
        {
            // Set our immunities
            // Sum of all flags checked @ CPhysical__CanPhysicalBeDamaged
            CObjectSAInterface* pObjectSAInterface = GetObjectInterface();
            pObjectSAInterface->bBulletProof = true;
            pObjectSAInterface->bFireProof = true;
            pObjectSAInterface->bCollisionProof = true;
            pObjectSAInterface->bMeeleProof = true;
            pObjectSAInterface->bExplosionProof = true;
        }
        m_pInterface->bStreamingDontDelete = true;
    }
    else
    {
        // The exception handler doesn't work for some reason, so do this
        this->SetInterface(NULL);
    }
#endif

    this->internalID = pGame->GetPools()->GetObjectRef((DWORD*)this->GetInterface());

    m_ucAlpha = 255;

    if (m_pInterface)
    {
        ResetScale();
        CheckForGangTag();
    }
}

CObjectSA::~CObjectSA()
{
    DEBUG_TRACE("CObjectSA::~CObjectSA( )");
    // OutputDebugString("Attempting to destroy Object\n");
    if (!this->BeingDeleted && DoNotRemoveFromGame == false)
    {
        CEntitySAInterface* pInterface = GetInterface();
        if (pInterface)
        {
            pGame->GetRopes()->RemoveEntityRope(pInterface);

            if ((DWORD)pInterface->vtbl != VTBL_CPlaceable)
            {
                CWorldSA* world = (CWorldSA*)pGame->GetWorld();
                world->Remove(pInterface, CObject_Destructor);

                DWORD dwFunc = pInterface->vtbl->SCALAR_DELETING_DESTRUCTOR;            // we use the vtbl so we can be type independent
                _asm
                {
                    mov     ecx, pInterface
                    push    1            // delete too
                    call    dwFunc
                }

#ifdef MTA_USE_BUILDINGS_AS_OBJECTS
                DWORD dwModelID = this->internalInterface->m_nModelIndex;
                // REMOVE ref to colstore thingy
                dwFunc = 0x4107D0;
                _asm
                {
                    mov     eax, dwModelID

                    push    ecx
                    mov     ecx, dword ptr[ARRAY_ModelInfo]
                    mov     eax, dword ptr[ecx + eax*4]
                    pop     ecx

                    mov     eax, [eax+20]
                    movzx   eax, byte ptr [eax+40]
                    push    eax
                    call    dwFunc
                    add     esp, 4
                }
#endif
            }
        }

        this->BeingDeleted = true;
        ((CPoolsSA*)pGame->GetPools())->RemoveObject((CObject*)(CObjectSA*)this);

        // OutputDebugString("Destroying Object\n");
    }
}

void CObjectSA::Explode()
{
    DWORD dwFunc = FUNC_CObject_Explode;
    DWORD dwThis = (DWORD)this->GetInterface();

    _asm
    {
        mov     ecx, dwThis
        call    dwFunc
    }
}

void CObjectSA::Break()
{
    DWORD dwFunc = 0x5A0D90;
    DWORD dwThis = (DWORD)GetInterface();

    float fHitVelocity = 1000.0f;            // has no direct influence, but should be high enough to trigger the break (effect)

    _asm
    {
        push    32h // most cases: between 30 and 37
        push    0 // colliding entity. To ignore it, we can set it to 0
        push    0B73710h // vecCollisionImpactVelocity
        push    0 // vecCollisionLastPos
        push    fHitVelocity
        mov     ecx, dwThis
        call    dwFunc
    }

    if (IsGlass())
    {
        float fX = 0.0f;
        float fY = 0.0f;
        float fZ = 0.0f;
        dwFunc = FUNC_CGlass_WindowRespondsToCollision;

        _asm
        {
            push 0
            push fZ
            push fY
            push fX
            push 0
            push 0
            push 0
            push fHitVelocity
            push dwThis
            call dwFunc
            add esp, 24h
        }
    }
}

void CObjectSA::SetHealth(float fHealth)
{
    static_cast<CObjectSAInterface*>(this->GetInterface())->fHealth = fHealth;
}

float CObjectSA::GetHealth()
{
    return static_cast<CObjectSAInterface*>(this->GetInterface())->fHealth;
}

void CObjectSA::SetModelIndex(unsigned long ulModel)
{
    // Delete any existing RwObject first
    DWORD dwFunc = this->GetInterface()->vtbl->DeleteRwObject;
    DWORD dwThis = (DWORD)this->GetInterface();
    _asm
        {
        mov     ecx, dwThis
        call    dwFunc
        }

    // Jax: I'm not sure if using the vtbl is right (as ped and vehicle dont), but it works
    dwFunc = this->GetInterface()->vtbl->SetModelIndex;
    _asm
        {
        mov     ecx, dwThis
        push    ulModel
        call    dwFunc
        }

    CheckForGangTag();
}

void CObjectSA::CheckForGangTag()
{
    switch (GetModelIndex())
    {
        case 1524:
        case 1525:
        case 1526:
        case 1527:
        case 1528:
        case 1529:
        case 1530:
        case 1531:
            m_bIsAGangTag = true;
            break;
        default:
            m_bIsAGangTag = false;
            break;
    }
}

bool CObjectSA::IsGlass()
{
    DWORD dwFunc = 0x46A760;
    DWORD dwThis = (DWORD)GetInterface();
    bool  bResult;

    _asm
    {
        push dwThis
        call dwFunc
        mov bResult, al
        add esp, 4
    }
    return bResult;
}

void CObjectSA::SetScale(float fX, float fY, float fZ)
{
    m_vecScale = CVector(fX, fY, fZ);
    GetObjectInterface()->bUpdateScale = true;
    GetObjectInterface()->fScale = std::max(fX, std::max(fY, fZ));
}

CVector* CObjectSA::GetScale()
{
    return &m_vecScale;
}

void CObjectSA::ResetScale()
{
    SetScale(1.0f, 1.0f, 1.0f);
}
