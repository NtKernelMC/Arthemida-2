/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *               (Shared logic for modifications)
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        mods/shared_logic/CClientSoundManager.h
 *  PURPOSE:     Sound manager class header
 *
 *****************************************************************************/

class CClientSoundManager;

#pragma once

#include <list>
#include <bass.h>
#include "CClientSound.h"

class CClientSoundManager
{
public:
    ZERO_ON_NEW
    CClientSoundManager(CClientManager* pClientManager);
    ~CClientSoundManager();

    void DoPulse();

    void SetDimension(unsigned short usDimension);

    CClientSound* PlaySound2D(const SString& strSound, bool bIsURL, bool bIsRawData, bool bLoop, bool bThrottle);
    CClientSound* PlaySound2D(void* pMemory, unsigned int uiLength, bool bLoop);
    CClientSound* PlaySound3D(const SString& strSound, bool bIsURL, bool bIsRawData, const CVector& vecPosition, bool bLoop, bool bThrottle);
    CClientSound* PlaySound3D(void* pMemory, unsigned int uiLength, const CVector& vecPosition, bool bLoop);

    CClientSound* PlayGTASFX(eAudioLookupIndex containerIndex, int iBankIndex, int iAudioIndex, bool bLoop = false);
    CClientSound* PlayGTASFX3D(eAudioLookupIndex containerIndex, int iBankIndex, int iAudioIndex, const CVector& vecPosition, bool bLoop = false);

    bool GetSFXStatus(eAudioLookupIndex containerIndex);

    void AddToList(CClientSound* pSound);
    void RemoveFromList(CClientSound* pSound);

    int GetFxEffectFromName(const std::string& strEffectName);

    std::map<std::string, int> GetFxEffects() { return m_FxEffectNames; }

    void UpdateVolume();

    void UpdateDistanceStreaming(const CVector& vecListenerPosition);

    void OnDistanceStreamIn(CClientSound* pSound);
    void OnDistanceStreamOut(CClientSound* pSound);

    bool IsDistanceStreamedIn(CClientSound* pSound) { return MapContains(m_DistanceStreamedInMap, pSound); };

    bool IsMinimizeMuted() { return m_bMinimizeMuted; };
    void SetMinimizeMuted(bool bMute) { m_bMinimizeMuted = bMute; };

    void QueueChannelStop(DWORD pSound);
    void QueueAudioStop(CBassAudio* pAudio);
    void ProcessStopQueues(bool bFlush = false);

private:
    CClientManager* m_pClientManager;

    unsigned short m_usDimension;

    std::list<CClientSound*> m_Sounds;
    std::set<CClientSound*>  m_DistanceStreamedInMap;

    std::map<std::string, int> m_FxEffectNames;
    SString                    m_strUserAgent;

    bool m_bMinimizeMuted;

    bool m_aValidatedSFX[9];

    std::vector<DWORD>                  m_ChannelStopQueue;
    std::map<CBassAudio*, CElapsedTime> m_AudioStopQueue;
    CCriticalSection                    m_CS;
};
