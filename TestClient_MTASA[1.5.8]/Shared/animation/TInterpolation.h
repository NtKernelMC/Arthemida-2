/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.1
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        animation/TInterpolation.h
 *  PURPOSE:     Shared (server/client) way of performing interpolation for any data type
 *
 *****************************************************************************/

#pragma once

template <typename T>
class TInterpolation
{
public:
    TInterpolation() : m_easingCurve(CEasingCurve::Linear), m_ullStartTime(0), m_ullEndTime(0), m_ulDuration(0) {}

    virtual ~TInterpolation(){};

    virtual void SetSourceValue(const T& a_rValue)
    {
        m_SourceValue = a_rValue;
        m_DeltaValue = m_TargetValue - m_SourceValue;
    }

    virtual void SetTargetValue(const T& a_rValue)
    {
        m_TargetValue = a_rValue;
        m_DeltaValue = m_TargetValue - m_SourceValue;
    }

    void SetEasing(CEasingCurve::eType a_easingType, double a_fEasingPeriod = 0.3, double a_fEasingAmplitude = 1.0, double a_fEasingOvershoot = 1.70158)
    {
        m_easingCurve.SetType(a_easingType);
        m_easingCurve.SetParams(a_fEasingPeriod, a_fEasingAmplitude, a_fEasingOvershoot);
    }

    void SetDuration(unsigned long a_ulDuration)
    {
        unsigned long long ullNow = _GetTime();
        m_ullStartTime = ullNow;
        m_ullEndTime = ullNow + a_ulDuration;
        m_ulDuration = a_ulDuration;
    }

    void SetDuration(unsigned long a_ulElapsedTime, unsigned long a_ulTimeLeft)
    {
        unsigned long long ullNow = _GetTime();
        m_ullStartTime = ullNow - a_ulElapsedTime;
        m_ullEndTime = ullNow + a_ulTimeLeft;
        m_ulDuration = a_ulElapsedTime + a_ulTimeLeft;
    }

    bool IsRunning() const
    {
        unsigned long long ullNow = _GetTime();
        return (ullNow < m_ullEndTime) && (m_ulDuration > 0);
    }

    // Returns false if the animation reached the end and should not be used anymore
    bool GetValue(T& a_rResult) const
    {
        if (IsRunning())
        {
            unsigned long long ullNow = _GetTime();
            float              fElapsedTime = static_cast<float>(ullNow - m_ullStartTime);

            float fAnimationTime = fElapsedTime / m_ulDuration;                         // Division by 0 is handled by IsRunning ()
            fAnimationTime = m_easingCurve.ValueForProgress(fAnimationTime);            // Get the animation time to use (since it can be non linear)

            _GetValue(a_rResult, fAnimationTime);

            return true;
        }
        else
        {
            GetFinalValue(a_rResult);
            return false;
        }
    }

    // Returns the values at the end of the animation (not necessarly "target" due to some easing function ending at values != 1)
    void GetFinalValue(T& a_rResult) const
    {
        if (m_easingCurve.IsTargetValueFinalValue())
        {
            a_rResult = m_TargetValue;
        }
        else
        {
            float fAnimationTime = m_easingCurve.ValueForProgress(1.0);            // Get the animation time to use (since it can be non linear)
            _GetValue(a_rResult, fAnimationTime);
        }
    }

    static T Interpolate(const T& a_rSourceValue, const T& a_rTargetValue, float a_fAnimationTime)
    {
        T currentDelta = a_rTargetValue - a_rSourceValue;
        currentDelta *= a_fAnimationTime;
        return a_rSourceValue + currentDelta;
    }

    static T Interpolate(const T& a_rSourceValue, const T& a_rTargetValue, float a_fAnimationTime, CEasingCurve::eType a_easingType,
                         double a_fEasingPeriod = 0.3, double a_fEasingAmplitude = 1.0, double a_fEasingOvershoot = 1.70158)
    {
        CEasingCurve easingCurve(a_easingType);
        easingCurve.SetParams(a_fEasingPeriod, a_fEasingAmplitude, a_fEasingOvershoot);
        if (a_fAnimationTime >= 1.0f && easingCurve.IsTargetValueFinalValue())
        {
            return a_rTargetValue;
        }
        else
        {
            float fAnimationTime = easingCurve.ValueForProgress(a_fAnimationTime);
            return Interpolate(a_rSourceValue, a_rTargetValue, fAnimationTime);
        }
    }

protected:
    unsigned long long _GetTime() const { return GetTickCount64_(); }

    void _GetValue(T& a_rResult, float a_fAnimationTime) const
    {
        T currentDelta = m_DeltaValue;
        currentDelta *= a_fAnimationTime;
        a_rResult = m_SourceValue + currentDelta;
    }

    T m_SourceValue;
    T m_TargetValue;
    T m_DeltaValue;            // Used for calculations, also allows some subtypes to use a different way to set delta

    CEasingCurve m_easingCurve;

    unsigned long long m_ullStartTime;
    unsigned long long m_ullEndTime;
    unsigned long      m_ulDuration;
};
