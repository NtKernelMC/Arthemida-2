/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        mods/shared_logic/CClientColPolygon.h
 *  PURPOSE:     Polygon-shaped collision entity class
 *
 *  Multi Theft Auto is available from http://www.multitheftauto.com/
 *
 *****************************************************************************/

#pragma once

class CClientColPolygon : public CClientColShape
{
    DECLARE_CLASS(CClientColPolygon, CClientColShape)
public:
    CClientColPolygon(CClientManager* pManager, ElementID ID, const CVector2D& vecPosition);

    virtual CSphere GetWorldBoundingSphere();
    virtual void    DebugRender(const CVector& vecPosition, float fDrawRadius);

    eColShapeType GetShapeType() { return COLSHAPE_POLYGON; }

    bool DoHitDetection(const CVector& vecNowPosition, float fRadius);

    void SetPosition(const CVector& vecPosition);

    bool AddPoint(CVector2D vecPoint);
    bool AddPoint(CVector2D vecPoint, unsigned int uiPointIndex);
    bool SetPointPosition(unsigned int uiPointIndex, const CVector2D& vecPoint);
    bool RemovePoint(unsigned int uiPointIndex);

    unsigned int                           CountPoints() const { return static_cast<unsigned int>(m_Points.size()); };
    std::vector<CVector2D>::const_iterator IterBegin() { return m_Points.begin(); };
    std::vector<CVector2D>::const_iterator IterEnd() { return m_Points.end(); };

protected:
    std::vector<CVector2D> m_Points;

    bool IsInBounds(CVector vecPoint);
    void CalculateRadius();
    void CalculateRadius(const CVector2D& vecPoint);

    float m_fRadius;
};
