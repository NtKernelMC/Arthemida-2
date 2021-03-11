/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto v1.0
 *               (Shared logic for modifications)
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        mods/deathmatch/logic/CSpatialDatabase.cpp
 *  PURPOSE:
 *
 *****************************************************************************/

#include "StdInc.h"
#include "RTree.h"

// Define our tree type
typedef RTree<CElement*, float, 2> CElementTree;

//
// SEntityInfo used by CSpatialDatabaseImpl
//
struct SEntityInfo
{
    CBox box;
};

///////////////////////////////////////////////////////////////
//
// CSpatialDatabaseImpl
//
///////////////////////////////////////////////////////////////
class CSpatialDatabaseImpl : public CSpatialDatabase
{
public:
    // CSpatialDatabase interface
    virtual void UpdateEntity(CElement* pEntity);
    virtual void RemoveEntity(CElement* pEntity);
    virtual bool IsEntityPresent(CElement* pEntity);
    virtual void SphereQuery(CElementResult& outResult, const CSphere& sphere);
    virtual void AllQuery(CElementResult& outResult);

    // CSpatialDatabaseImpl functions
    void FlushUpdateQueue();
    bool IsValidSphere(const CSphere& sphere);

    CElementTree                     m_Tree;
    std::map<CElement*, SEntityInfo> m_InfoMap;
    std::map<CElement*, int>         m_UpdateQueue;
};

///////////////////////////////////////////////////////////////
//
// Temporary home for global object
//
//
//
///////////////////////////////////////////////////////////////
static CSpatialDatabaseImpl* g_pSpatialDatabaseImp = NULL;

CSpatialDatabase* GetSpatialDatabase()
{
    if (!g_pSpatialDatabaseImp)
        g_pSpatialDatabaseImp = new CSpatialDatabaseImpl();
    return g_pSpatialDatabaseImp;
}

///////////////////////////////////////////////////////////////
//
// CSpatialDatabaseImpl::UpdateEntity
//
//
//
///////////////////////////////////////////////////////////////
void CSpatialDatabaseImpl::UpdateEntity(CElement* pEntity)
{
    // Add the entity to a list of pending updates
    m_UpdateQueue[pEntity] = 1;
}

///////////////////////////////////////////////////////////////
//
// CSpatialDatabaseImpl::RemoveEntity
//
// Remove an entity from the database
//
///////////////////////////////////////////////////////////////
void CSpatialDatabaseImpl::RemoveEntity(CElement* pEntity)
{
    // Remove from the tree and info map
    SEntityInfo* pInfo = MapFind(m_InfoMap, pEntity);
    if (pInfo)
    {
        m_Tree.Remove(&pInfo->box.vecMin.fX, &pInfo->box.vecMax.fX, pEntity);
        MapRemove(m_InfoMap, pEntity);
    }
    // Remove from the update queue
    MapRemove(m_UpdateQueue, pEntity);
}

///////////////////////////////////////////////////////////////
//
// CSpatialDatabaseImpl::IsEntityPresent
//
// Check if an entity is in the database
//
///////////////////////////////////////////////////////////////
bool CSpatialDatabaseImpl::IsEntityPresent(CElement* pEntity)
{
    return MapFind(m_InfoMap, pEntity) != NULL || MapFind(m_UpdateQueue, pEntity) != NULL;
}

///////////////////////////////////////////////////////////////
//
// CSpatialDatabaseImpl::SphereQuery
//
// Return the list of entities that intersect the sphere
//
///////////////////////////////////////////////////////////////
void CSpatialDatabaseImpl::SphereQuery(CElementResult& outResult, const CSphere& sphere)
{
    // Do any pending updates first
    FlushUpdateQueue();

    if (!IsValidSphere(sphere))
        return;

    // Make a box from the sphere
    CBox box(sphere.vecPosition, fabsf(sphere.fRadius));
    // Make everything 2D for now
    box.vecMin.fZ = SPATIAL_2D_Z;
    box.vecMax.fZ = SPATIAL_2D_Z;

    // Find all entiites which overlap the box
    m_Tree.Search(&box.vecMin.fX, &box.vecMax.fX, outResult);
}

///////////////////////////////////////////////////////////////
//
// CSpatialDatabaseImpl::AllQuery
//
// Return the list of all entities
//
///////////////////////////////////////////////////////////////
void CSpatialDatabaseImpl::AllQuery(CElementResult& outResult)
{
    // Do any pending updates first
    FlushUpdateQueue();

    // Copy results from map to output
    outResult.clear();
    for (std::map<CElement*, SEntityInfo>::iterator it = m_InfoMap.begin(); it != m_InfoMap.end(); ++it)
        outResult.push_back(it->first);
}

///////////////////////////////////////////////////////////////
//
// CSpatialDatabaseImpl::FlushUpdateQueue
//
// Process all entities that have changed since the last call
//
///////////////////////////////////////////////////////////////
void CSpatialDatabaseImpl::FlushUpdateQueue()
{
    std::map<CElement*, int> updateQueueCopy = m_UpdateQueue;
    m_UpdateQueue.clear();
    for (std::map<CElement*, int>::iterator it = updateQueueCopy.begin(); it != updateQueueCopy.end(); ++it)
    {
        CElement* pEntity = it->first;

        // Get the new bounding box
        SEntityInfo newInfo;
        CSphere     sphere = pEntity->GetWorldBoundingSphere();
        newInfo.box = CBox(sphere.vecPosition, fabsf(sphere.fRadius));
        // Make everything 2D for now
        newInfo.box.vecMin.fZ = SPATIAL_2D_Z;
        newInfo.box.vecMax.fZ = SPATIAL_2D_Z;

        // Get previous info
        if (SEntityInfo* pOldInfo = MapFind(m_InfoMap, pEntity))
        {
            // Don't update if bounding box is the same
            if (pOldInfo->box == newInfo.box)
                continue;

            // Remove old bounding box from tree
            m_Tree.Remove(&pOldInfo->box.vecMin.fX, &pOldInfo->box.vecMax.fX, pEntity);
        }

        if (!IsValidSphere(sphere))
            continue;

        // Add new bounding box
        m_Tree.Insert(&newInfo.box.vecMin.fX, &newInfo.box.vecMax.fX, pEntity);

        // Update info map
        MapSet(m_InfoMap, pEntity, newInfo);
    }
}

///////////////////////////////////////////////////////////////
//
// CSpatialDatabaseImpl::IsValidSphere
//
// Is the sphere valid for use in this class
//
///////////////////////////////////////////////////////////////
bool CSpatialDatabaseImpl::IsValidSphere(const CSphere& sphere)
{
    // Check for nan
    if (std::isnan(sphere.fRadius + sphere.vecPosition.fX + sphere.vecPosition.fY + sphere.vecPosition.fZ))
        return false;

    // Check radius within limits
    if (sphere.fRadius < -12000 || sphere.fRadius > 12000)            // radius = sqrt(worldlimits*worldlimits + worldlimits*worldlimits)
        return false;

    // Check position within limits
    float fDistSquared2D = sphere.vecPosition.fX * sphere.vecPosition.fX + sphere.vecPosition.fY * sphere.vecPosition.fY;
    if (fDistSquared2D > 12000 * 12000)
        return false;

    return true;
}
