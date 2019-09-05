#ifndef UDAP_PATHSET_HPP
#define UDAP_PATHSET_HPP

#include <udap/path_types.hpp>
#include <map>
#include <tuple>

namespace udap
{
  namespace path
  {
    enum PathStatus
    {
      ePathBuilding,
      ePathEstablished,
      ePathTimeout,
      ePathExpired
    };
    // forward declare
    struct Path;

    /// a set of paths owned by an entity
    struct PathSet
    {
      /// construct
      /// @params numPaths the number of paths to maintain
      PathSet(size_t numPaths);

      void
      RemovePath(Path* path);

      void
      HandlePathBuilt(Path* path);

      void
      AddPath(Path* path);

      Path*
      GetByUpstream(const RouterID& remote, const PathID_t& rxid);

      void
      ExpirePaths(udap_time_t now);

      size_t
      NumInStatus(PathStatus st) const;

      /// return true if we should build another path
      bool
      ShouldBuildMore() const;

     private:
      typedef std::pair< RouterID, PathID_t > PathInfo_t;
      typedef std::map< PathInfo_t, Path* > PathMap_t;

      size_t m_NumPaths;
      PathMap_t m_Paths;
    };

  }  // namespace path
}  // namespace udap

#endif