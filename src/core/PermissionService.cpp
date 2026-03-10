#include "core/PermissionService.hpp"

#include "dal/RoleRepository.hpp"
#include "dal/ZoneRepository.hpp"

namespace dns::core {

PermissionService::PermissionService(dns::dal::RoleRepository& rrRepo,
                                     dns::dal::ZoneRepository& zrRepo)
    : _rrRepo(rrRepo), _zrRepo(zrRepo) {}

PermissionService::~PermissionService() = default;

bool PermissionService::hasPermission(int64_t iUserId, std::string_view svPermission) {
  auto perms = _rrRepo.resolveUserPermissions(iUserId);
  return perms.count(std::string(svPermission)) > 0;
}

bool PermissionService::hasPermissionForZone(int64_t iUserId,
                                              std::string_view svPermission,
                                              int64_t iZoneId) {
  // Look up the zone's view_id for view-level scope matching
  int64_t iViewId = 0;
  auto oZone = _zrRepo.findById(iZoneId);
  if (oZone.has_value()) {
    iViewId = oZone->iViewId;
  }

  auto perms = _rrRepo.resolveUserPermissions(iUserId, iViewId, iZoneId);
  return perms.count(std::string(svPermission)) > 0;
}

bool PermissionService::hasPermissionForView(int64_t iUserId,
                                              std::string_view svPermission,
                                              int64_t iViewId) {
  auto perms = _rrRepo.resolveUserPermissions(iUserId, iViewId);
  return perms.count(std::string(svPermission)) > 0;
}

std::unordered_set<std::string> PermissionService::getEffectivePermissions(
    int64_t iUserId) {
  return _rrRepo.resolveUserPermissions(iUserId);
}

std::unordered_set<std::string> PermissionService::getEffectivePermissionsForZone(
    int64_t iUserId, int64_t iZoneId) {
  int64_t iViewId = 0;
  auto oZone = _zrRepo.findById(iZoneId);
  if (oZone.has_value()) {
    iViewId = oZone->iViewId;
  }
  return _rrRepo.resolveUserPermissions(iUserId, iViewId, iZoneId);
}

}  // namespace dns::core
