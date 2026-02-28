#include "dal/AuditRepository.hpp"

#include <stdexcept>

namespace dns::dal {

AuditRepository::AuditRepository() = default;
AuditRepository::~AuditRepository() = default;

PurgeResult AuditRepository::purgeOld(int /*iRetentionDays*/) {
  throw std::runtime_error{"not implemented"};
}

}  // namespace dns::dal
