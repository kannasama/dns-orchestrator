#include "dal/UserRepository.hpp"
#include "dal/ConnectionPool.hpp"

namespace dns::dal {

UserRepository::UserRepository(ConnectionPool& cpPool) : _cpPool(cpPool) {}
UserRepository::~UserRepository() = default;

}  // namespace dns::dal
