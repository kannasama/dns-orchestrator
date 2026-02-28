#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace dns::core {

/// Tokenizes and expands {{var}} placeholders in record templates.
/// Class abbreviation: ve
class VariableEngine {
 public:
  VariableEngine();
  ~VariableEngine();

  std::string expand(const std::string& sTmpl, int64_t iZoneId) const;
  bool validate(const std::string& sTmpl, int64_t iZoneId) const;
  std::vector<std::string> listDependencies(const std::string& sTmpl) const;
};

}  // namespace dns::core
