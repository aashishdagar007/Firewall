#pragma once
#include "util/types.hpp"
#include <array>
#include <cstddef>
#include <string>
#include <vector>

namespace fw {

struct DpiSignature {
  std::string name;
  std::vector<uint8_t> pattern;
  bool case_insensitive = false;
  std::array<size_t, 256> bad_char{};
};

class DpiEngine {
public:
  DpiEngine();

  // Scans the payload against known threat signatures.
  // Returns Action::BLOCK if a threat is found, Action::ALLOW otherwise.
  // If blocked, populates threat_name with the signature name.
  Action scan(const uint8_t *payload, uint16_t len, std::string &threat_name);

private:
  std::vector<DpiSignature> signatures_;

  bool bmh_search(const uint8_t *payload, uint16_t len,
                  const DpiSignature &signature) const;
};

} // namespace fw
