#include "persistence/config_parser.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
    constexpr std::size_t kMaxRuleBytes = 4096;
    if (size > kMaxRuleBytes)
        return 0;

    const std::string line(reinterpret_cast<const char*>(data), size);
    fw::Rule rule{};
    (void)fw::ConfigParser::parse_line(line, rule);
    return 0;
}
