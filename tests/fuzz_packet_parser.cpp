#include "net/packet.hpp"

#include <climits>
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
    if (size > static_cast<std::size_t>(INT_MAX))
        return 0;

    fw::PacketInfo packet{};
    if (fw::PacketParser::parse(data, static_cast<int>(size), packet))
        (void)fw::PacketParser::is_supported_by_v1(packet);
    return 0;
}
