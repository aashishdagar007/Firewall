#pragma once
#include <string>
#include <vector>
#include <mutex>
#include <memory>

namespace fw {

enum class VpnProtocol {
    OPENVPN,
    WIREGUARD,
    IPSEC
};
enum class Cipher {
    NONE,
    AES_256_GCM,
    CHACHA20_POLY1305
};

struct VpnConnection {
    std::string id;
    VpnProtocol protocol;
    Cipher cipher;
    std::string remote_endpoint;
    uint32_t virtual_ip;
    uint32_t subnet_mask;
    bool active;
};

class VpnManager {
public:
    VpnManager();
    ~VpnManager();

    // Cryptographic transformations (simulated packet data using OpenSSL)
    static std::vector<uint8_t> encrypt_payload(const std::vector<uint8_t>& plaintext, const std::string& key, Cipher cipher);
    static std::vector<uint8_t> decrypt_payload(const std::vector<uint8_t>& ciphertext, const std::string& key, Cipher cipher);

    // Register a new VPN connection endpoint and rules
    std::string add_connection(VpnProtocol protocol, const std::string& endpoint, uint32_t vip, uint32_t mask);
    bool remove_connection(const std::string& id);
    
    // Connect / Disconnect operations (simulated for now)
    bool connect(const std::string& id);
    bool disconnect(const std::string& id);

    // Get active connections
    std::vector<VpnConnection> get_active_connections() const;

private:
    mutable std::mutex mtx_;
    std::vector<VpnConnection> connections_;
    uint32_t next_id_ = 1;
};

} // namespace fw
