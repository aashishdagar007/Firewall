#include "engine/vpn_manager.hpp"
#include <iostream>
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif

namespace fw {

std::vector<uint8_t> VpnManager::encrypt_payload(const std::vector<uint8_t>& plaintext, const std::string& key, Cipher cipher) {
    if (cipher == Cipher::NONE || plaintext.empty()) return plaintext;

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    const EVP_CIPHER* evp_cipher = nullptr;
    if (cipher == Cipher::AES_256_GCM) {
        evp_cipher = EVP_aes_256_gcm();
    } else if (cipher == Cipher::CHACHA20_POLY1305) {
        evp_cipher = EVP_chacha20_poly1305();
    }

    if (!evp_cipher) return plaintext;

    std::vector<uint8_t> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH + 16); // +16 for tag
    int out_len1 = 0, out_len2 = 0;
    
    // Create IV
    std::vector<uint8_t> iv(12, 0);
    RAND_bytes(iv.data(), iv.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, evp_cipher, nullptr, reinterpret_cast<const unsigned char*>(key.data()), iv.data());
    EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len1, plaintext.data(), plaintext.size());
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len1, &out_len2);
    
    // Get GCM Tag
    uint8_t tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(out_len1 + out_len2);
    // Append IV and Tag (simulated payload format: [IV][Ciphertext][Tag])
    std::vector<uint8_t> final_payload;
    final_payload.insert(final_payload.end(), iv.begin(), iv.end());
    final_payload.insert(final_payload.end(), ciphertext.begin(), ciphertext.end());
    final_payload.insert(final_payload.end(), std::begin(tag), std::end(tag));

    return final_payload;
#else
    // Fallback if OpenSSL is not available
    (void)key;
    return plaintext;
#endif
}

std::vector<uint8_t> VpnManager::decrypt_payload(const std::vector<uint8_t>& payload, const std::string& key, Cipher cipher) {
    if (cipher == Cipher::NONE || payload.size() <= 28) return payload; // IV(12) + Tag(16)

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    const EVP_CIPHER* evp_cipher = nullptr;
    if (cipher == Cipher::AES_256_GCM) {
        evp_cipher = EVP_aes_256_gcm();
    } else if (cipher == Cipher::CHACHA20_POLY1305) {
        evp_cipher = EVP_chacha20_poly1305();
    }
    if (!evp_cipher) return payload;

    std::vector<uint8_t> iv(payload.begin(), payload.begin() + 12);
    std::vector<uint8_t> tag(payload.end() - 16, payload.end());
    std::vector<uint8_t> ciphertext(payload.begin() + 12, payload.end() - 16);

    std::vector<uint8_t> plaintext(ciphertext.size());
    int out_len1 = 0, out_len2 = 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, evp_cipher, nullptr, reinterpret_cast<const unsigned char*>(key.data()), iv.data());
    EVP_DecryptUpdate(ctx, plaintext.data(), &out_len1, ciphertext.data(), ciphertext.size());
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data());
    
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len1, &out_len2);
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext.resize(out_len1 + out_len2);
        return plaintext;
    }
    // Decryption failed (auth tag mismatch)
    return {};
#else
    // Fallback if OpenSSL is not available
    (void)key;
    return payload;
#endif
}

VpnManager::VpnManager() {}
VpnManager::~VpnManager() {}

std::string VpnManager::add_connection(VpnProtocol protocol, const std::string& endpoint, uint32_t vip, uint32_t mask) {
    std::lock_guard<std::mutex> lock(mtx_);
    std::string id = "vpn_" + std::to_string(next_id_++);
    
    VpnConnection conn;
    conn.id = id;
    conn.protocol = protocol;
    conn.remote_endpoint = endpoint;
    conn.virtual_ip = vip;
    conn.subnet_mask = mask;
    conn.active = false;

    connections_.push_back(conn);
    return id;
}

bool VpnManager::remove_connection(const std::string& id) {
    std::lock_guard<std::mutex> lock(mtx_);
    for (auto it = connections_.begin(); it != connections_.end(); ++it) {
        if (it->id == id) {
            connections_.erase(it);
            return true;
        }
    }
    return false;
}

bool VpnManager::connect(const std::string& id) {
    std::lock_guard<std::mutex> lock(mtx_);
    for (auto& conn : connections_) {
        if (conn.id == id) {
            if (!conn.active) {
                // Simulate establishing connection
                conn.active = true;
                std::cout << "[VPN] Connected to " << conn.remote_endpoint << " via ID " << conn.id << "\n";
            }
            return true;
        }
    }
    return false;
}

bool VpnManager::disconnect(const std::string& id) {
    std::lock_guard<std::mutex> lock(mtx_);
    for (auto& conn : connections_) {
        if (conn.id == id) {
            if (conn.active) {
                // Simulate disconnecting
                conn.active = false;
                std::cout << "[VPN] Disconnected from " << conn.remote_endpoint << " (ID " << conn.id << ")\n";
            }
            return true;
        }
    }
    return false;
}

std::vector<VpnConnection> VpnManager::get_active_connections() const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<VpnConnection> active;
    for (const auto& conn : connections_) {
        if (conn.active) {
            active.push_back(conn);
        }
    }
    return active;
}

} // namespace fw
