#include <gtest/gtest.h>
#include "vpn_manager.hpp"
#include <string>
#include <vector>

using namespace fw;

TEST(VpnCryptoTest, Aes256GcmEncryptionDecryption) {
    std::string key = "01234567890123456789012345678901"; // 32 bytes for AES-256
    std::vector<uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o', ' ', 'V', 'P', 'N'};
    
    // Encrypt
    auto ciphertext = VpnManager::encrypt_payload(plaintext, key, Cipher::AES_256_GCM);
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    EXPECT_GT(ciphertext.size(), plaintext.size()) << "Ciphertext should include IV and Tag";
#endif
    
    // Decrypt
    auto decrypted = VpnManager::decrypt_payload(ciphertext, key, Cipher::AES_256_GCM);
    
    EXPECT_EQ(plaintext, decrypted);
}

TEST(VpnCryptoTest, ChaCha20Poly1305EncryptionDecryption) {
    std::string key = "01234567890123456789012345678901"; 
    std::vector<uint8_t> plaintext = {'S', 'e', 'c', 'r', 'e', 't'};
    
    // Encrypt
    auto ciphertext = VpnManager::encrypt_payload(plaintext, key, Cipher::CHACHA20_POLY1305);
    
    // Decrypt
    auto decrypted = VpnManager::decrypt_payload(ciphertext, key, Cipher::CHACHA20_POLY1305);
    
    EXPECT_EQ(plaintext, decrypted);
}

TEST(VpnCryptoTest, InvalidKeyDecryptionFails) {
    std::string key = "01234567890123456789012345678901"; 
    std::string bad_key = "11111111111111111111111111111111"; 
    std::vector<uint8_t> plaintext = {'D', 'a', 't', 'a'};
    
    auto ciphertext = VpnManager::encrypt_payload(plaintext, key, Cipher::AES_256_GCM);
    auto decrypted = VpnManager::decrypt_payload(ciphertext, bad_key, Cipher::AES_256_GCM);
    
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    EXPECT_TRUE(decrypted.empty()) << "Decryption should fail with bad key (Tag mismatch)";
#else
    // Without OpenSSL, crypto is a pass-through
    EXPECT_EQ(plaintext, decrypted);
#endif
}
