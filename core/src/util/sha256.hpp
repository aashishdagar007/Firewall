#pragma once
// ──────────────────────────────────────────────────────────────
//  sha256.hpp  –  Header-only, zero-dependency SHA-256 (FIPS 180-4)
//
//  Usage:
//    auto digest = SHA256::hash(data_ptr, len);
//    auto digest = SHA256::hash("some string");
//    std::string hex = SHA256::to_hex(digest);
//
//    // Streaming:
//    SHA256 h;
//    h.update(buf, len);
//    h.update(buf2, len2);
//    auto digest = h.finalize();
// ──────────────────────────────────────────────────────────────

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

class SHA256 {
public:
    static constexpr size_t DIGEST_SIZE = 32;
    using Digest = std::array<uint8_t, DIGEST_SIZE>;

    SHA256() { reset(); }

    void reset() {
        h_[0] = 0x6a09e667u; h_[1] = 0xbb67ae85u;
        h_[2] = 0x3c6ef372u; h_[3] = 0xa54ff53au;
        h_[4] = 0x510e527fu; h_[5] = 0x9b05688cu;
        h_[6] = 0x1f83d9abu; h_[7] = 0x5be0cd19u;
        bit_len_ = 0;
        idx_     = 0;
    }

    void update(const void* data, size_t n) {
        const auto* p = static_cast<const uint8_t*>(data);
        for (size_t i = 0; i < n; ++i) {
            buf_[idx_++] = p[i];
            if (idx_ == 64) { transform(); idx_ = 0; }
        }
        bit_len_ += static_cast<uint64_t>(n) * 8;
    }

    void update(const std::string& s) { update(s.data(), s.size()); }
    void update(const std::vector<uint8_t>& v) { update(v.data(), v.size()); }

    Digest finalize() {
        uint64_t total_bits = bit_len_;

        // Append 0x80 padding byte
        buf_[idx_++] = 0x80;
        if (idx_ > 56) {
            while (idx_ < 64) buf_[idx_++] = 0;
            transform();
            idx_ = 0;
        }
        while (idx_ < 56) buf_[idx_++] = 0;

        // Append big-endian 64-bit bit-length
        for (int i = 7; i >= 0; --i)
            buf_[idx_++] = static_cast<uint8_t>((total_bits >> (i * 8)) & 0xFF);
        transform();

        Digest d;
        for (int i = 0; i < 8; ++i) {
            d[i*4+0] = static_cast<uint8_t>((h_[i] >> 24) & 0xFF);
            d[i*4+1] = static_cast<uint8_t>((h_[i] >> 16) & 0xFF);
            d[i*4+2] = static_cast<uint8_t>((h_[i] >>  8) & 0xFF);
            d[i*4+3] = static_cast<uint8_t>( h_[i]        & 0xFF);
        }
        reset();
        return d;
    }

    // ── One-shot helpers ──────────────────────────────────────
    static Digest hash(const void* data, size_t n) {
        SHA256 h; h.update(data, n); return h.finalize();
    }
    static Digest hash(const std::string& s) { return hash(s.data(), s.size()); }
    static Digest hash(const std::vector<uint8_t>& v) { return hash(v.data(), v.size()); }

    static std::string to_hex(const Digest& d) {
        static constexpr char HEX[] = "0123456789abcdef";
        std::string s; s.reserve(64);
        for (uint8_t b : d) { s += HEX[b >> 4]; s += HEX[b & 0xF]; }
        return s;
    }

    static Digest from_hex(const std::string& hex) {
        Digest d{}; d.fill(0);
        for (size_t i = 0; i < 32 && i*2+1 < hex.size(); ++i) {
            auto nibble = [](char c) -> uint8_t {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return 0;
            };
            d[i] = static_cast<uint8_t>((nibble(hex[i*2]) << 4) | nibble(hex[i*2+1]));
        }
        return d;
    }

    // HMAC-SHA256 for message authentication
    static Digest hmac(const uint8_t* key, size_t key_len,
                       const void* msg, size_t msg_len) {
        uint8_t k_ipad[64]{}, k_opad[64]{};
        if (key_len > 64) {
            Digest kd = hash(key, key_len);
            std::memcpy(k_ipad, kd.data(), 32);
            std::memcpy(k_opad, kd.data(), 32);
        } else {
            std::memcpy(k_ipad, key, key_len);
            std::memcpy(k_opad, key, key_len);
        }
        for (int i = 0; i < 64; ++i) { k_ipad[i] ^= 0x36; k_opad[i] ^= 0x5c; }

        SHA256 inner;
        inner.update(k_ipad, 64);
        inner.update(msg, msg_len);
        Digest inner_digest = inner.finalize();

        SHA256 outer;
        outer.update(k_opad, 64);
        outer.update(inner_digest.data(), 32);
        return outer.finalize();
    }

private:
    // ── SHA-256 round constants (first 32 bits of fractional cube roots) ──
    static constexpr uint32_t K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
        0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
        0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
        0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
        0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
        0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
        0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
        0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
        0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };

    static uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32-n)); }
    static uint32_t Ch (uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
    static uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    static uint32_t S0 (uint32_t x) { return rotr32(x, 2) ^ rotr32(x,13) ^ rotr32(x,22); }
    static uint32_t S1 (uint32_t x) { return rotr32(x, 6) ^ rotr32(x,11) ^ rotr32(x,25); }
    static uint32_t s0 (uint32_t x) { return rotr32(x, 7) ^ rotr32(x,18) ^ (x >>  3); }
    static uint32_t s1 (uint32_t x) { return rotr32(x,17) ^ rotr32(x,19) ^ (x >> 10); }

    void transform() {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (static_cast<uint32_t>(buf_[i*4+0]) << 24) |
                   (static_cast<uint32_t>(buf_[i*4+1]) << 16) |
                   (static_cast<uint32_t>(buf_[i*4+2]) <<  8) |
                    static_cast<uint32_t>(buf_[i*4+3]);
        for (int i = 16; i < 64; ++i)
            w[i] = s1(w[i-2]) + w[i-7] + s0(w[i-15]) + w[i-16];

        uint32_t a=h_[0], b=h_[1], c=h_[2], d=h_[3],
                 e=h_[4], f=h_[5], g=h_[6], hh=h_[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = hh + S1(e) + Ch(e,f,g) + K[i] + w[i];
            uint32_t t2 = S0(a) + Maj(a,b,c);
            hh = g; g = f; f = e; e = d + t1;
            d  = c; c = b; b = a; a = t1 + t2;
        }
        h_[0]+=a; h_[1]+=b; h_[2]+=c; h_[3]+=d;
        h_[4]+=e; h_[5]+=f; h_[6]+=g; h_[7]+=hh;
    }

    uint32_t h_[8];
    uint64_t bit_len_ = 0;
    size_t   idx_     = 0;
    uint8_t  buf_[64];
};
