#ifndef CRYPTO_HPP
#define CRYPTO_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <sstream>
#include <iomanip>

namespace Crypto {

// SHA-256 Hash Implementation
class SHA256 {
private:
    uint32_t state[8];
    uint64_t bitCount;
    uint8_t buffer[64];

    static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
    static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
    static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    static uint32_t sig0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
    static uint32_t sig1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
    static uint32_t theta0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
    static uint32_t theta1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

    void transform(const uint8_t chunk[64]);

public:
    SHA256();
    void update(const uint8_t* data, size_t length);
    std::vector<uint8_t> digest();
    static std::string hashString(const std::string& input);
};

// Robust XOR-Cipher stream layer seeded with 256-bit key & dynamic keystream
// Emulates full stream encryption for vault persistence
std::vector<uint8_t> encryptPayload(const std::string& plaintext, const std::string& key);
std::string decryptPayload(const std::vector<uint8_t>& ciphertext, const std::string& key);

} // namespace Crypto

#endif // CRYPTO_HPP
