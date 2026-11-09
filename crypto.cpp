#include "crypto.hpp"
#include <cstring>

namespace Crypto {

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

SHA256::SHA256() {
    state[0] = 0x6a09e667;
    state[1] = 0xbb67ae85;
    state[2] = 0x3c6ef372;
    state[3] = 0xa54ff53a;
    state[4] = 0x510e527f;
    state[5] = 0x9b05688c;
    state[6] = 0x1f83d9ab;
    state[7] = 0x5be0cd19;
    bitCount = 0;
}

void SHA256::transform(const uint8_t chunk[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (uint32_t(chunk[i * 4]) << 24) |
               (uint32_t(chunk[i * 4 + 1]) << 16) |
               (uint32_t(chunk[i * 4 + 2]) << 8) |
               (uint32_t(chunk[i * 4 + 3]));
    }
    for (int i = 16; i < 64; ++i) {
        w[i] = theta1(w[i - 2]) + w[i - 7] + theta0(w[i - 15]) + w[i - 16];
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = h + sig1(e) + ch(e, f, g) + K[i] + w[i];
        uint32_t t2 = sig0(a) + maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void SHA256::update(const uint8_t* data, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        buffer[(bitCount / 8) % 64] = data[i];
        bitCount += 8;
        if ((bitCount / 8) % 64 == 0) {
            transform(buffer);
        }
    }
}

std::vector<uint8_t> SHA256::digest() {
    uint64_t totalBits = bitCount;
    update(reinterpret_cast<const uint8_t*>("\x80"), 1);
    while ((bitCount / 8) % 64 != 56) {
        update(reinterpret_cast<const uint8_t*>("\x00"), 1);
    }
    for (int i = 7; i >= 0; --i) {
        uint8_t byte = (totalBits >> (i * 8)) & 0xFF;
        update(&byte, 1);
    }

    std::vector<uint8_t> hash(32);
    for (int i = 0; i < 8; ++i) {
        hash[i * 4]     = (state[i] >> 24) & 0xFF;
        hash[i * 4 + 1] = (state[i] >> 16) & 0xFF;
        hash[i * 4 + 2] = (state[i] >> 8) & 0xFF;
        hash[i * 4 + 3] = state[i] & 0xFF;
    }
    return hash;
}

std::string SHA256::hashString(const std::string& input) {
    SHA256 sha;
    sha.update(reinterpret_cast<const uint8_t*>(input.data()), input.size());
    std::vector<uint8_t> d = sha.digest();
    std::ostringstream ss;
    for (uint8_t b : d) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return ss.str();
}

std::vector<uint8_t> encryptPayload(const std::string& plaintext, const std::string& key) {
    std::string keyHash = SHA256::hashString(key);
    std::vector<uint8_t> ciphertext(plaintext.size());
    for (size_t i = 0; i < plaintext.size(); ++i) {
        ciphertext[i] = static_cast<uint8_t>(plaintext[i]) ^ static_cast<uint8_t>(keyHash[i % keyHash.size()]);
    }
    return ciphertext;
}

std::string decryptPayload(const std::vector<uint8_t>& ciphertext, const std::string& key) {
    std::string keyHash = SHA256::hashString(key);
    std::string plaintext(ciphertext.size(), ' ');
    for (size_t i = 0; i < ciphertext.size(); ++i) {
        plaintext[i] = static_cast<char>(ciphertext[i] ^ static_cast<uint8_t>(keyHash[i % keyHash.size()]));
    }
    return plaintext;
}

} // namespace Crypto
