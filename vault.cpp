#include "vault.hpp"
#include "crypto.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <random>
#include <chrono>
#include <ctime>
#include <algorithm>

bool VaultManager::authenticate() {
    std::ifstream check(vaultPath, std::ios::binary);
    if (!check.is_open()) {
        std::cout << "\n[!] No existing vault found. Initializing new master credential store.\n";
        std::cout << "Create a strong Master Password: ";
        std::getline(std::cin, masterPassword);
        while (masterPassword.empty()) {
            std::cout << "Master Password cannot be empty. Enter password: ";
            std::getline(std::cin, masterPassword);
        }
        saveToFile();
        std::cout << "[✓] New encrypted vault successfully created!\n";
        return true;
    }
    check.close();

    std::cout << "Enter Master Password: ";
    std::getline(std::cin, masterPassword);

    if (loadFromFile()) {
        std::cout << "[✓] Vault unlocked successfully.\n";
        return true;
    } else {
        std::cout << "\n[✗] ACCESS DENIED: Invalid Master Password or corrupted vault!\n";
        return false;
    }
}

std::string VaultManager::serializeEntries() const {
    std::ostringstream ss;
    for (const auto& item : entries) {
        ss << item.service << "\t"
           << item.username << "\t"
           << item.password << "\t"
           << item.url << "\t"
           << item.dateAdded << "\n";
    }
    return ss.str();
}

void VaultManager::deserializeEntries(const std::string& raw) {
    entries.clear();
    std::istringstream stream(raw);
    std::string line;
    while (std::getline(stream, line)) {
        if (line.empty()) continue;
        std::istringstream lineStream(line);
        CredentialEntry item;
        std::getline(lineStream, item.service, '\t');
        std::getline(lineStream, item.username, '\t');
        std::getline(lineStream, item.password, '\t');
        std::getline(lineStream, item.url, '\t');
        std::getline(lineStream, item.dateAdded, '\t');
        entries.push_back(item);
    }
}

bool VaultManager::saveToFile() {
    std::ofstream file(vaultPath, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) return false;

    // Header: 64-character SHA-256 verification hash
    std::string masterHash = Crypto::SHA256::hashString(masterPassword);
    file.write(masterHash.data(), 64);

    // Payload: Encrypted serialized credential entries
    std::string serialized = serializeEntries();
    std::vector<uint8_t> encrypted = Crypto::encryptPayload(serialized, masterPassword);
    file.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());

    file.close();
    return true;
}

bool VaultManager::loadFromFile() {
    std::ifstream file(vaultPath, std::ios::binary);
    if (!file.is_open()) return false;

    char storedHash[64];
    file.read(storedHash, 64);
    if (file.gcount() < 64) return false;

    std::string expectedHash(storedHash, 64);
    std::string currentHash = Crypto::SHA256::hashString(masterPassword);

    if (expectedHash != currentHash) {
        return false;
    }

    std::vector<uint8_t> encrypted((std::istreambuf_iterator<char>(file)),
                                    std::istreambuf_iterator<char>());
    file.close();

    std::string decrypted = Crypto::decryptPayload(encrypted, masterPassword);
    deserializeEntries(decrypted);
    return true;
}

void VaultManager::addEntry(const CredentialEntry& entry) {
    entries.push_back(entry);
    saveToFile();
    std::cout << "\n[✓] Successfully added and encrypted: " << entry.service << "\n";
}

void VaultManager::listEntries() const {
    if (entries.empty()) {
        std::cout << "\n[!] Vault is empty. No credentials found.\n";
        return;
    }

    std::cout << "\n" << std::string(75, '=') << "\n";
    std::cout << std::left
              << std::setw(20) << "SERVICE"
              << std::setw(20) << "USERNAME"
              << std::setw(20) << "PASSWORD"
              << std::setw(15) << "DATE ADDED" << "\n";
    std::cout << std::string(75, '-') << "\n";

    for (const auto& item : entries) {
        std::cout << std::left
                  << std::setw(20) << item.service
                  << std::setw(20) << item.username
                  << std::setw(20) << item.password
                  << std::setw(15) << item.dateAdded << "\n";
    }
    std::cout << std::string(75, '=') << "\n";
}

void VaultManager::searchEntries(const std::string& query) const {
    std::string q = query;
    std::transform(q.begin(), q.end(), q.begin(), ::tolower);

    bool found = false;
    for (const auto& item : entries) {
        std::string s = item.service;
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);

        if (s.find(q) != std::string::npos) {
            if (!found) {
                std::cout << "\n--- Search Results for '" << query << "' ---\n";
                found = true;
            }
            std::cout << "Service : " << item.service << "\n"
                      << "User    : " << item.username << "\n"
                      << "Password: " << item.password << "\n"
                      << "URL     : " << item.url << "\n"
                      << "Date    : " << item.dateAdded << "\n"
                      << std::string(30, '-') << "\n";
        }
    }

    if (!found) {
        std::cout << "\n[!] No records matching '" << query << "' were found.\n";
    }
}

bool VaultManager::deleteEntry(const std::string& service) {
    auto it = std::remove_if(entries.begin(), entries.end(), [&](const CredentialEntry& e) {
        return e.service == service;
    });

    if (it != entries.end()) {
        entries.erase(it, entries.end());
        saveToFile();
        std::cout << "\n[✓] Record for '" << service << "' removed and vault updated.\n";
        return true;
    }

    std::cout << "\n[!] Entry not found.\n";
    return false;
}

std::string VaultManager::generatePassword(int length, bool includeSymbols) {
    const std::string letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const std::string digits = "0123456789";
    const std::string symbols = "!@#$%^&*()-_=+[]{}<>?";

    std::string pool = letters + digits;
    if (includeSymbols) pool += symbols;

    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<size_t> dist(0, pool.size() - 1);

    std::string password = "";
    for (int i = 0; i < length; ++i) {
        password += pool[dist(generator)];
    }
    return password;
}

std::string VaultManager::getCurrentDate() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    char buf[16];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d", std::localtime(&now_c));
    return std::string(buf);
}
