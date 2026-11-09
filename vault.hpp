#ifndef VAULT_HPP
#define VAULT_HPP

#include <string>
#include <vector>

struct CredentialEntry {
    std::string service;
    std::string username;
    std::string password;
    std::string url;
    std::string dateAdded;
};

class VaultManager {
private:
    std::vector<CredentialEntry> entries;
    std::string masterPassword;
    const std::string vaultPath = "vault.bin";

    std::string serializeEntries() const;
    void deserializeEntries(const std::string& raw);

public:
    bool authenticate();
    bool saveToFile();
    bool loadFromFile();
    void addEntry(const CredentialEntry& entry);
    void listEntries() const;
    void searchEntries(const std::string& query) const;
    bool deleteEntry(const std::string& service);
    bool copyPasswordToClipboard(const std::string& service);
    bool changeMasterPassword();

    static std::string generatePassword(int length, bool includeSymbols);
    static std::string getCurrentDate();
};

#endif // VAULT_HPP
