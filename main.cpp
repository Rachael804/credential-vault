#include "vault.hpp"
#include <iostream>
#include <string>
#include <limits>

void printBanner() {
    std::cout << "\n"
              << "=====================================================\n"
              << "       SECURE CLI CREDENTIAL & PASSWORD VAULT        \n"
              << "=====================================================\n"
              << " [1] View All Stored Credentials\n"
              << " [2] Search Credential by Service\n"
              << " [3] Add New Credential\n"
              << " [4] Generate Cryptographic Password\n"
              << " [5] Delete a Credential\n"
              << " [6] Save & Exit Vault\n"
              << "=====================================================\n"
              << "Select an option [1-6]: ";
}

int main() {
    VaultManager vault;

    std::cout << "\n=====================================================\n";
    std::cout << "       SECURE CLI CREDENTIAL VAULT AUTHENTICATION     \n";
    std::cout << "=====================================================\n";

    if (!vault.authenticate()) {
        std::cout << "Exiting application.\n";
        return 1;
    }

    int choice = 0;
    while (true) {
        printBanner();
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "\n[!] Invalid input. Enter a number between 1 and 6.\n";
            continue;
        }

        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        if (choice == 1) {
            vault.listEntries();
        } else if (choice == 2) {
            std::cout << "Enter service name to search: ";
            std::string q;
            std::getline(std::cin, q);
            vault.searchEntries(q);
        } else if (choice == 3) {
            CredentialEntry entry;
            std::cout << "Service Name (e.g. GitHub): ";
            std::getline(std::cin, entry.service);
            std::cout << "Username/Email: ";
            std::getline(std::cin, entry.username);

            std::cout << "Generate a strong password automatically? (y/n): ";
            char genChoice;
            std::cin >> genChoice;
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

            if (genChoice == 'y' || genChoice == 'Y') {
                entry.password = VaultManager::generatePassword(16, true);
                std::cout << "[Generated Password]: " << entry.password << "\n";
            } else {
                std::cout << "Enter password: ";
                std::getline(std::cin, entry.password);
            }

            std::cout << "Service URL (optional): ";
            std::getline(std::cin, entry.url);
            entry.dateAdded = VaultManager::getCurrentDate();

            vault.addEntry(entry);
        } else if (choice == 4) {
            int len = 16;
            std::cout << "Desired password length (default 16): ";
            if (!(std::cin >> len) || len <= 4) len = 16;
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

            std::string generated = VaultManager::generatePassword(len, true);
            std::cout << "\n[+] Generated Key: " << generated << "\n";
        } else if (choice == 5) {
            std::cout << "Enter exact service name to delete: ";
            std::string svc;
            std::getline(std::cin, svc);
            vault.deleteEntry(svc);
        } else if (choice == 6) {
            vault.saveToFile();
            std::cout << "\n[✓] Vault encrypted and closed safely.\n";
            break;
        } else {
            std::cout << "\n[!] Unknown choice. Select 1 through 6.\n";
        }
    }

    return 0;
}
