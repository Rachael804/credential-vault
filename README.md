# Personal Encrypted Credential Vault (C++17 CLI)

A secure, terminal-based credential manager and password vault engineered in modern C++17. Designed to provide local-first, zero-knowledge credential storage secured via cryptographic hashing and payload stream encryption.

---

## 🔒 Security Architecture

* **Authentication & Key Derivation**: SHA-256 digests verify master passwords without storing plaintext secrets.
* **Encrypted Storage at Rest**: Serialized records are encrypted and written to a binary file (`vault.bin`).
* **Cryptographic Password Generation**: Implements a uniform distribution pseudo-random generator supporting configurable entropy sets (alphanumeric + high-entropy symbols).
* **Defensive Memory Hygiene**: Decrypted credential structs exist solely in RAM during execution and are committed back to disk with immediate stream flushes.

---

## 🛠️ Features & CLI Interface

* **`[1] View Stored Credentials`**: Outputs decrypted records in an aligned terminal table.
* **`[2] Search Credential by Service`**: Linear-time substring filter across stored domains.
* **`[3] Add New Credential`**: Manual entry or one-key automated strong password generation.
* **`[4] Generate Cryptographic Password`**: Custom length password generator.
* **`[5] Delete a Credential`**: In-place removal and re-serialization of vault contents.
* **`[6] Save & Exit Vault`**: Cryptographic flush and process termination.

---

## 🚀 Build & Compilation

### Using Code::Blocks:
1. Open `credential-vault.cbp` in Code::Blocks 25.03+.
2. Build target: `Debug` or `Release`.
3. Press `F9` (Build & Run).

### Using GCC / G++ (C++17):
```powershell
g++ -std=c++17 main.cpp vault.cpp crypto.cpp -o vault.exe
.\vault.exe