#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>
#include <vector>

// Define constants for our cryptographic parameters.
constexpr int KEY_SIZE = 32; // AES-256 key size in bytes
constexpr int SALT_SIZE = 16; // Standard salt size
constexpr int PBKDF2_ITERATIONS = 100000; // A good baseline for iterations

// A simple alias for a byte vector for clarity.
using byte_vec = std::vector<unsigned char>;

namespace crypto {

/**
 * @brief Derives a key from a password and salt using PBKDF2.
 * @param password The user's password.
 * @param salt A random salt.
 * @param key The output vector to store the derived key.
 * @return True on success, false on failure.
 */
bool derive_key_from_password(const std::string& password, const byte_vec& salt, byte_vec& key);

/**
 * @brief Encrypts a file using AES-256-GCM.
 * Output file format: [SALT][IV][TAG][CIPHERTEXT]
 * @param input_path Path to the file to encrypt.
 * @param output_path Path to write the encrypted file.
 * @param password The password for key derivation.
 * @return True on success, false on failure.
 */
bool encrypt_file(const std::string& input_path, const std::string& output_path, const std::string& password);

/**
 * @brief Decrypts a file encrypted with encrypt_file.
 * @param input_path Path to the encrypted file.
 * @param output_path Path to write the decrypted file.
 * @param password The password for key derivation.
 * @return True on success (and authentication), false on failure.
 */
bool decrypt_file(const std::string& input_path, const std::string& output_path, const std::string& password);

/**
 * @brief Validates password strength
 * @param password The password to validate
 * @return True if password meets minimum requirements
 */
bool validate_password_strength(const std::string& password);

} // namespace crypto

#endif // CRYPTO_H
