#include "crypto.h"
#include <fstream>
#include <iostream>
#include <cctype>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

// Define constants for GCM parameters
constexpr int GCM_IV_SIZE = 12;  // Recommended IV size for GCM
constexpr int GCM_TAG_SIZE = 16; // Authentication tag size

// Helper function to print OpenSSL errors for debugging
void handle_openssl_errors() {
    unsigned long err_code;
    while ((err_code = ERR_get_error())) {
        char err_buf[256];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        std::cerr << "OpenSSL Error: " << err_buf << std::endl;
    }
}

// Helper function to read a whole file into a byte vector.
byte_vec read_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) return {};
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    byte_vec buffer(size);
    if (size > 0 && file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        return buffer;
    }
    return buffer; // Return empty buffer for empty files
}

// Helper function to write a byte vector to a file.
bool write_file(const std::string& path, const byte_vec& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file) return false;
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    return file.good();
}

namespace {
    // RAII wrapper for OpenSSL initialization
    struct OpenSSLInit {
        OpenSSLInit() {
            OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | 
                              OPENSSL_INIT_ADD_ALL_CIPHERS |
                              OPENSSL_INIT_ADD_ALL_DIGESTS, nullptr);
        }
        ~OpenSSLInit() {
            OPENSSL_cleanup();
        }
    };
    static OpenSSLInit openssl_init;

    // Secure memory zeroing
    void secure_zero(void* ptr, size_t size) {
        OPENSSL_cleanse(ptr, size);
    }

    // RAII wrapper for EVP_CIPHER_CTX
    class CipherContext {
    private:
        EVP_CIPHER_CTX* ctx;
    public:
        CipherContext() : ctx(EVP_CIPHER_CTX_new()) {}
        ~CipherContext() { 
            if (ctx) EVP_CIPHER_CTX_free(ctx); 
        }
        EVP_CIPHER_CTX* get() { return ctx; }
        operator bool() const { return ctx != nullptr; }
        // Prevent copying
        CipherContext(const CipherContext&) = delete;
        CipherContext& operator=(const CipherContext&) = delete;
    };

    // RAII wrapper for secure data
    class SecureBuffer {
    private:
        byte_vec data;
    public:
        SecureBuffer() = default;
        explicit SecureBuffer(size_t size) : data(size) {}
        SecureBuffer(byte_vec&& vec) : data(std::move(vec)) {}
        ~SecureBuffer() {
            if (!data.empty()) {
                secure_zero(data.data(), data.size());
            }
        }
        byte_vec& get() { return data; }
        const byte_vec& get() const { return data; }
        // Move only
        SecureBuffer(SecureBuffer&& other) noexcept : data(std::move(other.data)) {}
        SecureBuffer& operator=(SecureBuffer&& other) noexcept {
            if (this != &other) {
                if (!data.empty()) {
                    secure_zero(data.data(), data.size());
                }
                data = std::move(other.data);
            }
            return *this;
        }
        SecureBuffer(const SecureBuffer&) = delete;
        SecureBuffer& operator=(const SecureBuffer&) = delete;
    };
}

bool crypto::validate_password_strength(const std::string& password) {
    if (password.length() < 8) {
        std::cerr << "Error: Password must be at least 8 characters long" << std::endl;
        return false;
    }

    bool hasUpper = false, hasLower = false, hasDigit = false;
    for (char c : password) {
        if (std::isupper(c)) hasUpper = true;
        if (std::islower(c)) hasLower = true;
        if (std::isdigit(c)) hasDigit = true;
    }

    if (!hasUpper || !hasLower || !hasDigit) {
        std::cout << "Warning: Weak password detected. Consider using uppercase, lowercase, and numbers for better security." << std::endl;
    }

    return true;
}

bool crypto::derive_key_from_password(const std::string& password, const byte_vec& salt, byte_vec& key) {
    key.resize(KEY_SIZE);
    int result = PKCS5_PBKDF2_HMAC(
        password.c_str(),
        password.length(),
        salt.data(),
        salt.size(),
        PBKDF2_ITERATIONS,
        EVP_sha256(),
        KEY_SIZE,
        key.data()
    );
    if (result != 1) {
        secure_zero(key.data(), key.size());
        handle_openssl_errors();
        return false;
    }
    return true;
}

bool crypto::encrypt_file(const std::string& input_path, const std::string& output_path, const std::string& password) {
    if (input_path.empty() || output_path.empty()) {
        std::cerr << "Error: Invalid file paths." << std::endl;
        return false;
    }

    // Check if input file exists and can be opened
    std::ifstream test_file(input_path, std::ios::binary);
    if (!test_file) {
        std::cerr << "Error: Could not open input file: " << input_path << std::endl;
        return false;
    }
    test_file.close();

    SecureBuffer plaintext_buffer(read_file(input_path));
    byte_vec& plaintext = plaintext_buffer.get();
    
    // Allow empty files to be encrypted
    if (plaintext.empty()) {
        std::cout << "Warning: Input file is empty, but will be encrypted anyway." << std::endl;
    }

    byte_vec salt(SALT_SIZE);
    if (RAND_bytes(salt.data(), salt.size()) != 1) {
        handle_openssl_errors();
        return false;
    }

    SecureBuffer key_buffer;
    byte_vec& key = key_buffer.get();
    if (!derive_key_from_password(password, salt, key)) {
        secure_zero(salt.data(), salt.size());
        return false;
    }

    CipherContext ctx;
    if (!ctx) {
        handle_openssl_errors();
        return false;
    }

    byte_vec iv(GCM_IV_SIZE);
    if (RAND_bytes(iv.data(), iv.size()) != 1) {
        handle_openssl_errors();
        return false;
    }

    // 1. Initialize encryption operation.
    if (1 != EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        handle_openssl_errors();
        return false;
    }
    // 2. Set IV length.
    if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL)) {
        handle_openssl_errors();
        return false;
    }
    // 3. Provide key and IV.
    if (1 != EVP_EncryptInit_ex(ctx.get(), NULL, NULL, key.data(), iv.data())) {
        handle_openssl_errors();
        return false;
    }

    // Initialize ciphertext with extra space for padding
    byte_vec ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0;
    // 4. Encrypt plaintext.
    if (1 != EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len, plaintext.data(), plaintext.size())) {
        handle_openssl_errors();
        return false;
    }
    int ciphertext_len = len;

    // 5. Finalize encryption.
    if (1 != EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len)) {
        handle_openssl_errors();
        return false;
    }
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    byte_vec tag(GCM_TAG_SIZE);
    // 6. Get the authentication tag.
    if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data())) {
        handle_openssl_errors();
        return false;
    }

    // 7. Assemble the output file: [salt][iv][tag][ciphertext]
    byte_vec output_data;
    output_data.reserve(salt.size() + iv.size() + tag.size() + ciphertext.size());
    output_data.insert(output_data.end(), salt.begin(), salt.end());
    output_data.insert(output_data.end(), iv.begin(), iv.end());
    output_data.insert(output_data.end(), tag.begin(), tag.end());
    output_data.insert(output_data.end(), ciphertext.begin(), ciphertext.end());
    
    // Clean up sensitive data
    secure_zero(salt.data(), salt.size());
    secure_zero(iv.data(), iv.size());
    secure_zero(ciphertext.data(), ciphertext.size());
    
    return write_file(output_path, output_data);
}

bool crypto::decrypt_file(const std::string& input_path, const std::string& output_path, const std::string& password) {
    if (input_path.empty() || output_path.empty()) {
        std::cerr << "Error: Invalid file paths." << std::endl;
        return false;
    }

    // Check if input file exists
    std::ifstream test_file(input_path, std::ios::binary);
    if (!test_file) {
        std::cerr << "Error: Could not open encrypted file: " << input_path << std::endl;
        return false;
    }
    test_file.close();

    byte_vec encrypted_data = read_file(input_path);
    if (encrypted_data.empty()) {
        std::cerr << "Error: Encrypted file is empty or could not be read." << std::endl;
        return false;
    }

    if (encrypted_data.size() < (SALT_SIZE + GCM_IV_SIZE + GCM_TAG_SIZE)) {
        std::cerr << "Error: File is corrupted or not properly encrypted (too small)." << std::endl;
        return false;
    }

    // 1. Deconstruct the file: [salt][iv][tag][ciphertext]
    auto current = encrypted_data.begin();
    byte_vec salt(current, current + SALT_SIZE);
    current += SALT_SIZE;
    byte_vec iv(current, current + GCM_IV_SIZE);
    current += GCM_IV_SIZE;
    byte_vec tag(current, current + GCM_TAG_SIZE);
    current += GCM_TAG_SIZE;
    byte_vec ciphertext(current, encrypted_data.end());

    SecureBuffer key_buffer;
    byte_vec& key = key_buffer.get();
    if (!derive_key_from_password(password, salt, key)) {
        secure_zero(salt.data(), salt.size());
        return false;
    }

    CipherContext ctx;
    if (!ctx) {
        handle_openssl_errors();
        return false;
    }

    // 2. Initialize decryption.
    if (1 != EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        handle_openssl_errors();
        return false;
    }
    // 3. Set IV length.
    if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL)) {
        handle_openssl_errors();
        return false;
    }
    // 4. Provide key and IV.
    if (1 != EVP_DecryptInit_ex(ctx.get(), NULL, NULL, key.data(), iv.data())) {
        handle_openssl_errors();
        return false;
    }

    SecureBuffer plaintext_buffer(ciphertext.size());
    byte_vec& plaintext = plaintext_buffer.get();
    int len = 0;
    // 5. Decrypt ciphertext.
    if (1 != EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, ciphertext.data(), ciphertext.size())) {
        handle_openssl_errors();
        return false;
    }
    int plaintext_len = len;

    // 6. Set the expected authentication tag. THIS MUST BE DONE BEFORE FINALIZING.
    if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data())) {
        handle_openssl_errors();
        return false;
    }

    // 7. Finalize decryption. This is the step that performs the authentication check.
    // If the tag does not match, this function will fail.
    int result = EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len);
    
    // Clean up sensitive data
    secure_zero(salt.data(), salt.size());
    secure_zero(iv.data(), iv.size());
    secure_zero(ciphertext.data(), ciphertext.size());
    
    if (result > 0) {
        // Success! Authentication passed.
        plaintext_len += len;
        plaintext.resize(plaintext_len);
        bool write_success = write_file(output_path, plaintext);
        return write_success;
    } else {
        // Failure! Authentication failed. This means the password was wrong OR the file was tampered with.
        std::cerr << "Error: Decryption failed. The password may be incorrect or the file is corrupt." << std::endl;
        handle_openssl_errors();
        return false;
    }
}
