#pragma once

// OpenSSL stub definitions for compilation without OpenSSL installed
// This allows the project to compile, but TLS functionality will be limited

#ifndef OPENSSL_STUB_H
#define OPENSSL_STUB_H

#include <windows.h>
#include <stdint.h>

// Basic OpenSSL type definitions
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;
typedef struct x509_st X509;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_cipher_st EVP_CIPHER;
typedef struct evp_md_st EVP_MD;

// Constants
#define TLS1_3_VERSION 0x0304
#define SSL_OP_NO_COMPRESSION 0x00020000UL
#define SSL_VERIFY_PEER 0x01
#define EVP_MAX_MD_SIZE 64
#define AES_BLOCK_SIZE 16

// Function stubs (will return error or do nothing)
inline int SSL_library_init() { return 1; }
inline void SSL_load_error_strings() {}
inline void OpenSSL_add_all_algorithms() {}

inline SSL_CTX* SSL_CTX_new(void* method) { return nullptr; }
inline void SSL_CTX_free(SSL_CTX* ctx) {}
inline int SSL_CTX_set_min_proto_version(SSL_CTX* ctx, int version) { return 1; }
inline int SSL_CTX_set_max_proto_version(SSL_CTX* ctx, int version) { return 1; }
inline void SSL_CTX_set_security_level(SSL_CTX* ctx, int level) {}
inline void SSL_CTX_set_options(SSL_CTX* ctx, long options) {}
inline int SSL_CTX_set_ciphersuites(SSL_CTX* ctx, const char* str) { return 1; }
inline void SSL_CTX_set_verify(SSL_CTX* ctx, int mode, void* callback) {}
inline void SSL_CTX_set_verify_depth(SSL_CTX* ctx, int depth) {}
inline int SSL_CTX_set_default_verify_paths(SSL_CTX* ctx) { return 1; }

inline void* TLS_client_method() { return nullptr; }

inline X509* SSL_get_peer_certificate(SSL* ssl) { return nullptr; }
inline void X509_free(X509* x) {}
inline int X509_digest(const X509* data, const EVP_MD* type, unsigned char* md, unsigned int* len) { return 0; }

inline void SSL_shutdown(SSL* ssl) {}
inline void SSL_free(SSL* ssl) {}

inline EVP_CIPHER_CTX* EVP_CIPHER_CTX_new() { return nullptr; }
inline void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX* ctx) {}

inline const EVP_CIPHER* EVP_aes_256_cbc() { return nullptr; }
inline const EVP_MD* EVP_sha256() { return nullptr; }

inline int EVP_EncryptInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, void* engine, const unsigned char* key, const unsigned char* iv) { return 0; }
inline int EVP_EncryptUpdate(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl, const unsigned char* in, int inl) { return 0; }
inline int EVP_EncryptFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl) { return 0; }

inline int EVP_DecryptInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, void* engine, const unsigned char* key, const unsigned char* iv) { return 0; }
inline int EVP_DecryptUpdate(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl, const unsigned char* in, int inl) { return 0; }
inline int EVP_DecryptFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl) { return 0; }

inline int RAND_bytes(unsigned char* buf, int num) { 
    // Fallback to Windows CryptoAPI
    return 0; // Will trigger fallback in actual code
}

inline int PKCS5_PBKDF2_HMAC(const char* pass, int passlen, const unsigned char* salt, int saltlen, int iter, const EVP_MD* digest, int keylen, unsigned char* out) { 
    return 0; 
}

inline void OPENSSL_cleanse(void* ptr, size_t len) {
    SecureZeroMemory(ptr, len);
}

#endif // OPENSSL_STUB_H