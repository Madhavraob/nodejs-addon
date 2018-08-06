//
// Created by Joe Lou on 7/24/18.
//

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <unordered_map>

#ifndef ENCRYPTIONDEMO_KEYCHAIN_H
#define ENCRYPTIONDEMO_KEYCHAIN_H

/* This namespace contains utility functions related to key generation and storage. */

namespace keyUtils {
    /* Generate a key pair and store the keys in the paths specified. The private key will be encrypted using
     * 3DES encryption and the supplied password. */
    void generateKeyPair(const std::string &privatePath, const std::string &publicPath, const std::string &password);

    /* Save a private key to a file using 3DES encryption and the specified password. */
    void savePrivateKey(EVP_PKEY *key, const std::string &filename, const std::string &password);
    /* Save a public key to a file. */
    void savePublicKey(EVP_PKEY *key, const std::string &filename);

    /* Load a private key from a file, attempting to access it using the supplied password. Returns nullptr
     * on failure. */
    EVP_PKEY* loadPrivateKey(const std::string &filename, const std::string &password);
    /* Load a public key from a file. Returns nullptr on failure. */
    EVP_PKEY* loadPublicKey(const std::string &filename);

    /* Convert a string containing a public key in PEM format to an EVP key object. */
    EVP_PKEY* stringToPublicKey(const std::string &keyString);

    /* Convert a public key to a PEM formatted string, minus the header and footer.
     * This is what we want to store on the key server. */
    std::string publicKeyToString(EVP_PKEY* key);
};


#endif //ENCRYPTIONDEMO_KEYCHAIN_H
