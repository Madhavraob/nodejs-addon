//
// Created by Joe Lou on 7/24/18.
//

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <string>

#include "MessageContext.h"

#ifndef ENCRYPTIONDEMO_ENCRYPTIONMODULE_H
#define ENCRYPTIONDEMO_ENCRYPTIONMODULE_H

/* This class implements RSA/AES based encryption and signing of a data block. The file itself
 * is encrypted using AES-256 encryption, and the AES key (which is generated using a
 * cryptographically secure random number generator) is itself encrypted with RSA-2048.
 * Note that as currently designed, a single EncryptionModule should only be used once;
 * otherwise the encryption context constitutes a memory leak. This may be something to change
 * in the future. */

class EncryptionModule {
public:
    /* The constructor takes in the private and public keys to be used for encryption. */
    EncryptionModule(EVP_PKEY *userKeypair, EVP_PKEY *targetPublicKey);

    /* This function initializes the encryption context. It can be called multiple times
     * to encrypt multiple files, but as it currently stands the previous contexts will be
     * leaked. */
    void initContext();

    /* The destructor cleans up the encryption context to avoid memory leaks. */
    ~EncryptionModule();

    /* This does the actual encryption of a 'cleartext' of the given length. It uses a
     * standard 'sign-and-encrypt' protocol to ensure privacy, immutability, and identity.
     * Returns a pointer to the encrypted data, and encLen is modified to store the length
     * of the encrypted data segment. NOTE: the encrypted data is dynamically allocated; the
     * user is responsible for freeing this memory. */
    unsigned char* encrypt(const unsigned char* cleartext, size_t clearLen, size_t &encLen);

    /* This function saves the necessary metadata for decryption into the provided
     * MessageContext. This data is generated in the encrypt step. */
    void getContext(MessageContext &context);

private:
    // OpenSSL variables, self explanatory.
    EVP_PKEY *privateKey;
    EVP_PKEY *publicKey;
    EVP_CIPHER_CTX *encryptionContext;
    EVP_MD_CTX *signatureContext;

    // Metadata that needs to reach the decryption module.
    unsigned char *AESKey;
    int keyLen;
    unsigned char *IV;
    size_t IVLen;
    size_t bodyLen;
    size_t sigLen;

    /* This function generates a message by appending the provided signature to the provided
     * cleartext. It then leverages the OpenSSL 'seal' function, generating a cryptographically
     * random symmetric key and using it to encrypt the message using AES-256. The symmetric key
     * is then encrypted using RSA-2048 with the constructor-initialized public key. Returns
     * the length of the encrypted message and sets encMessage to point to the encrypted
     * message. Also sets the metada variables for access with getContext. */
    int seal(const unsigned char* cleartext, unsigned char* signature, unsigned char* &encMessage);

    /* This function generates a digital signature for the provided message, whose length should
     * be provided. It first computes a SHA-256 hash of the message, then uses the constructor
     * initialized private key to encrypt that hash value using RSA-2048. Returns the signature,
     * and sets the sigLen internal state variable. */
    unsigned char* sign(const unsigned char* encMsg, size_t encLen);
};


#endif //ENCRYPTIONDEMO_ENCRYPTIONMODULE_H
