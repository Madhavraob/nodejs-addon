//
// Created by Joe Lou on 7/25/18.
//

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "MessageContext.h"

#ifndef ENCRYPTIONDEMO_DECRYPTIONMODULE_H
#define ENCRYPTIONDEMO_DECRYPTIONMODULE_H

/* This class implements decryption and signature verification of the messages encrypted
 * using the method described in EncryptionModule. */

class DecryptionModule {
public:
    /* The constructor takes the public and private keys to be used. */
    DecryptionModule(EVP_PKEY *userKey, EVP_PKEY *targetPublicKey);

    /* The destructor just handles memory management. */
    ~DecryptionModule();

    /* This function initializes the decryption context. It can be called multiple times
     * to encrypt multiple files, but as it currently stands the previous contexts will be
     * leaked. */
    void initContext();

    /* This function performs decryption of a signed and encrypted messsage. It first uses
     * the open function to decrypt the message, then uses the verify function to verify
     * the signature. If the message decrypts successfully and the signature is verified to
     * match, returns the decrypted cleartext, otherwise returns nullptr. NOTE: the returned
     * cleartext is dynamically allocated; the user is responsible for freeing this memory. */
    unsigned char* decrypt(unsigned char* message, const MessageContext &context);

private:
    // OpenSSL variables.
    EVP_CIPHER_CTX *decryptionContext;
    EVP_MD_CTX *verificationContext;
    EVP_PKEY *privateKey;
    EVP_PKEY *publicKey;

    /* This function opens an encrypted message with given length using the constructor
     * initialized private key. It must be supplied with a set of context variables which
     * are contained in a MessageContext object. Returns the length of the cleartext, and
     * sets the cleartext variable to point to the cleartext. NOTE: The returned cleartext
     * is dynamically allocated; the user is responsible for freeing this memory. */
    int open(unsigned char* message, size_t msgLen, unsigned char* AESKey, int keyLen, unsigned char* IV,
             unsigned char* &cleartext);

    /* This function verifies the signature appended to a message against the cleartext of
     * the message. It uses the constructor initialized public key to decrypt the signature.
     * Returns 1 if the verification is successful, 0 otherwise. */
    int verify(unsigned char *message, size_t bodyLen, size_t sigLen);
};


#endif //ENCRYPTIONDEMO_DECRYPTIONMODULE_H
