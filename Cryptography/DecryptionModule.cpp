//
// Created by Joe Lou on 7/25/18.
//

#include "DecryptionModule.h"

DecryptionModule::DecryptionModule(EVP_PKEY *userKey, EVP_PKEY *targetPublicKey) : privateKey(userKey),
publicKey(targetPublicKey) {
    initContext();
}

DecryptionModule::~DecryptionModule() {
    EVP_CIPHER_CTX_cleanup(decryptionContext);
}

void DecryptionModule::initContext() {
    decryptionContext = (EVP_CIPHER_CTX*) malloc(sizeof(EVP_CIPHER_CTX));
    EVP_CIPHER_CTX_init(decryptionContext);
    verificationContext = EVP_MD_CTX_create();
}

unsigned char* DecryptionModule::decrypt(unsigned char *message, const MessageContext &context) {
    int cleartextLen;
    unsigned char* cleartext;

    cleartextLen = open(message, context.msgLen, context.AESKey, context.keyLen, context.IV, cleartext);
    if(cleartextLen < 0)
        return nullptr;

    int verifyStatus;
    verifyStatus = verify(cleartext, context.bodyLen, context.sigLen);
    if(verifyStatus == 1)
        return cleartext;
    return nullptr;
}

int DecryptionModule::open(unsigned char *message, size_t msgLen, unsigned char *AESKey, int keyLen,
                           unsigned char *IV, unsigned char *&cleartext) {
    int numDecrypted = 0;
    int totalLen = 0;
    cleartext = (unsigned char*) malloc(msgLen);

    if(!EVP_OpenInit(decryptionContext, EVP_aes_256_cbc(), AESKey, keyLen, IV, privateKey))
        return -1;
    if(!EVP_OpenUpdate(decryptionContext, cleartext, &numDecrypted, message, (int) msgLen))
        return -1;
    totalLen += numDecrypted;
    if(!EVP_OpenFinal(decryptionContext, cleartext + numDecrypted, &numDecrypted))
        return -1;
    totalLen += numDecrypted;

    EVP_CIPHER_CTX_cleanup(decryptionContext);

    return totalLen;
}

int DecryptionModule::verify(unsigned char *message, size_t bodyLen, size_t sigLen) {
    if(!EVP_DigestVerifyInit(verificationContext, nullptr, EVP_sha256(), nullptr, publicKey))
        return -1;
    if(!EVP_DigestVerifyUpdate(verificationContext, message, bodyLen))
        return -1;
    return EVP_DigestVerifyFinal(verificationContext, message + bodyLen, sigLen);
}