//
// Created by Joe Lou on 7/24/18.
//

#include "EncryptionModule.h"

EncryptionModule::EncryptionModule(EVP_PKEY *userKeypair, EVP_PKEY *targetPublicKey) : privateKey(userKeypair),
publicKey(targetPublicKey) {
    initContext();
}

EncryptionModule::~EncryptionModule() {
    EVP_CIPHER_CTX_cleanup(encryptionContext);
}

void EncryptionModule::initContext() {
    encryptionContext = (EVP_CIPHER_CTX*) malloc(sizeof(EVP_CIPHER_CTX));
    EVP_CIPHER_CTX_init(encryptionContext);
    signatureContext = EVP_MD_CTX_create();
}

unsigned char* EncryptionModule::encrypt(const unsigned char* cleartext, size_t clearLen, size_t &encLen) {
    unsigned char* encMessage = nullptr;
    bodyLen = clearLen;

    unsigned char* signature = sign(cleartext, bodyLen);
    if(signature == nullptr)
        return nullptr;

    encLen = (size_t) seal(cleartext, signature, encMessage);
    if(encLen <= 0)
        return nullptr;
    return encMessage;
}

int EncryptionModule::seal(const unsigned char* cleartext, unsigned char* signature, unsigned char* &encMessage) {
    AESKey = (unsigned char *) malloc((size_t) EVP_PKEY_size(publicKey));
    IVLen = EVP_MAX_IV_LENGTH;
    IV = (unsigned char*) malloc(IVLen);
    //The encoded message may be padded out to fill the block.
    encMessage = (unsigned char*) malloc(bodyLen + sigLen + EVP_MAX_BLOCK_LENGTH);
    int numEncrypted = 0;
    int totalLength = 0;

    if(!EVP_SealInit(encryptionContext, EVP_aes_256_cbc(), &AESKey, &keyLen, IV, &publicKey, 1))
        return -1;

    // Encrypt the cleartext.
    if(!EVP_SealUpdate(encryptionContext, encMessage, &numEncrypted, cleartext, (int) bodyLen))
        return -1;
    totalLength += numEncrypted;

    //Encrypt the signature.
    if(!EVP_SealUpdate(encryptionContext, encMessage + totalLength, &numEncrypted, signature,
                       (int) sigLen))
        return -1;
    totalLength += numEncrypted;
    if(!EVP_SealFinal(encryptionContext, encMessage + totalLength, &numEncrypted))
        return -1;
    totalLength += numEncrypted;

    return totalLength;
}

unsigned char* EncryptionModule::sign(const unsigned char* encMsg, size_t encLen) {
    if(!EVP_DigestSignInit(signatureContext, nullptr, EVP_sha256(), nullptr, privateKey))
        return nullptr;
    if(!EVP_DigestSignUpdate(signatureContext, encMsg, encLen))
        return nullptr;
    if(!EVP_DigestSignFinal(signatureContext, nullptr, &sigLen))
        return nullptr;
    auto signature = (unsigned char*) malloc(sigLen);
    if(!EVP_DigestSignFinal(signatureContext, signature, &sigLen))
        return nullptr;

    return signature;
}

void EncryptionModule::getContext(MessageContext &context) {
    context.AESKey = this->AESKey;
    context.keyLen = this->keyLen;
    context.IV = this->IV;
    context.IVLen = this->IVLen;
    context.bodyLen = this->bodyLen;
    context.sigLen = this->sigLen;
}