//
// Created by Joe Lou on 7/24/18.
//

#include <iostream>

#include <openssl/pem.h>

#include "KeyUtils.h"

void keyUtils::generateKeyPair(const std::string &privatePath, const std::string &publicPath, const std::string &password) {
    EVP_PKEY *keyPair = nullptr;
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if(EVP_PKEY_keygen_init(context) <= 0)
        return;
    if(EVP_PKEY_CTX_set_rsa_keygen_bits(context, 2048) <= 0)
        return;
    if(EVP_PKEY_keygen(context, &keyPair) <= 0)
        return;

    EVP_PKEY_CTX_free(context);

    keyUtils::savePrivateKey(keyPair, privatePath, password);
    keyUtils::savePublicKey(keyPair, publicPath);
}

void keyUtils::savePrivateKey(EVP_PKEY* key, const std::string &filename, const std::string &password){
    BIO* fileBio = BIO_new(BIO_s_file());
    BIO_write_filename(fileBio, (char*) filename.c_str());
    //TODO: Figure out how to get encryption on the private key.
    PEM_write_bio_PrivateKey(fileBio, key, nullptr, nullptr, 0, nullptr, nullptr);
    //int status = PEM_write_bio_PrivateKey(fileBio, key, EVP_des_ede3_cbc(), nullptr,
    //        0, nullptr, (void*) password.c_str());
    //std::cout << std::to_string(status) << std::endl;
    BIO_flush(fileBio);
}

void keyUtils::savePublicKey(EVP_PKEY* key, const std::string &filename){
    BIO* fileBio = BIO_new(BIO_s_file());
    BIO_write_filename(fileBio, (char*) filename.c_str());
    PEM_write_bio_PUBKEY(fileBio, key);
    BIO_flush(fileBio);
}

EVP_PKEY* keyUtils::loadPrivateKey(const std::string &filename, const std::string &password){
    BIO* fileBio = BIO_new(BIO_s_file());
    BIO_read_filename(fileBio, (char*) filename.c_str());
    EVP_PKEY *key = PEM_read_bio_PrivateKey(fileBio, nullptr, nullptr, nullptr);//(unsigned char*) password.c_str());

    return key;
}

EVP_PKEY* keyUtils::loadPublicKey(const std::string &filename){
    BIO* fileBio = BIO_new(BIO_s_file());
    BIO_read_filename(fileBio, (char*) filename.c_str());
    EVP_PKEY *key = PEM_read_bio_PUBKEY(fileBio, nullptr, nullptr, nullptr);

    return key;
}

EVP_PKEY* keyUtils::stringToPublicKey(const std::string &keyString) {
    BIO* memBio = BIO_new(BIO_s_mem());

    //Write the header and footer for the PEM formatted file, along with the key.
    BIO_puts(memBio, "-----BEGIN PUBLIC KEY-----\n");
    BIO_puts(memBio, keyString.c_str());
    BIO_puts(memBio, "-----END PUBLIC KEY-----\n\n");

    //Parse the PEM formatted string.
    return PEM_read_bio_PUBKEY(memBio, nullptr, nullptr, nullptr);
}

std::string keyUtils::publicKeyToString(EVP_PKEY *key) {
    BIO* memBio = BIO_new(BIO_s_mem());

    //Write the key into a bio, then extract the string from the bio.
    PEM_write_bio_PUBKEY(memBio, key);
    char keyStr[450];
    BIO_read(memBio, keyStr, 450);

    std::string PEMKey(keyStr);
    return PEMKey.substr(27, 398);
}

