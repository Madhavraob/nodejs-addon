#include <iostream>
#include <fstream>
#include <sys/socket.h>

#include <openssl/pem.h>
#include <openssl/evp.h>

#include "SecureComm.h"

/* The functions in this file implement the command line interface to the cryptography API.
 * Note that the network functionality is not demonstrated here; the networking functions
 * can be found with documentation in Utils/NetworkUtils. */

/* Prompt user for key storage locations, generate a key pair, and save the keys. */
void createKeypair() {
    std::string privatePath;
    std::string password;
    std::string publicPath;

    std::cout << "Where would you like your private key to be stored?" << std::endl;
    getline(std::cin, privatePath);
    //std::cout << "Create a password for your private key: ";
    //getline(std::cin, password);

    std::cout << "Where would you like your public key to be stored?" << std::endl;
    getline(std::cin, publicPath);

    std::cout << "Generating keys..." << std::endl;
    KeyUtils::generateKeyPair(privatePath, publicPath, password);

    std::cout << "User creation complete." << std::endl;
}

/* Given the keys to encrypt with, the data to encrypt, and the file to write to, this function
 * interfaces with the API to do the actual encryption. */
void encryptToFile(EVP_PKEY *privateKey, EVP_PKEY *publicKey, const unsigned char* data, size_t length) {
    std::string outPath;
    std::cout << "Where would you like to save the file?" << std::endl;
    getline(std::cin, outPath);

    MessageContext context;
    EncryptionModule encrypter(privateKey, publicKey);
    unsigned char* encryptedData = encrypter.encrypt(data, length, context.msgLen);
    encrypter.getContext(context);
    IOUtils::writeEncryptedFile(encryptedData, context, const_cast<char*> (outPath.c_str()));
    free(encryptedData);
}

/* Common prompt sequence for both encryption options. Get the public and private keys. */
void doEncryptPrompt(EVP_PKEY** privateKey, EVP_PKEY** publicKey) {
    std::string path;
    std::string password;

    std::cout << "Specify the location of your private key: ";
    getline(std::cin, path);
    //std::cout << "Password: ";
    //getline(std::cin, password);
    *privateKey = KeyUtils::loadPrivateKey(path, password);

    std::cout << "Specify the location of your recipient's public key: ";
    getline(std::cin, path);
    *publicKey = KeyUtils::loadPublicKey(path);

    if(*privateKey == nullptr || *publicKey == nullptr) {
        std::cout << "Error loading keys." << std::endl;
        return;
    }
}

void encryptData(unsigned char* data, size_t length) {
    EVP_PKEY* privateKey;
    EVP_PKEY* publicKey;
    doEncryptPrompt(&privateKey, &publicKey);
    encryptToFile(privateKey, publicKey, data, length);
    std::cout << "Encryption Complete." << std::endl;
}

/* Prompt for file encryption. Get the file to be encrypted. */
void doFileEncryptPrompt() {
    std::string path;
    std::cout << "What file would you like to encrypt?" << std::endl;
    getline(std::cin, path);
    size_t length;
    unsigned char* fileContents = IOUtils::readFile(path, length);
    if(fileContents == nullptr)
        return;

    encryptData(fileContents, length);

    free(fileContents);
}

/* Prompt for text encryption. Get the text to be encrypted. */
void doTextEncryptPrompt() {
    std::string text;
    std::cout << "Input the text you want to encrypt: ";
    getline(std::cin, text);

    encryptData((unsigned char*) text.c_str(), text.length());
}

/* Given a set of keys, a file to decrypt, and a file to write to, this function interfaces with
 * the API to do the actual decryption. */
void decryptToFile(EVP_PKEY *privateKey, EVP_PKEY *publicKey, const std::string &inPath, const std::string &outPath) {
    unsigned char* message;
    MessageContext context = IOUtils::readEncryptedFile(&message, inPath.c_str());

    DecryptionModule decrypter(privateKey, publicKey);
    unsigned char* cleartext = decrypter.decrypt(message, context);

    if(cleartext != nullptr) {
        IOUtils::writeFile(cleartext, outPath.c_str(), context.bodyLen);
        std::cout << "Decryption Complete." << std::endl;
    }
    else
        std::cout << "Decryption Failed; your key may be incorrect or the message may have been modified." << std::endl;
    free(message);
}

/* Prompt user for the information necessary for decryption: file, keys, and new file. */
void doDecryptPrompt() {
    std::string filePath;
    std::cout << "What file would you like to decrypt?" << std::endl;
    getline(std::cin, filePath);

    std::ifstream test(filePath);
    if(!test.is_open()) {
        std::cout << "Unable to open file." << std::endl;
        return;
    }
    test.close();

    std::string path;
    std::string password;
    std::cout << "Specify the location of your private key: ";
    getline(std::cin, path);
    //std::cout << "Password: ";
    //getline(std::cin, password);
    EVP_PKEY *privateKey = KeyUtils::loadPrivateKey(path, password);

    std::cout << "Specify the location of the sender's public key: ";
    getline(std::cin, path);
    EVP_PKEY *publicKey = KeyUtils::loadPublicKey(path);

    if(privateKey == nullptr || publicKey == nullptr) {
        std::cout << "Error loading keys." << std::endl;
        return;
    }

    std::string outPath;
    std::cout << "Where would you like to save the file?" << std::endl;
    getline(std::cin, outPath);

    decryptToFile(privateKey, publicKey, filePath, outPath);
}

void doSendPrompt() {
    std::string path;
    std::string ip;
    std::cout << "What file would you like to send?" << std::endl;
    getline(std::cin, path);

    std::cout << "What IP would you like to send it to?" << std::endl;
    getline(std::cin, ip);
    int socket = NetworkUtils::connectToServer(ip);

    if(socket == -1) {
        std::cout << "Couldn't connect to server." << std::endl;
        return;
    }

    size_t length;
    char* fileContents = (char*) IOUtils::readFile(path, length);
    if(fileContents == nullptr)
        return;

    NetworkUtils::sendData(fileContents, length, socket);
    free(fileContents);
    close(socket);
}

void doReceivePrompt() {
    std::string path;
    std::cout << "Where should the received file be saved?" << std::endl;
    getline(std::cin, path);
    int serverSocket = NetworkUtils::createServerSocket();

    std::cout << "This machine's IP addresses: " << NetworkUtils::getIPAddress() << std::endl;
    int clientSocket = accept(serverSocket, nullptr, nullptr);
    std::cout << "Recieved connection." << std::endl;

    size_t length;
    char* recievedData = NetworkUtils::receiveData(clientSocket, length);
    std::ofstream file(path);
    file.write(recievedData, length);

    free(recievedData);
    close(serverSocket);
    close(clientSocket);
}

void doEncryptAndSendPrompt() {
    std::string path;
    std::cout << "What file would you like to send?" << std::endl;
    getline(std::cin, path);
    size_t length;
    unsigned char* fileContents = IOUtils::readFile(path, length);
    if(fileContents == nullptr)
        return;

    std::string privateKeyPath;
    std::string publicKeyPath;
    std::cout << "Specify private key:" << std::endl;
    getline(std::cin, privateKeyPath);
    std::cout << "Specify public key:" << std::endl;
    getline(std::cin, publicKeyPath);

    std::string ips;
    std::cout << "Input IP(s) of server to connect to:" << std::endl;
    getline(std::cin, ips);

    bool status = SecureComm::encryptAndSendData(fileContents, length, ips, publicKeyPath, privateKeyPath);

    if(!status)
        std::cout << "Failed." << std::endl;
}

void doReceiveAndDecryptPrompt() {
    std::string privateKeyPath;
    std::string publicKeyPath;
    std::cout << "Specify private key:" << std::endl;
    getline(std::cin, privateKeyPath);
    std::cout << "Specify public key:" << std::endl;
    getline(std::cin, publicKeyPath);

    std::cout << "This machine's IP addresses: " << NetworkUtils::getIPAddress() << std::endl;

    size_t length;
    unsigned char* data = SecureComm::receiveDataAndDecrypt(publicKeyPath, privateKeyPath, length);

    if(data == nullptr)
        std::cout << "Failed." << std::endl;
    else{
        std::string path;
        std::cout << "Where would you like the file to be saved?" << std::endl;
        getline(std::cin, path);
        IOUtils::writeFile(data, path.c_str(), length);
    }
}

int main() {
    while(true) {
        std::string input;

        // I am assuming that we never want to decrypt text since the user would need some way to type the
        // special characters that often come out.
        std::cout << "Create Keypair (1), Encrypt File (2), Encrypt Text (3), Decrypt File (4), Send File (5), "
                     "Receive File (6)? (0 to quit) Encrypt and Send File (7), Receive and Decrypt File (8) ? (0 to quit)"
                  << std::endl;
        getline(std::cin, input);
        if (input == "1")
            createKeypair();
        else if (input == "2")
            doFileEncryptPrompt();
        else if (input == "3")
            doTextEncryptPrompt();
        else if (input == "4")
            doDecryptPrompt();
        else if (input == "5")
            doSendPrompt();
        else if(input == "6")
            doReceivePrompt();
        else if(input == "7")
            doEncryptAndSendPrompt();
        else if(input == "8")
            doReceiveAndDecryptPrompt();
        else if (input == "0")
            return 0;
        else
            std::cout << "Unrecognized command." << std::endl;
    }
}