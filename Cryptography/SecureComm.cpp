//
// Created by Joe Lou on 8/2/18.
//

#include "SecureComm.h"

#include <sys/socket.h>

bool SecureComm::encryptAndSendData(const unsigned char *data, size_t length, const std::string &ips,
                                    const std::string &publicKeyPath, const std::string &privateKeyPath,
                                    unsigned short port) {
    //Load keys.
    EVP_PKEY* privateKey = KeyUtils::loadPrivateKey(privateKeyPath, "");
    EVP_PKEY* publicKey = KeyUtils::loadPublicKey(publicKeyPath);
    if(privateKey == nullptr || publicKey == nullptr)
        return false;

    //Encrypt the data and get the context.
    EncryptionModule encrypter(privateKey, publicKey);
    MessageContext context;
    unsigned char* message = encrypter.encrypt(data, length, context.msgLen);
    if(message == nullptr)
        return false;
    encrypter.getContext(context);

    //Package the data and context together into a message for communication.
    std::string encryptedMessage = IOUtils::writeEncryptedMessage(message, context);
    free(message);

    //Connect to the server, and send the message.
    int socket = NetworkUtils::connectToServer(ips, port);
    if(socket == -1)
        return false;
    NetworkUtils::sendData(const_cast<char*> (encryptedMessage.c_str()), encryptedMessage.length(), socket);

    close(socket);
    return true;
}

unsigned char* SecureComm::receiveDataAndDecrypt(const std::string &publicKeyPath, const std::string &privateKeyPath,
                                                 size_t &clearLength, int serverSocket, unsigned short port) {
    //Load Keys.
    EVP_PKEY* privateKey = KeyUtils::loadPrivateKey(privateKeyPath, "");
    EVP_PKEY* publicKey = KeyUtils::loadPublicKey(publicKeyPath);
    if(privateKey == nullptr || publicKey == nullptr)
        return nullptr;

    //If the user has not provided a server socket, create one.
    bool createdSocket = (serverSocket < 0);
    if(createdSocket)
        serverSocket = NetworkUtils::createServerSocket(port);
    if(serverSocket < -1)
        return nullptr;

    //Wait for client to connect.
    int clientSocket = accept(serverSocket, nullptr, nullptr);
    if(clientSocket < -1)
        return nullptr;

    //Receive the client's message, and do some cleanup.
    size_t length;
    auto data = (unsigned char*) NetworkUtils::receiveData(clientSocket, length);
    if(data == nullptr)
        return nullptr;
    if(createdSocket)
        close(serverSocket);
    close(clientSocket);
    std::string dataStr((char*) data, length);
    free(data);

    //Parse the message into a context and a payload.
    unsigned char* message;
    MessageContext context = IOUtils::readEncryptedMessage(&message, dataStr);

    //Decrypt the payload.
    DecryptionModule decrypter(privateKey, publicKey);
    unsigned char* cleartext = decrypter.decrypt(message, context);
    free(message);

    clearLength = context.bodyLen;
    return cleartext;
}