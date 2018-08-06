//
// Created by Joe Lou on 7/30/18.
//

#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#include "NetworkUtils.h"
#include "IOUtils.h"

std::string NetworkUtils::getIPAddress() {
    struct ifaddrs *addr;
    getifaddrs(&addr);
    std::string ips;

    while(addr != nullptr && addr->ifa_addr != nullptr) {
        if(addr->ifa_addr->sa_family != AF_INET) {
            addr = addr->ifa_next;
            continue;
        }

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(((sockaddr_in *) addr->ifa_addr)->sin_addr), ip, INET_ADDRSTRLEN);

        //Localhost will cause issues if we allow it.
        if(strcmp(ip, "127.0.0.1") == 0) {
            addr = addr->ifa_next;
            continue;
        }

        ips += ip;
        ips += ",";
        addr = addr->ifa_next;
    }
    //Remove last comma.
    ips.resize(ips.length() - 1);
    return ips;
}

int NetworkUtils::connectToServer(const std::string &addresses, unsigned short port) {
    size_t prevPos = 0;
    size_t currPos = 0;

    while((currPos = addresses.find(',', prevPos)) != std::string::npos){
        std::string address = addresses.substr(prevPos, currPos - prevPos);
        int result = NetworkUtils::createClientSocket(address, port);
        if(result != -1)
            return result;
    }
    return -1;
}

int NetworkUtils::createClientSocket(const std::string& host, unsigned short port) {
    struct hostent *he = gethostbyname(host.c_str());
    if (he == nullptr) return -1;

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;

    struct sockaddr_in serverAddress;
    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(port);
    serverAddress.sin_addr.s_addr = ((struct in_addr *)he->h_addr)->s_addr;

    if (connect(s, (struct sockaddr *) &serverAddress, sizeof(serverAddress)) == 0)
        return s;

    close(s);
    return -1;
}

int NetworkUtils::createServerSocket(unsigned short port) {
    const int kReuseAddresses = 1;
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) return -1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &kReuseAddresses, sizeof(int)) < 0) {
        close(serverSocket);
        return -1;
    } // setsockopt used here so port becomes available even if server crashes and reboots

    struct sockaddr_in serverAddress; // IPv4-style socket address
    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET; // sin_family field used to self-identify sockaddr type
    serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddress.sin_port = htons(port);

    if (bind(serverSocket, (struct sockaddr *) &serverAddress, sizeof(struct sockaddr_in)) == 0 &&
        listen(serverSocket, 128) == 0) return serverSocket;

    close(serverSocket);
    return -1;
}

void NetworkUtils::sendData(char *data, size_t length, int serverSocket) {
    size_t numWritten = 0;

    //Prepend the length of the message.
    std::string lengthStr = std::to_string(length) + '|';
    while(numWritten < lengthStr.length())
        numWritten += write(serverSocket, lengthStr.c_str() + numWritten, (int) lengthStr.length() - numWritten);

    //Reset and send the message itself.
    numWritten = 0;
    while(numWritten < length)
        numWritten += write(serverSocket, data + numWritten, (int) length - numWritten);
}

char* NetworkUtils::receiveData(int clientSocket, size_t &length) {
    size_t numRead = 0;
    char c = 0;
    std::string lengthStr;

    //Read the length of the message.
    while(c != '|') {
        read(clientSocket, &c, 1);
        lengthStr += c;
    }
    length = std::stoul(lengthStr);

    //Read the message itself.
    auto data = (char*) malloc(length);
    while(numRead < length)
        numRead += read(clientSocket, data + numRead, (int) length - numRead);

    return data;
}
