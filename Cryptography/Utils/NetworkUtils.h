//
// Created by Joe Lou on 7/30/18.
//

#ifndef ENCRYPTIONDEMO_NETWORKUTILS_H
#define ENCRYPTIONDEMO_NETWORKUTILS_H

#include <string>
#include <unistd.h>

/* This namespace contains utility functions for networked communication.
 * The send/recieve data functions are currently untested. */

namespace NetworkUtils {
    /* Returns all of the IPv4 addresses associated with this machine, comma delimited.
     * On my computer at least, the first one is the one to use.*/
    std::string getIPAddress();

    /* Given a comma delimited string of IP addresses, tries all of them until it
     * successfully connects to one, then configures a client socket connected to
     * that address. Returns the socket descriptor, or -1 on failure. */
    int connectToServer( const std::string &addresses, unsigned short port=13370);

    /* Configures and creates a client socket connected to the specified host and port.
     * Returns the socket descriptor, or -1 on failure. */
    int createClientSocket( const std::string &host, unsigned short port=13370 );

    /* Configures and creates a server socket listening to all addresses on this machine,
     * with the specified port. Returns the socket descriptor, or -1 on failure. */
    int createServerSocket(unsigned short port=13370);

    /* Sends length bytes of the memory pointed to by data to the specified socket.
     * Prepends the length to the message so that the recipient knows how long it is. */
    void sendData(char* data, size_t length, int serverSocket);

    /* Recieves bytes from the specified socket and returns a pointer to the data. The
     * length of this data is MUST be prepended to the data, delimited by a '|'. The
     * returned pointer is to dynamically allocated data; the user is responsible for
     * freeing it. Length is modified to be the number of bytes read. */
    char* receiveData(int clientSocket, size_t &length);
};


#endif //ENCRYPTIONDEMO_NETWORKUTILS_H
