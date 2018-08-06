//
// Created by Joe Lou on 7/26/18.
//

#ifndef ENCRYPTIONDEMO_IOUTILS_H
#define ENCRYPTIONDEMO_IOUTILS_H

#include <openssl/pem.h>

#include <fstream>

#include "../MessageContext.h"

/* This namespace contains utility functions for file I/O */

namespace IOUtils {
    /* Reads an encrypted file. Parses the first part into the encryption context and
     * stores it in a MessageContext object, which it returns. The message itself is
     * passed back through the char**. */
    MessageContext readEncryptedFile(unsigned char** message, const char* filename);

    /* Reads a file. Treats it as a binary file for generality. The length parameter
     * is modified to contain the size of the file. Returns a pointer to a dynamically
     * allocated block of data containing the file contents. NOTE: the user is responsible
     * for freeing this data. */
    unsigned char* readFile(std::string path, size_t &length);

    /* Helper function to write a complete message regardless of I/O failures. */
    void writeComplete(BIO *bio, unsigned char* data, int length);

    /* Writes an encrypted message. First prints the MessageContext, then prints the
     * message itself. */
    void writeEncryptedFile(unsigned char* data, MessageContext context, char* filename);

    /* Writes a normal file using the data pointed to by data. Writes the supplied
     * number of bytes. */
    void writeFile(unsigned char* data, const char* filename, size_t numBytes);
};


#endif //ENCRYPTIONDEMO_IOUTILS_H
