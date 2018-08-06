//
// Created by Joe Lou on 7/26/18.
//

#include "IOUtils.h"
#include <iostream>

MessageContext IOUtils::readEncryptedFile(unsigned char** message, const char* filename) {
    std::ifstream stream(filename);
    std::string contents( (std::istreambuf_iterator<char>(stream) ), (std::istreambuf_iterator<char>() ));
    MessageContext context;
    size_t pos = context.deserialize(contents);
    *message = (unsigned char*) malloc(context.msgLen + context.sigLen);
    memcpy(*message, contents.c_str() + pos, context.msgLen + context.sigLen);
    stream.close();
    return context;
}

unsigned char* IOUtils::readFile(std::string path, size_t &length) {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if(!stream.is_open()) {
        std::cout << "Unable to open file." << std::endl;
        return nullptr;
    }

    length = (size_t) stream.tellg();
    stream.seekg(0, std::ios::beg);
    auto fileContents = (unsigned char*) malloc(length);
    stream.read((char*) fileContents, length);
    stream.close();
    return fileContents;
}

void IOUtils::writeComplete(BIO *bio, unsigned char* data, int length) {
    int numWritten = 0;
    while(numWritten < length)
        numWritten += BIO_write(bio, data + numWritten, length - numWritten);
}

void IOUtils::writeEncryptedFile(unsigned char* data, MessageContext context, char* filename) {
    BIO *fileBio = BIO_new(BIO_s_file());
    BIO_write_filename(fileBio, filename);
    std::string contextString = context.serialize();
    writeComplete(fileBio, (unsigned char*) contextString.c_str(), (int) contextString.length());

    writeComplete(fileBio, data, (int) context.msgLen);

    BIO_flush(fileBio);
}

void IOUtils::writeFile(unsigned char* data, const char* filename, size_t numBytes) {
    std::ofstream outputFile;
    outputFile.open(filename, std::ios::binary);
    outputFile.write((const char*) data, (std::streamsize) numBytes);
    outputFile.close();
}