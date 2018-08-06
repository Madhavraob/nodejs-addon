//
// Created by Joe Lou on 7/25/18.
//

#include "MessageContext.h"
#include <stdio.h>
#include <string.h>

MessageContext::MessageContext() : deserialized(false) {}

MessageContext::~MessageContext() {
    if(this->deserialized) {
        free(this->IV);
        free(this->AESKey);
    }
}

std::string MessageContext::serialize() const {
    std::string out;
    out = std::to_string(this->msgLen) + "|" + std::to_string(this->bodyLen) + "|" + std::to_string(this->sigLen) + "|" + std::to_string(this->IVLen) + "|" +
            std::to_string(this->keyLen) + "|";

    out.append((const char*) this->IV, this->IVLen);
    out.append((const char*) this->AESKey, (size_t) this->keyLen);
    return out;
}

size_t MessageContext::deserialize(std::string str) {
    deserialized = true;
    size_t prevPos = 0;
    size_t currPos = 0;

    // Get the metadata about file sizing.
    for(int i = 0; i < 5; i++) {
        currPos = str.find('|', prevPos);
        std::string data = str.substr(prevPos, currPos - prevPos);
        switch(i) {
            case(0): this->msgLen = stoul(data); break;
            case(1): this->bodyLen = stoul(data); break;
            case(2): this->sigLen = stoul(data); break;
            case(3): this->IVLen = stoul(data); break;
            case(4): this->keyLen = stoi(data); break;
            default: return 0; //Here just to make the compiler happy.
        }
        prevPos = currPos + 1;
    }

    // Now that we have the sizes of the initialization vector and key, we can read them in.
    // Note that we must treat them as raw memory segments and not strings.
    this->IV = (unsigned char*) malloc(this->IVLen);
    this->AESKey = (unsigned char*) malloc((size_t) this->keyLen);
    memcpy(this->IV, str.c_str() + prevPos, this->IVLen);
    memcpy(this->AESKey, str.c_str() + prevPos + this->IVLen, (size_t) this->keyLen);

    return prevPos + this->IVLen + (size_t) this->keyLen;
}