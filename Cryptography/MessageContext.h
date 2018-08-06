//
// Created by Joe Lou on 7/25/18.
//

#include <string>

#ifndef ENCRYPTIONDEMO_MESSAGECONTEXT_H
#define ENCRYPTIONDEMO_MESSAGECONTEXT_H

/* This class describes the contextual information needed to decrypt a message. Various metadata
 * about the file size breakdown are stored, along with the RSA-encrypted AES key to encrypt the
 * actual file and its initialization vector. This information MUST reach the decryption module
 * for successful decryption. */

class MessageContext{
public:
    //This class doesn't adhere to data privacy because it's used more or less as a POD. (+ serialization)
    size_t msgLen;
    unsigned char *AESKey;
    int keyLen;
    unsigned char *IV;
    size_t IVLen;
    size_t bodyLen;
    size_t sigLen;

    /* This function serializes the MessageContext to a string. Intended use is to prepend the
     * MessageContext to the encrypted file, so that the recipient will have the context
     * immediately available for decryption use. */
    std::string serialize() const;

    /* This function deserializes a string to resuscitate a MessageContext object out of it.
     * Intended use is for recovery of the MessageContext prepended to an encrypted file. Returns
     * the position of the start of the encrypted message. */
    size_t deserialize(std::string str);

    /* The constructor and destructor just handle some memory management. */
    MessageContext();
    ~MessageContext();

private:
    //This bool is necessary for knowing whether or not to free a pointer at destruction.
    bool deserialized;
};


#endif //ENCRYPTIONDEMO_MESSAGECONTEXT_H
