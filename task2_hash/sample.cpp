#ifndef __PROGTEST__
#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

#endif /* __PROGTEST__ */

std::string convertToHex(const std::string &input) {
    static const char hex[] = "0123456789abcdef";
    std::string output(input.size() * 2, '\0');

    for (size_t i = 0; i < input.size(); ++i) {
        output[i * 2] = hex[(unsigned char)input[i] >> 4];
        output[i * 2 + 1] = hex[(unsigned char)input[i] & 15];
    }

    return output;
}

std::string generateRandomMessage(int length) {
    std::string random_string(length, '\0');
    RAND_bytes((unsigned char *)random_string.data(), length);
    return random_string;
}

std::string calculateHash(const std::string &message, const EVP_MD *md) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen;

    EVP_Digest(message.c_str(), message.size(), hash, &hashLen, md, NULL);

    std::string result(hashLen * 2, '0');
    static const char* digits = "0123456789abcdef";

    for(unsigned int i = 0; i < hashLen; ++i) {
        result[i * 2] = digits[hash[i] >> 4];
        result[i * 2 + 1] = digits[hash[i] & 0xf];
    }

    return result;
}

int findHashEx(int bits, string &message, string &hash, string_view hashType) {
    if (bits < 0) 
        return 0;

    const EVP_MD *md = EVP_get_digestbyname(hashType.data());
    if (!md) 
        return 0;

    int messageLength = 64;//EVP_MD_size(md);
    if (bits > messageLength * 8) 
        return 0;
    
    message = generateRandomMessage(messageLength);
    int zeroChars = bits >> 2;
    int zeroBits = bits & 3;
    std::string mask(zeroChars, '0');
    if (zeroBits > 0) {
        char maskChar = (1 << (4 - zeroBits)) - 1 + '0';
        mask += maskChar;
    }

    while (true) {
        hash = calculateHash(message, md);

        if (hash.compare(0, mask.size(), mask) == 0){
            message = convertToHex(message);
            return 1;
        }
        std::swap(message, hash);
    }
}

int findHash(int bits, string &message, string &hash) {
    return findHashEx(bits, message, hash, "sha512");
}

#ifndef __PROGTEST__

int checkHash(int bits, const string &hash) {
    for (int i = 0; i < bits; i++)
        if (hash[i] == i) 
            return 0;
    return 1;
}

int main () {
    string hash, message;
    assert(findHash(0, message, hash) == 1);
    assert(!message.empty() && !hash.empty() && checkHash(0, hash));
    message.clear();
    hash.clear();
    assert(findHash(1, message, hash) == 1);
    assert(!message.empty() && !hash.empty() && checkHash(1, hash));
    message.clear();
    hash.clear();
    assert(findHash(2, message, hash) == 1);
    assert(!message.empty() && !hash.empty() && checkHash(2, hash));
    message.clear();
    hash.clear();
    assert(findHash(3, message, hash) == 1);
    assert(!message.empty() && !hash.empty() && checkHash(3, hash));
    message.clear();
    hash.clear();
    assert(findHash(-1, message, hash) == 0);
    std::cout << "Done" << std::endl;

    for (int j = 0; j < 10; ++j) {
        string hash, message;
        assert(findHash(20, message, hash) == 1);
        assert(!message.empty() && !hash.empty() && checkHash(20, hash));
        message.clear();
        hash.clear();
    }
    std::cout << "Done2" << std::endl;

    return EXIT_SUCCESS;
}
#endif /* __PROGTEST__ */

