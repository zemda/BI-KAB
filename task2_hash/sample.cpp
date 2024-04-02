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


bool checkZeroBits(const std::string &hash, int bits) {
    int zeroChars = bits / 4;
    int zeroBits = bits % 4;

    for (int i = 0; i < zeroChars; ++i)
        if (hash[i] != '0')
            return false;

    if (zeroBits > 0) {
        char mask = (1 << (4 - zeroBits)) - 1 + '0';
        if (hash[zeroChars] > mask)
            return false;
    }

    return true;
}

int findHashEx(int bits, string &message, string &hash, string_view hashType) {
    if (bits < 0) return 0;
    const EVP_MD *md = EVP_get_digestbyname(hashType.data());
    if (!md) return 0;

    int messageLength = EVP_MD_size(md);
    if (bits > messageLength * 8) return 0;
    message.resize(messageLength);
    RAND_bytes((unsigned char *)message.data(), messageLength);
    static const char* digits = "0123456789abcdef";
    
    while (true) {
        std::vector<unsigned char> hash_v(EVP_MAX_MD_SIZE);
        unsigned int hashLen;

        EVP_Digest(message.c_str(), message.size(), hash_v.data(), &hashLen, md, NULL);
        if ((unsigned int)bits > hashLen * 8) return 0;
        std::string hash_(hashLen * 2, '0');

        for(unsigned int i = 0; i < hashLen; ++i) {
            hash_[i * 2] = digits[hash_v[i] >> 4];
            hash_[i * 2 + 1] = digits[hash_v[i] & 0xf];
        }

        if (checkZeroBits(hash_, bits)) {
            auto size = message.size();
            std::string output(size * 2, '\0');
            for (size_t i = 0; i < size; ++i) {
                output[i * 2] = digits[(unsigned char)message[i] >> 4];
                output[i * 2 + 1] = digits[(unsigned char)message[i] & 15];
            }
            std::swap(message, output);
            std::swap(hash, hash_);
            cout << "Message: " << message << endl;
            cout << "Hash: " << hash << endl;
            
            return 1;
        }
        std::swap(message, hash_);
    }
}

int findHash(int bits, string &message, string &hash) {
    return findHashEx(bits, message, hash, "sha512");
}


#ifndef __PROGTEST__

int checkHash(int bits, const string &hexHash) {
    size_t zeros = bits/4;
    int remainingBits = bits % 4;
    if (hexHash.size() < zeros + 1) return 0;
    for (size_t i = 0; i < zeros; ++i) {
        if (hexHash[i] != '0') return 0;
    }
    if (remainingBits > 0) {
        switch(remainingBits) {
            case 1:
                if (hexHash[zeros] > '7') return 0;
                break;
            case 2:
                if (hexHash[zeros] > '3') return 0;
                break;
            case 3:
                if (hexHash[zeros] > '1') return 0;
                break;
        }
    }
    return 1;
}

int main () {
    string hash, message;
    assert(findHash(0, message, hash) == 1);
    assert(!message.empty() && !hash.empty());
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

