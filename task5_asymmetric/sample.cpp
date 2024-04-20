#ifndef __PROGTEST__
#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <climits>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

using namespace std;

#endif /* __PROGTEST__ */

bool seal(string_view inFile, string_view outFile, string_view publicKeyFile, string_view symmetricCipher) {
    if (inFile.empty() || outFile.empty() || publicKeyFile.empty() || symmetricCipher.empty())
        return false;
    FILE* pubKeyFile = fopen(publicKeyFile.data(), "r");
    if (!pubKeyFile) return false;
    
    EVP_PKEY* pubKey = PEM_read_PUBKEY(pubKeyFile, NULL, NULL, NULL);
    fclose(pubKeyFile);
    if (!pubKey) return false;

    const EVP_CIPHER* cipher = EVP_get_cipherbyname(symmetricCipher.data());
    if (!cipher) {
        EVP_PKEY_free(pubKey);
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pubKey);
        return false;
    }

    unsigned char* ek = new unsigned char[EVP_PKEY_size(pubKey)];
    int eklen;
    shared_ptr<unsigned char[]> iv(new unsigned char[EVP_CIPHER_iv_length(cipher)]);
    if (!EVP_SealInit(ctx, cipher, &ek, &eklen, iv.get(), &pubKey, 1)) {
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        delete[] ek;
        return false;
    }

    std::ifstream input(inFile.data(), std::ios::binary);
    if (!input.is_open()) {
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        delete[] ek;
        return false;
    }

    std::ofstream output(outFile.data(), std::ios::binary);
    if (!output.is_open()) {
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        delete[] ek;
        return false;
    }

    int nid = EVP_CIPHER_nid(cipher);
    if (!output.write((char*)&nid, sizeof(int)) ||
        !output.write((char*)&eklen, sizeof(int)) ||
        !output.write((char*)ek, eklen) ||
        !output.write((char*)iv.get(), EVP_CIPHER_iv_length(cipher)) ||
        output.bad()) {
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        delete[] ek;
        remove(outFile.data());
        return false;
    }

    std::vector<unsigned char> inBuffer(4096), outBuffer(4096 + EVP_MAX_BLOCK_LENGTH);
    int len;
    while (input.read((char*)inBuffer.data(), inBuffer.size()), input.gcount() > 0) {
        if (input.bad() || 
            !EVP_SealUpdate(ctx, outBuffer.data(), &len, inBuffer.data(), input.gcount()) ||
            !output.write((char*)outBuffer.data(), len) ||
            output.bad()) {
            EVP_CIPHER_CTX_free(ctx);
            EVP_PKEY_free(pubKey);
            delete[] ek;
            remove(outFile.data());
            return false;
        }
    }

    if (!EVP_SealFinal(ctx, outBuffer.data(), &len) ||
        !output.write((char*)outBuffer.data(), len) || 
        output.bad()) {
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        delete[] ek;
        remove(outFile.data());
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);
    EVP_PKEY_free(pubKey);
    delete[] ek;
    
    return true;
}

bool open(string_view inFile, string_view outFile, string_view privateKeyFile) {
    if (inFile.empty() || outFile.empty() || privateKeyFile.empty())
        return false;
    FILE* privKeyFile = fopen(privateKeyFile.data(), "r");
    if (!privKeyFile)
        return false;
    
    EVP_PKEY* privKey = PEM_read_PrivateKey(privKeyFile, NULL, NULL, NULL);
    fclose(privKeyFile);
    if (!privKey)
        return false;

    OpenSSL_add_all_ciphers();

    std::ifstream input(inFile.data(), std::ios::binary);
    if (!input.is_open())
        return false;

    int nid, eklen = -1;
    if (!input.read((char*)&nid, sizeof(nid)) ||
        !input.read((char*)&eklen, sizeof(eklen)) || eklen < 0 ){
        EVP_PKEY_free(privKey);
        return false;
    }
    std::vector<unsigned char> ek(eklen);
    
    if (!input.read((char*)ek.data(), eklen)) {
        EVP_PKEY_free(privKey);
        return false;
    }
    const EVP_CIPHER* cipher = EVP_get_cipherbynid(nid);
    if (!cipher) {
        EVP_PKEY_free(privKey);
        return false;
    }
    std::vector<unsigned char> iv(EVP_CIPHER_iv_length(cipher));
    input.read((char*)iv.data(), iv.size());
    if (input.bad()) {
        EVP_PKEY_free(privKey);
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(privKey);
        return false;
    }

    if (EVP_OpenInit(ctx, cipher, ek.data(), eklen, iv.data(), privKey) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(privKey);    
        return false;
    }
    
    std::ofstream output(outFile.data(), std::ios::binary);
    if (!output.is_open()) {
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(privKey);
        return false;
    }

    std::vector<unsigned char> inBuffer(4096), outBuffer(4096 + EVP_MAX_BLOCK_LENGTH);
    int len;
    while (true) {
        input.read((char*)inBuffer.data(), inBuffer.size());
        if (input.bad()) {
            EVP_CIPHER_CTX_free(ctx);
            EVP_PKEY_free(privKey);
            remove(outFile.data());
            return false;
        }
        if (input.gcount() <= 0) break;
        if (EVP_OpenUpdate(ctx, outBuffer.data(), &len, inBuffer.data(), input.gcount()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            EVP_PKEY_free(privKey);
            remove(outFile.data());
            return false;
        }
        output.write((char*)outBuffer.data(), len);
        if (output.bad()) {
            EVP_CIPHER_CTX_free(ctx);
            EVP_PKEY_free(privKey);
            remove(outFile.data());
            return false;
        }
    }
    if (EVP_OpenFinal(ctx, outBuffer.data(), &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_free(privKey);    
        remove(outFile.data());
        return false;
    }

    output.write((char*)outBuffer.data(), len);

    EVP_CIPHER_CTX_free(ctx);
    EVP_PKEY_free(privKey);

    if (output.bad()) {
        remove(outFile.data());
        return false;
    }

    return true;
}


#ifndef __PROGTEST__

bool areSame(string_view file1, string_view file2) {
    std::ifstream f1(file1.data(), std::ios::binary);
    std::ifstream f2(file2.data(), std::ios::binary);

    if (f1.fail() || f2.fail())
        return false;

    std::string str1, str2;
    while (getline(f1, str1) && getline(f2, str2))
        if (str1 != str2)
            return false;
        
    return f1.eof() && f2.eof();
}

int main (void) {
    assert( seal("toseal.txt", "sealedlong.bin", "PublicKey.pem", "aes-128-ecb") );
    assert( open("sealedlong.bin", "openedlong.txt", "PrivateKey.pem") );
    assert( areSame("toseal.txt", "openedlong.txt") );

    assert( seal("fileToEncrypt.txt", "sealed.bin", "PublicKey.pem", "aes-128-ecb") );
    assert( open("sealed.bin", "openedFileToEncrypt", "PrivateKey.pem") );
    assert( areSame("fileToEncrypt.txt", "openedFileToEncrypt") );
    
    assert( seal("sample_to_seal.txt", "sample_out.bin", "PublicKey.pem", "aes-128-cbc") );
    assert( open("sample_out.bin", "opened_saml", "PrivateKey.pem") );
    assert( areSame("sample_to_seal.txt", "opened_saml") );


    return 0;
}

#endif /* __PROGTEST__ */

