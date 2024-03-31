#ifndef __PROGTEST__
#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <climits>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <unistd.h>
#include <string>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

struct crypto_config{
	const char* m_crypto_function;
	std::unique_ptr<uint8_t[]> m_key;
	std::unique_ptr<uint8_t[]> m_IV;
	size_t m_key_len;
	size_t m_IV_len;
};
#endif /* _PROGTEST_ */

bool process_data(const std::string& in_filename, const std::string& out_filename, crypto_config& config, bool encrypt, const EVP_CIPHER* cipher){
    std::ifstream in_file(in_filename, std::ios::binary);
    std::ofstream out_file(out_filename, std::ios::binary);

    if (!in_file.is_open() || !out_file.is_open()) return false;

    char header[18];
    in_file.read(header, 18);
    if (in_file.gcount() != 18) return false;

    out_file.write(header, 18);
    if (out_file.fail()) return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx || (encrypt ? !EVP_EncryptInit_ex(ctx, cipher, NULL, config.m_key.get(), config.m_IV.get()) 
                         : !EVP_DecryptInit_ex(ctx, cipher, NULL, config.m_key.get(), config.m_IV.get()))){
        if(ctx) EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    std::vector<char> in_buf(4096);
    std::vector<unsigned char> out_buf(4096 + EVP_MAX_BLOCK_LENGTH);
    int out_len;

    while (in_file){
        in_file.read(in_buf.data(), in_buf.size());
        if (encrypt ? !EVP_EncryptUpdate(ctx, out_buf.data(), &out_len, reinterpret_cast<unsigned char*>(in_buf.data()), in_file.gcount())
                    : !EVP_DecryptUpdate(ctx, out_buf.data(), &out_len, reinterpret_cast<unsigned char*>(in_buf.data()), in_file.gcount())){
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        out_file.write(reinterpret_cast<char*>(out_buf.data()), out_len);
        if (out_file.fail()){
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }

    if (encrypt ? !EVP_EncryptFinal_ex(ctx, out_buf.data(), &out_len) 
                : !EVP_DecryptFinal_ex(ctx, out_buf.data(), &out_len)){
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    out_file.write(reinterpret_cast<char*>(out_buf.data()), out_len);
    
    EVP_CIPHER_CTX_free(ctx);
    if (out_file.fail()) return false;
    return true;
}

bool encrypt_data(const std::string& in_filename, const std::string& out_filename, crypto_config& config){
    const EVP_CIPHER* cipher = EVP_get_cipherbyname(config.m_crypto_function);
    if (!cipher) return false;

    if (!config.m_key || config.m_key_len < (size_t)EVP_CIPHER_key_length(cipher)){
        config.m_key = std::make_unique<uint8_t[]>(EVP_CIPHER_key_length(cipher));
        config.m_key_len = EVP_CIPHER_key_length(cipher);
        RAND_bytes(config.m_key.get(), config.m_key_len);
    }

    if ((!config.m_IV && EVP_CIPHER_iv_length(cipher) > 0) || config.m_IV_len < (size_t)EVP_CIPHER_iv_length(cipher)){
        config.m_IV = std::make_unique<uint8_t[]>(EVP_CIPHER_iv_length(cipher));
        config.m_IV_len = EVP_CIPHER_iv_length(cipher);
        RAND_bytes(config.m_IV.get(), config.m_IV_len);
    }
    return process_data(in_filename, out_filename, config, true, cipher);
}

bool decrypt_data(const std::string& in_filename, const std::string& out_filename, crypto_config& config){
    const EVP_CIPHER* cipher = EVP_get_cipherbyname(config.m_crypto_function);
    if (!cipher) return false;

    if (!config.m_key || config.m_key_len < (size_t)EVP_CIPHER_key_length(cipher)) return false;

    if ((!config.m_IV && EVP_CIPHER_iv_length(cipher) > 0) || config.m_IV_len < (size_t)EVP_CIPHER_iv_length(cipher)) return false;

    return process_data(in_filename, out_filename, config, false, cipher);
}

#ifndef __PROGTEST__
bool compare_files(const char* name1, const char* name2){
    std::ifstream file1(name1, std::ios::binary);
    std::ifstream file2(name2, std::ios::binary);

    if (file1.fail() || file2.fail())
        return false;

    std::istreambuf_iterator<char> iter1(file1);
    std::istreambuf_iterator<char> iter2(file2);
    std::istreambuf_iterator<char> end;

    while (iter1 != end && iter2 != end){
        if (*iter1 != *iter2)
            return false;
        ++iter1;
        ++iter2;
    }

    return (iter1 == end && iter2 == end);
}

int main(){
	crypto_config config {nullptr, nullptr, nullptr, 0, 0};

	// ECB mode
	config.m_crypto_function = "AES-128-ECB";
	config.m_key = std::make_unique<uint8_t[]>(16);
 	memset(config.m_key.get(), 0, 16);
	config.m_key_len = 16;

	assert( encrypt_data  ("homer-simpson.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson_enc_ecb.TGA") );

	assert( decrypt_data  ("homer-simpson_enc_ecb.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson.TGA") );

	assert( encrypt_data  ("UCM8.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8_enc_ecb.TGA") );

	assert( decrypt_data  ("UCM8_enc_ecb.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8.TGA") );

	assert( encrypt_data  ("image_1.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_1_enc_ecb.TGA") );

	assert( encrypt_data  ("image_2.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_2_enc_ecb.TGA") );

	assert( decrypt_data ("image_3_enc_ecb.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_3_dec_ecb.TGA") );

	assert( decrypt_data ("image_4_enc_ecb.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_4_dec_ecb.TGA") );

	// CBC mode
	config.m_crypto_function = "AES-128-CBC";
	config.m_IV = std::make_unique<uint8_t[]>(16);
	config.m_IV_len = 16;
	memset(config.m_IV.get(), 0, 16);

	assert( encrypt_data  ("UCM8.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8_enc_cbc.TGA") );

	assert( decrypt_data  ("UCM8_enc_cbc.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8.TGA") );

	assert( encrypt_data  ("homer-simpson.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson_enc_cbc.TGA") );

	assert( decrypt_data  ("homer-simpson_enc_cbc.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson.TGA") );

	assert( encrypt_data  ("image_1.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_5_enc_cbc.TGA") );

	assert( encrypt_data  ("image_2.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_6_enc_cbc.TGA") );

	assert( decrypt_data ("image_7_enc_cbc.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_7_dec_cbc.TGA") );

	assert( decrypt_data ("image_8_enc_cbc.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_8_dec_cbc.TGA") );
	return 0;
}
#endif /* _PROGTEST_ */