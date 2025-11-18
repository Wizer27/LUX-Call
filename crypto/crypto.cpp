#include <iostream>
#include <sstream>
#include <fstream>
#include <unordered_map>
#include <nlohmann/json.hpp>
#include <iomanip>
#include <random>
#include <algorithm>
#include <ctime>
#include <cmath>
#include <stdexcept>
#include <string>
#include <vector>
#include <functional>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <random>



using namespace std;
using json = nlohmann::json;


class AES{
private:
    vector<unsigned char> key;
public:
    AES(const std::vector<unsigned char>& key) : key(key) {}
    struct Enc{
        vector<unsigned char> iv;
        vector<unsigned char> ciphertext;
    };
    Enc encrypt(const std::string& plaintext) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        Enc result;
        
        // Генерируем случайный IV
        result.iv.resize(16); // 128 бит для AES
        RAND_bytes(result.iv.data(), result.iv.size());
        
        result.ciphertext.resize(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
        int len = 0;
        int ciphertext_len = 0;
        
        // Инициализация шифрования
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, 
                          key.data(), result.iv.data());
        
        // Шифрование
        EVP_EncryptUpdate(ctx, result.ciphertext.data(), &len,
                         (unsigned char*)plaintext.c_str(), plaintext.length());
        ciphertext_len = len;
        
        // Финальная часть
        EVP_EncryptFinal_ex(ctx, result.ciphertext.data() + len, &len);
        ciphertext_len += len;
        
        EVP_CIPHER_CTX_free(ctx);
        result.ciphertext.resize(ciphertext_len);
        
        return result;
    }
    std::string decrypt(const Enc& encrypted) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        std::vector<unsigned char> plaintext(encrypted.ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
        int len = 0;
        int plaintext_len = 0;
        
        // Инициализация расшифровки
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, 
                          key.data(), encrypted.iv.data());
        
        // Расшифровка
        EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                         encrypted.ciphertext.data(), encrypted.ciphertext.size());
        plaintext_len = len;
        
        // Финальная часть
        EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
        plaintext_len += len;
        
        EVP_CIPHER_CTX_free(ctx);
        
        return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
    }


};

string generate_key(){
    const long long int  lenght = 20;
    const std::string characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789,./;'[]*()!@#$%_+-";
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> distribution(0, characters.size() - 1);
    std::string key;
    key.reserve(lenght);
    for(size_t i = 0;i < lenght;++i){
        key += characters[distribution(generator)];
    }
    return key;
}



string enc_with_key(string message){
    std::vector<unsigned char> key = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    AES aes(key);
    string result;
    auto encrypted = aes.encrypt(message);
    for(auto byte : encrypted.iv){
        printf("%02x",byte);
        result += byte;
    }
    std::cout << std::endl;
    std::cout << result << endl;
    return result;
}


class Hashing{
public:
    size_t get_hash(string mess){
        return std::hash<std::string>()(mess);
    }
};


int main(){
    Hashing hsh_obj;
    string key = generate_key();
    string message = "test_tyest";
    string enc = enc_with_key(message);
    cout << "Encrypted" << enc << endl;
    cout << "KEY" << key <<  endl;
    return 0;
}

