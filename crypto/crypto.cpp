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
    // Конструктор принимает string и преобразует в vector<unsigned char>
    AES(const std::string& key_str) {
        // Просто копируем байты из string
        key.assign(key_str.begin(), key_str.end());
        
        // Для AES-256 ключ должен быть 32 байта
        // Дополняем или обрезаем ключ до нужного размера
        if (key.size() < 32) {
            // Дополняем нулями
            key.resize(32, 0);
        } else if (key.size() > 32) {
            // Обрезаем до 32 байт
            key.resize(32);
        }
    }
    
    // Остальной код остается без изменений
    struct Enc{
        vector<unsigned char> iv;
        vector<unsigned char> ciphertext;
    };
    
    Enc encrypt(const std::string& plaintext) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        Enc result;
        
        result.iv.resize(16);
        RAND_bytes(result.iv.data(), result.iv.size());
        
        result.ciphertext.resize(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
        int len = 0;
        int ciphertext_len = 0;
        
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, 
                          key.data(), result.iv.data());
        
        EVP_EncryptUpdate(ctx, result.ciphertext.data(), &len,
                         (unsigned char*)plaintext.c_str(), plaintext.length());
        ciphertext_len = len;
        
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
        
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, 
                          key.data(), encrypted.iv.data());
        
        EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                         encrypted.ciphertext.data(), encrypted.ciphertext.size());
        plaintext_len = len;
        
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


AES::Enc encrypt(string message){
   const string key = "my_secret_key";
   AES aes(key);
   AES::Enc encrypted = aes.encrypt(message);
   return encrypted;
}
string decrypt(AES::Enc encrypted){
    const string key = "mu_secret_key";
    AES aes(key);
    string res = aes.decrypt(encrypted);
    return res;
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
    cout << "KEY" << key <<  endl;
    return 0;
}

