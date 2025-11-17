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

class Hashing{
public:
    size_t get_hash(string mess){
        return std::hash<std::string>()(mess);
    }
};


int main(){
    Hashing hsh_obj;
    string key = generate_key();
    cout << key << endl;
    return 0;
}

