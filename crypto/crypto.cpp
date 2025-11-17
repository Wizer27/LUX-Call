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
    Enc encrypt(const string& plain_text){
        
    }


};

class Hashing{
public:
    size_t get_hash(string mess){
        return std::hash<std::string>()(mess);
    }
};


int main(){
    return 0;
}

