#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <sstream>
#include <nlohmann/json.hpp>
#include <pistache/endpoint.h>
#include <pistache/router.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <iomanip>


using namespace std;
using namespace Pistache;
using namespace Pistache::Rest; 
using json = nlohmann::json;



class SecurityManager {
private:
    string secretKey;
public:
    SecurityManager(const std::string& key) : secretKey(key) {}    
    string generateSignature(const string& data, const string& timestamp) {
        string message = data + timestamp + secretKey;
        
        unsigned char* digest = HMAC(EVP_sha256(), 
                                   secretKey.c_str(), secretKey.length(),
                                   (unsigned char*)message.c_str(), message.length(),
                                   NULL, NULL);
        
        std::stringstream ss;
        for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
        }
        
        return ss.str();
    }
    
    bool verifySignature(const std::string& data, 
                        const std::string& timestamp, 
                        const std::string& signature) {
        std::string expectedSignature = generateSignature(data, timestamp);
        return signature == expectedSignature;
    }
    bool isTimeValid(const string& timestamp,long long int max_time = 300){
        try{
            auto time = stoll(timestamp);
            auto currentTime = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            return (currentTime - time) <= max_time;    
        }catch (exception& e){
            cerr << "Error" << e.what() << endl;
            return false;
        }
    }
};

void get_main(const Rest::Request& request,Http::ResponseWriter response){
    response.send(Http::Code::Ok,"Lux-Call API");
}
void create_chat(const Rest::Request& request,Http::ResponseWriter response){

}

int main(){
    Http::Endpoint server(Address("*:8080")); 
    Rest::Router router;
    Routes::Post(router, "/api/data", Routes::bind(get_main));
    server.init();
    server.setHandler(router.handler());
    server.serve();
}
