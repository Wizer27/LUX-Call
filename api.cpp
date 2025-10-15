#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <nlohmann/json.hpp>
#include <pistache/endpoint.h>
#include <pistache/router.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <iomanip>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>



using namespace std;
using namespace Pistache;
using namespace Pistache::Rest; 
using json = nlohmann::json;

boost::uuids::random_generator  id_genrator;


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

class SignatureMiddleware{
private:
    SecurityManager& security;
public:
    bool validate_request(const Rest::Request& request){
        auto signature = request.headers().tryGetRaw("X-Signature");
        auto timestamp = request.headers().tryGetRaw("X-Timestamp");
        auto apiKey = request.headers().tryGetRaw("X-API-Key");
        if (!signature || !timestamp || !apiKey){
            return false;
        }

        string req_sig = signature -> value();
        string time_req = timestamp -> value();
        string apiKey_req = apiKey -> value();


        if (!security.isTimeValid(time_req)){
            return false;
        }
        
        const string data = request.body() + time_req + apiKey_req;

        return security.verifySignature(data,time_req,req_sig);

    }    
};

SignatureMiddleware siganture_middleware;

void get_main(const Rest::Request& request,Http::ResponseWriter response){
    response.send(Http::Code::Ok,"Lux-Call API");
}
void default_chats(string username){
    ifstream file;
    json data;
    if(!file.is_open()){
        cerr << "Error file wasnt opened" << endl;
        return;
    }
    else{
        file >> data;
        file.close();
        json new_user = {
            {"username",username},
            {"chats",json::array()}
        };
        ofstream exit_file("data/chats.json");
        if(!exit_file.is_open()){
            cerr << "Error while writing the data" << endl;
            return;
        }
        else{
            exit_file << data.dump(4);
            exit_file.close();
        }
        
    }
}
void register_new_user(const Rest::Request& request,Http::ResponseWriter response){
    if(!siganture_middleware.validate_request(request)){
        response.send(Http::Code::Forbidden,"Invalid siganture");
        return;
    }
    json body = json::parse(request.body());
    string username = body[0];
    string hash_pasw = body[1];

    try{
        ifstream file("data/users.josn");
        if(!file.is_open()){
            response.send(Http::Code::Bad_Request,"Error file wanst opened");
        }
        else{
            json data;
            file >> data;
            file.close();
            data[username] = hash_pasw;
            ofstream exit_file("data/users.json");
            if(!exit_file.is_open()){
                response.send(Http::Code::Bad_Request,"Error while writing data");
            }
            else{
                exit_file << data.dump(4);
                exit_file.close();
                default_chats(username);
                response.send(Http::Code::Ok,"Done");
            }

        }
    }catch(exception& e){
        response.send(Http::Code::Bad_Request,"Error");
    }
}

void Create_New_chat(const Rest::Request& request,Http::ResponseWriter response){
    if(!siganture_middleware.validate_request(request)){
        response.send(Http::Code::Forbidden,"Invalid siganture");
        return;
    }    
    try{
        ifstream file("data/chats.json");
        json data;
        json body = json::parse(request.body());
        string user1 = body[0];//our user
        string user2 = body[1]; // his contact
        string id;
        bool ind = false;
        if(!file.is_open()){
            response.send(Http::Code::Bad_Request,"Error");
            return;
        }
        else{
            file >> data;
            file.close();
            for(auto chat:data){
                if(chat["users"].size() == 0){
                    chat["users"].push_back(user1);
                    chat["users"].push_back(user2);
                    ind = true;
                    id = chat["id"];
                }
            }
            if(ind){
                ofstream exit_file("data/chats.json");
                if(!exit_file.is_open()){
                    response.send(Http::Code::Bad_Gateway,"Error whijle writing");
                }
                else{
                    exit_file << data.dump(4);
                    exit_file.close();
                    response.send(Http::Code::Ok,id);
                }
            }
        }   
    }catch(exception& e){
        response.send(Http::Code::Bad_Request,"Error");
    }
}
bool in(vector<string> main,string username){
    for(string user:main){
        if(user == username){
            return true;
        }
    }
    return false;

}

long long int index(vector<string> main,string find_elem){
    for(int i = 0; i < main.size();i++){
        if(main[i] == find_elem){
            return i;
        }
    }
    return -1;
}

string get_except(vector<string> main,string rem_elem){
    long long int ind = index(main,rem_elem);
    string res;
    for(int i=0;i<main.size();i++){
        if(main[i] != rem_elem){
            res = main[i];
        }
    }
    return res;
}

//FIXME write the user contact list endpoint
void get_user_contacts(const Rest::Request& request,Http::ResponseWriter response){
    if(!siganture_middleware.validate_request(request)){
        response.send(Http::Code::Forbidden,"Invalid signature");
    }
    try{
        json body = json::parse(request.body());
        string username = body["username"];
        ifstream file("data/chats.json");
        if(file.is_open()){
            cerr << "Error while opening file" << endl;
            return;
        }
        json data;
        file >> data;
        file.close();
        vector<string> contacts;
        for(const auto chat: data){
            if(in(chat["users"],username)){
                string refactor = get_except(chat["users"],username);
                contacts.push_back(refactor);

            }
        }
        try{
        

        }catch(exception& e){
            response.send(Http::Code::Bad_Request,"Error while debugs");
        }
    }catch(exception& e){
        response.send(Http::Code::Bad_Request,e.what());
    }
}




int main(){
    Http::Endpoint server(Address("*:8080")); 
    Rest::Router router;
    Routes::Get(router, "/api/data", Routes::bind(get_main));
    Routes::Post(router, "/api/register", Routes::bind(register_new_user));
    Routes::Post(router,"/api/create_new_chat",Routes::bind(Create_New_chat));
    server.init();
    server.setHandler(router.handler());
    server.serve();
}
