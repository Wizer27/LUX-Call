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




using namespace std;
using namespace Pistache;
using namespace Pistache::Rest; 
using json = nlohmann::json;




class SecurityManager {
private:
    string secretKey;
public:
    explicit SecurityManager(const std::string& key) : secretKey(key) {}    
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
    explicit SignatureMiddleware(SecurityManager& sec) : security(sec) {}
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

string get_key(){
    try{
        ifstream file("/Users/ivan/LUX-Call/data/secrets.json");if(!file.is_open()) std::cerr << "Error while opening file";
        else{
            json data;file >> data;file.close();
            return data["key"]; 
        }
    }catch(exception& e){
        std::cerr << "Error while opening";return "Error";
    }
    return NULL;
}

string get_api_key(){
    try{
        ifstream file("/Users/ivan/LUX-Call/data/secrets.json");if(!file.is_open()) std::cerr << "Error while opening file";
        else{
            json data;file >> data;file.close();
            return data["api"]; 
        }
    }catch(exception& e){
        std::cerr << "Error while opening";return "Error";
    }
    return NULL;
}

SecurityManager security(get_key());

SignatureMiddleware siganture_middleware(security);

void get_main(const Rest::Request& request,Http::ResponseWriter response){
    response.send(Http::Code::Ok,"Lux-Call API");
}
void default_contacts(string username){
    ifstream file("data/contacts.json");
    if(!file.is_open()){
        cerr << "Error" << endl;
    }else{
        json data;
        file >> data;
        file.close();
        json new_user_data = {
            {"username",username},
            {"contacts",json::array()}
        };
        data.push_back(new_user_data);
        ofstream exit_file("data/contacts.json");
        if(!exit_file.is_open()){
            cerr << "Error" << endl;
        }else{
            exit_file << data.dump(4);
            exit_file.close();
        }
    }
}
void default_chats(string username){
    ifstream file("data/chats.json");
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
    string username = body["username"];
    string hash_pasw = body["password"];

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
                //default user data
                default_chats(username);
                default_contacts(username);
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
bool delete_data_from_vector(vector<string> main,string del){
    long long int ind = index(main,del);
    try{
        main.erase(main.begin() + ind);
        return true;
    }catch(exception& e){
        return false;
    }
}

//FIXME write the user contact list endpoint
void get_user_contacts(const Rest::Request& request,Http::ResponseWriter response){
    if(!siganture_middleware.validate_request(request)){
        response.send(Http::Code::Forbidden,"Invalid signature");
    }
    try{
        json body = json::parse(request.body());
        string username = body["username"];
        ifstream file("data/contacts.json");
        if(file.is_open()){
            cerr << "Error while opening file" << endl;
            return;
        }
        json data;
        file >> data;
        file.close();
        string contacts;
        for(const auto user:data){
            if(user["username"] == username){
                for(const string cont:user["contacts"]){
                    contacts += cont + ",/.,/.,/"; //разделитель, потом поменяй на что то более сложное
                }
            }
        }
        try{
            response.send(Http::Code::Ok,contacts);
        }catch(exception& e){
            response.send(Http::Code::Bad_Request,"Error");
        }
    }catch(exception& e){
        response.send(Http::Code::Bad_Request,e.what());
    }
}


void delete_user_contact(const Rest::Request& request,Http::ResponseWriter response){
    if(!siganture_middleware.validate_request(request)){
        response.send(Http::Code::Forbidden,"Invalid signature");
    }else{
        try{
            ifstream file("data/contacts.json");
            json user_data = json::parse(request.body());
            string username = user_data["username"];
            string delete_user = user_data["user_to_delete"];
            if(!file.is_open()){
                cerr << "Error" << endl;
            }else{
                json data;
                file >> data;
                file.close();
                bool indif = false;
                for(auto user:data){
                    if(user["username"] == username){
                        bool dellets = delete_data_from_vector(user["contacts"],delete_user);
                        
                        if(dellets){
                            indif = true;
                        }else{
                            response.send(Http::Code::Not_Found,"Error contact not found");
                        }
                    }
                }
                if(indif){
                    ofstream exit_file("data/cointacts.json");
                    if(!exit_file.is_open()){
                        response.send(Http::Code::Bad_Request,"Error while writing the data");
                    }else{
                        exit_file << data.dump(4);
                        exit_file.close();
                        response.send(Http::Code::Ok,"Ok");
                    }
                }else{
                    response.send(Http::Code::Not_Found,"Error user not found");
                }
            }
        }catch(exception& e){
            response.send(Http::Code::Bad_Request,"Bad request");
        }
    }
}
void create_new_contact(const Rest::Request& request,Http::ResponseWriter response){
    if(!siganture_middleware.validate_request(request)){
        response.send(Http::Code::Forbidden,"Ivalid signature");
    }else{
        auto user_data = json::parse(request.body());
        string username = user_data["username"];
        string new_contact = user_data["new_contact"];
        ifstream file("data/contacts.json");if(!file.is_open()) response.send(Http::Code::Bad_Request,"Error while opening");
        else{
            json data;file >> data;file.close();
            bool indf = false;
            for(auto& user : data){
                if(user["username"] == username){ user["contacts"].push_back(new_contact); indf = true;}
            }if(indf){
                ofstream exit_file("data/contacts.json");if(!exit_file.is_open()) response.send(Http::Code::Bad_Request,"Error while writing");
                else{
                    exit_file << data.dump(4);exit_file.close();
                    response.send(Http::Code::Ok,"Done");
                }
            }
            
        }
    }
}   


void get_chat_messages(const Rest::Request& request,Http::ResponseWriter response){
    if(!siganture_middleware.validate_request(request)){
        response.send(Http::Code::Forbidden,"Invalid signature");
    }else{
        try{
            auto req = json::parse(request.body());
            string id = req["id"];
        }catch(exception& e){
            response.send(Http::Code::Bad_Request,"Error");
        }
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
