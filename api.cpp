#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <random>
#include <algorithm>
#include <unordered_map>
#include <nlohmann/json.hpp>
#include <pistache/endpoint.h>
#include <pistache/router.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>






using namespace std;
using namespace Pistache;
using namespace Pistache::Rest; 
using json = nlohmann::json;


//Data files cache
string contatcts_file = "/Users/ivan/LUX-Call/data/contacts.json";
string users_file = "/Users/ivan/LUX-Call/data/users.json";
string chats_file = "/Users/ivan/LUX-Call/data/chats.json";
string secrets_file = "/Users/ivan/LUX-Call/data/secrets.json";
string recent_file = "/Users/ivan/LUX-Call/data/recent.json";
string history_calls = "/Users/ivan/LUX-Call/data/calls_history.json";


//random id generator
std::string generateUUID() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;

    uint64_t part1 = dis(gen);
    uint64_t part2 = dis(gen);

    std::stringstream ss;
    ss << std::hex << std::setfill('0')
       << std::setw(8) << (part1 >> 32) << "-"
       << std::setw(4) << ((part1 >> 16) & 0xFFFF) << "-"
       << std::setw(4) << (part1 & 0xFFFF) << "-"
       << std::setw(4) << ((part2 >> 48) & 0xFFFF) << "-"
       << std::setw(12) << (part2 & 0xFFFFFFFFFFFF);
    
    return ss.str();
}
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
        
        const string data = request.body() + time_req + get_key();


        std::cout << "=== C++ DEBUG ===" << std::endl;
        std::cout << "Request body: '" << request.body() << "'" << std::endl;
        std::cout << "Timestamp: '" << time_req << "'" << std::endl;
        std::cout << "Secret key: '" << get_key() << "'" << std::endl;
        std::cout << "Full message for signature: '" << data << "'" << std::endl;
        std::cout << "Received signature: '" << req_sig << "'" << std::endl;
        
        string expected = security.generateSignature(request.body(), time_req);
        std::cout << "Expected signature: '" << expected << "'" << std::endl;
        std::cout << "Match: " << (req_sig == expected) << std::endl;
        std::cout << "=== END DEBUG ===" << std::endl;

        return security.verifySignature(request.body(),time_req,req_sig);

    }    
};



SecurityManager security(get_key());

SignatureMiddleware siganture_middleware(security);

void get_main(const Rest::Request& request,Http::ResponseWriter response){
    response.send(Http::Code::Ok,"Lux-Call API");
}
void default_calls_history(const string username){
    try{
        ifstream file(history_calls);if(!file.is_open()) std::cerr << "Error while opening" << endl;
        else{
            json data;file >> data;file.close();
            json new_user_data = {
                {"username",username},
                {"calls",json::array()}
            };
            data.push_back(new_user_data);
            ofstream exit_file(history_calls);if(!exit_file.is_open()) std::cerr << "Error while writing" << endl;
            else{
                exit_file << data.dump(4);
                exit_file.close();
            }
        }
    }catch(exception& e){
        std::cerr << e.what() << endl;
    }
}
void default_contacts(string username){
    ifstream file("/Users/ivan/LUX-Call/data/contacts.json");
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
        ofstream exit_file("/Users/ivan/LUX-Call/data/contacts.json");
        if(!exit_file.is_open()){
            cerr << "Error" << endl;
        }else{
            exit_file << data.dump(4);
            exit_file.close();
        }
    }
}
void default_recent(string username){
    try{
        ifstream file(recent_file);if(!file.is_open()) std::cerr << "Error while opening the file" << endl;
        else{
            json data;file >> data;file.close();
            json new_user_data = {
                {"username",username},
                {"recent",json::array()}
            };
            data.push_back(new_user_data);
            ofstream exit_file(recent_file);if(!exit_file.is_open()) std::cerr << "Error while writing the data" << endl;
            else{
                exit_file << data.dump(4);
                exit_file.close();
            }
        }
    }catch(exception& e){
        std::cerr << e.what() << endl;
    }
}

bool is_user_exists(string username){
    try{
        ifstream file("/Users/ivan/LUX-Call/data/users.json");if(!file.is_open()) std::cerr << "Error while opening the file" << endl;
        else{
            json data;file >> data;file.close();
            for(const auto& [user,pasw] : data.items()){
                if(user == username){
                    return true;
                }
            }
            return false;
        }
    }catch(exception& e){
        std::cerr << e.what() << endl;
        return false;
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
void register_new_user(const Rest::Request& request,Http::ResponseWriter response){
    if(!siganture_middleware.validate_request(request)){
        response.send(Http::Code::Forbidden,"Invalid signature");
        return;
    }
    json body = json::parse(request.body());
    string username = body["username"];
    string hash_pasw = body["password"];
    if(is_user_exists(username)){
        response.send(Http::Code::Bad_Request,"Error user already exists");
        return;
    }
    try{
        ifstream file("/Users/ivan/LUX-Call/data/users.json");
        if(!file.is_open()){
            response.send(Http::Code::Bad_Request,"Error file wanst opened");
        }
        else{
            json data;
            file >> data;
            file.close();
            data[username] = hash_pasw;
            ofstream exit_file("/Users/ivan/LUX-Call/data/users.json");
            if(!exit_file.is_open()){
                response.send(Http::Code::Bad_Request,"Error while writing data");
                std::cerr << "Error 1" << endl;
            }
            else{
                exit_file << data.dump(4);
                exit_file.close();
                //default user data
                default_contacts(username);
                default_recent(username);
                default_calls_history(username);
                response.send(Http::Code::Ok,"Done");
            }

        }
    }catch(exception& e){
        response.send(Http::Code::Bad_Request,"Error");
    }
}
void login(const Rest::Request& request,Http::ResponseWriter response){
    if(!siganture_middleware.validate_request(request)){
            response.send(Http::Code::Forbidden,"invalid signature");
            return;
    }        
    try{
        ifstream file(users_file);if(!file.is_open()) std::cerr << "Error while opening" << endl;
        else{
            json data;file >> data;file.close();
            auto user_data = json::parse(request.body());
            if(data[user_data["username"]] == user_data["psw"]){
                response.send(Http::Code::Ok,"Access secured");
            }else{
                response.send(Http::Code::Bad_Request,"Access denied");
            }
        }
    }catch(exception& e){
        response.send(Http::Code::Bad_Request,e.what());
        std::cerr << "Exception: " << e.what() << endl;
        return;
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
        string user1 = body["user1"];//our user
        string user2 = body["user2"]; // his contact
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
void delete_the_chat(const Rest::Request& request,Http::ResponseWriter response){
    if(!siganture_middleware.validate_request(request)){
        response.send(Http::Code::Forbidden,"Invalid signature");
    }else{
        bool indif = false;
        try{
            ifstream file(chats_file);if(!file.is_open()) std::cerr << "Error while opening" << endl;
            else{
                json data;file >> data;file.close();
                const auto user_data = json::parse(request.body());
                for(auto& chat:data){
                    if(chat["id"] == user_data["chat_id"]){
                        chat["messages"] = json::array();
                        chat["users"] = json::array();
                        ofstream exit_file(chats_file);if(!exit_file.is_open()) std::cerr << "Error while writing" << endl;
                        else{
                            exit_file << data.dump(4);exit_file.close();indif = true;
                            response.send(Http::Code::Ok,"Done");
                        }
                    }
                }
            }
            if(!indif){
                response.send(Http::Code::Not_Found,"Error chat not found");
            }
        }catch(exception& e){
            std::cerr << e.what() << endl;
            response.send(Http::Code::Bad_Request,e.what());
        }
    }
}

void get_user_chats(const Rest::Request& request,Http::ResponseWriter response){
    if(!siganture_middleware.validate_request(request)){
        response.send(Http::Code::Forbidden,"Invalid signature");
    }else{
        try{
            ifstream file(chats_file);if(!file.is_open()) std::cerr << "Error while opening" << endl;
            else{
                json data;file >> data;file.close();
                vector<json> chats;
                const auto user_data = json::parse(request.body());
                for(const auto& chat:data){
                    if(in(chat["users"],user_data["username"])){
                        chats.push_back(chat);
                    }
                }
                if(!chats.empty()){
                    json result = chats;
                    response.send(Http::Code::Ok,result.dump(),MIME(Application,Json));
                }else{
                    response.send(Http::Code::Not_Found,"Users doesnt have any chats");
                }
            }
        }catch(exception& e){
            std::cerr << "Exception: " << e.what();
            response.send(Http::Code::Bad_Request,e.what());
            return;
        }
    }
}

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
                response.send(Http::Code::Ok,user["contacts"].dump(),MIME(Application,Json));
            }
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
//FIXME WRITE THE HISTORY OF CHAT CALLS
void write_the_message(const Rest::Request& request,Http::ResponseWriter response){
    if(!siganture_middleware.validate_request(request)){
        response.send(Http::Code::Forbidden,"Invalid signature");
    }else{
        ifstream file("data/chats.json");if(!file.is_open()) std::cerr << "Error while opening";return;
        json data;file >> data;file.close();
        auto user_data = json::parse(request.body());
        const string chat_id = user_data["id"];
        const string message_text = user_data["message"];
        const string author = user_data["author"];
        const auto files = user_data["files"];
        const string time = user_data["time"];
        bool indic = false;
        string id = generateUUID();
        for(auto chat:data){
            if(chat["id"] == chat_id){
                json new_message = {
                    {"message",message_text},
                    {"author",author},//write the user_id fitch
                    {"id",id},
                    {"files",files},
                    {"time",time}
                };
                chat["messages"].push_back(new_message);
                indic = true;
            }
        }
        if(indic){
            ofstream exit_file("data/chats.json");if(!exit_file.is_open()) response.send(Http::Code::Bad_Request,"Error while opening the file");
            else{
                exit_file << data.dump(4);
                exit_file.close();
                response.send(Http::Code::Ok,"Done");
            }
        }else{
            response.send(Http::Code::Not_Found,"Error chat not found");
        }

    }
}
void write_call_to_user(string username,string from,string date){
    try{
        ifstream file(history_calls);if(!file.is_open()) std::cerr << "Error while opening" << endl;
        else{
            json data;file >> data;file.close();
            for(auto user : data){
                if(user["username"] == username){
                    json new_call = {
                        {"to",username},
                        {"from",from},
                        {"date",date},
                        {"id",generateUUID()}
                    };
                    user["calls"].push_back(new_call);
                    ofstream exit_file(history_calls);if(!file.is_open()) std::cerr << "Error while writing" << endl;
                    else{
                        exit_file << data.dump(4);
                        exit_file.close();
                    }
                }
            }
        }
    }catch(exception& e){
        std::cerr << e.what() << endl;
    }
}
void write_call(const Rest::Request& request,Http::ResponseWriter response){
    if(!siganture_middleware.validate_request(request)){
        response.send(Http::Code::Forbidden,"Invalid signature");
    }else{
        try{
            bool indf = false;
            ifstream file(chats_file);if(!file.is_open()) std::cerr << "Error while opening the file" << endl;
            json data;file >> data;file.close();
            const auto user_data = json::parse(request.body());
            for(auto chat : data){
                if(chat["id"] == user_data["chat_id"]){
                    indf = true;
                    json new_call  = {
                        {"from",user_data["from"]},
                        {"to",user_data["to"]},
                        {"date",user_data["date"]},
                        {"type",user_data["type"]},
                        {"id",generateUUID()}
                    };
                    chat["messages"].push_back(new_call);
                    ofstream exit_file(chats_file);if(!exit_file.is_open()) std::cerr << "Error while writing the data" << endl;
                    else{
                        exit_file << data.dump(4);
                        exit_file.close();
                        write_call_to_user(user_data["to"],user_data["form"],user_data["date"]);
                        response.send(Http::Code::Ok,"Done");
                    }
                     
                }
            }
            if(!indf){
                response.send(Http::Code::Not_Found,"Error no chats found");
            }
        }catch(exception& e){
            std::cerr << e.what() << endl;
            response.send(Http::Code::Bad_Request,e.what());
            return;
        }
    }
}

//FIXME write the get user_calls endpoint
void get_user_history(const Rest::Request& request,Http::ResponseWriter response){
    if(!siganture_middleware.validate_request(request)){
        response.send(Http::Code::Ok,"Invalid siganture");
    }else{
        try{
            bool indf = false;
            ifstream file(history_calls);if(!file.is_open()) std::cerr << "Error while openign the file" << endl;
            else{
                json data;file >> data;file.close();
                const auto user_data = json::parse(request.body());
                for(const auto& user:data){
                    if(user["username"] == user_data["username"]){
                        indf = true;
                        response.send(Http::Code::Ok,user["calls"].dump(),MIME(Application,Json));
                    }
                }
            }
            if(!indf){
                response.send(Http::Code::Not_Found,"Error user not found");
            }
        }catch(exception& e){
            std::cerr << e.what() << endl;
            response.send(Http::Code::Bad_Request,e.what());
        }
    
    }
}
struct Message{
    string id;
    string author;
    string message;
};
void delete_message(const Rest::Request& request,Http::ResponseWriter response){
    if(!siganture_middleware.validate_request(request)){ response.send(Http::Code::Forbidden,"Invalid signature"); return;}
    try{
        ifstream file("data/chats.json");if(!file.is_open()) cerr << "Error while opnig the file" << endl;
        else{
            auto user_data = json::parse(request.body());
            string chat_id = user_data["chat_id"];
            string message_id = user_data["message_id"];
            json data;file >> data;file.close();
            bool indif = false;
            for(auto chat : data){
                if(chat["id"] == chat_id){
                    for(int i = 0;i < chat["messages"].size();i++){
                        if(chat["messages"][i] == message_id){
                            chat["messages"].erase(chat["messages"].begin() + i);
                            indif = true;
                            break;
                        }
                }
                }
            }if(indif){
                ofstream exit_file("data/chats.json");if(!exit_file.is_open()){ std::cerr << "Error while opening" << endl;response.send(Http::Code::Bad_Gateway,"Error while writing");}
                else{
                    exit_file << data.dump(4);
                    exit_file.close();
                    response.send(Http::Code::Ok,"Done");
                }
            }else{
                response.send(Http::Code::Not_Found,"Error not found");
            }
        }
    }catch(exception& e){
        std::cerr << e.what() << endl;
    }
}
void get_chat_messages(const Rest::Request& request,Http::ResponseWriter response){
    if(!siganture_middleware.validate_request(request)){
        response.send(Http::Code::Forbidden,"Invalid signature");
    }else{
        try{
            auto req = json::parse(request.body());
            string id = req["id"];
            ifstream file("data/chats.json");if(!file.is_open()) response.send(Http::Code::Bad_Request,"Error while opening the file");
            else{
                json data;file >> data;file.close();
                for(const auto chat : data){
                    if(chat["id"] == id){
                        response.send(Http::Code::Ok,chat["messages"].dump(),MIME(Application,Json));
                    }
                }
            }
        }catch(exception& e){
            response.send(Http::Code::Bad_Request,"Error");
        }
    }
}
void search_users(const Rest::Request& request,Http::ResponseWriter response){
    if(!siganture_middleware.validate_request(request)){
        response.send(Http::Code::Forbidden,"Invalid signature");
    }else{
        try{
            ifstream file(users_file);if(!file.is_open()) std::cerr << "Error while opening" << endl;
            else{
                json data;file >> data;file.close();
                const auto req_data = json::parse(request.body());
                vector<string> users_search;
                for(const auto& [user,pasw] : data.items()){
                    if(user == req_data["search"] || user.find(req_data["search"]) != string::npos || to_string(req_data["search"]).find(user) != string::npos){
                        users_search.push_back(user);
                    }
                }
                if(!users_search.empty()){
                    json res = users_search;
                    response.send(Http::Code::Ok,res.dump(),MIME(Application,Json));
                }else{
                    response.send(Http::Code::Not_Found,"Nothing found :(");
                }

            }
        }catch(exception& e){
            std::cerr << e.what() << endl;
            response.send(Http::Code::Bad_Request,e.what());
        }   
    }
}
void write_recent_search_find(const Rest::Request& request,Http::ResponseWriter response){
    if(!siganture_middleware.validate_request(request)){
        response.send(Http::Code::Forbidden,"Invalid signature");
    }else{
        try{
            ifstream file(recent_file);if(!file.is_open()) std::cerr << "Error while opening" << endl;
            else{
                json data;file >> data;file.close();
                auto user_data = json::parse(request.body());
                for(auto& user : data){
                    if(user["username"] == user_data["username"]){
                        user["recent"].push_back(user_data["recent"]);
                        ofstream exit_file(recent_file);if(!exit_file.is_open()) std::cerr << "Error while writing" << endl;
                        else{
                            exit_file << data.dump(4);exit_file.close();
                        }
                        response.send(Http::Code::Ok,"Done");
                        return;
                    }
                }
                response.send(Http::Code::Not_Found,"Error user not found :(");
            }
        }catch(exception& e){
            std::cerr << e.what() << endl;
            response.send(Http::Code::Bad_Request,e.what());
            return;
        }
    }
}
void delete_from_recent(const Rest::Request& request,Http::ResponseWriter response){
    if(!siganture_middleware.validate_request(request)){
        response.send(Http::Code::Forbidden,"Invalid signature");
    }else{
        try{
            bool indif = false;
            ifstream file(recent_file);if(!file.is_open()) std::cerr << "Error while opening" << endl;
            else{
                json data;file >> data;file.close();
                auto req_data = json::parse(request.body());
                for(auto user:data){
                    if(user["username"] == req_data["username"]){
                        indif = true;
                        long long int ind = index(user["recent"],req_data["to_delete"]);
                        if(ind != -1){
                            user["recent"].erase(user["recent"].begin() + ind);
                            ofstream exit_file(recent_file);if(!exit_file.is_open()) std::cerr << "Error while writing" << endl;
                            else{
                                exit_file << data.dump(4);exit_file.close();
                                response.send(Http::Code::Ok,"Done");

                            }
                        }else{
                            response.send(Http::Code::Not_Found,"Recent user not found");
                        }
                    }
                }if(!indif){
                    response.send(Http::Code::Not_Found,"User not found");
                }
            }
        }catch(exception& e){
            response.send(Http::Code::Bad_Request,e.what());
            std::cerr << e.what() << endl;
            return;
        }
    }
}


int main(){
    Http::Endpoint server(Address("*:8080")); 
    Rest::Router router;
    Routes::Get(router, "/api/data", Routes::bind(get_main));
    Routes::Post(router, "/api/register", Routes::bind(register_new_user));
    Routes::Post(router,"/api/create_new_chat",Routes::bind(Create_New_chat));
    Routes::Post(router,"/api/send/message",Routes::bind(write_the_message));
    Routes::Post(router,"/api/get/chat/messages",Routes::bind(get_chat_messages));
    Routes::Post(router,"/api/search",Routes::bind(search_users));
    Routes::Post(router,"/api/write/recent",Routes::bind(write_recent_search_find));
    Routes::Post(router,"/api/login",Routes::bind(login));
    Routes::Post(router,"/api/delete/chat",Routes::bind(delete_the_chat));
    Routes::Post(router,"/api/write/call",Routes::bind(write_call));
    server.init();
    server.setHandler(router.handler());
    server.serve();
}
