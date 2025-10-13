#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <nlohmann/json.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

using namespace std;

using json = nlohmann::json;

boost::uuids::random_generator  id_genrator;

void create_an_empty_chat(){
    ifstream file("/Users/ivan/LUX-Call/data/chats.json");
    if(!file.is_open()){
        cerr << "Error" << endl;
        return;
    }
    string id = boost::uuids::to_string(id_genrator());
    json data;
    file >> data;
    file.close();
    json new_chat = {
        {"users",json::array()},
        {"id",id},
        {"messages",json::array()}
    };
    data.push_back(new_chat);
    
    ofstream exit_file("/Users/ivan/LUX-Call/data/chats.json");
    if(!exit_file.is_open()){
        cerr << "Error while writing" << endl;
        return;
    }
    exit_file << data.dump(4);
    exit_file.close();

}
int main(){
    for(int i = 0;i < 10;i++){
        create_an_empty_chat();
    }
    return 0;
}