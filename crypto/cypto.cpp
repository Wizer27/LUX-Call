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
#include  <openssl>


using namespace std;
using json = nlohmann::json;


class Hashing{
public:
    size_t get_hash(string mess){
        return std::hash<std::string>()(mess);
    }
};


int main(){
    return 0;
}

