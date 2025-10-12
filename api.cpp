#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <sstream>
#include <nlohmann/json.hpp>
#include <pistache/endpoint.h>
#include <pistache/router.h>


using namespace std;
using namespace Pistache;
using namespace Pistache::Rest; 
using json = nlohmann::json;


void get_main(const Rest::Request& request,Http::ResponseWriter response){
    response.send(Http::Code::Ok,"Lux-Call API");
}

int main(){
    Http::Endpoint server(Address("*:8080")); 
    Rest::Router router;
    Routes::Post(router, "/api/data", Routes::bind(get_main));
}
