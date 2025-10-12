#include <iostream>
#include <algorithm>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <thread>
#include <string>
#include "/Users/ivan/vcpkg/installed/arm64-osx/include/rtc/rtc.hpp" //chacnge to your path



using namespace std;
std::shared_ptr<rtc::PeerConnection> pc;

class VideoCall {
public:
    void start_as_caller() {
        cout << "STARTING" << endl;
        setupPeerConnection();
        addMediaTracks();
        createOffer();
        waitForCall();
        pc -> setLocalDescription();
    }
    void start_as_callee() {
        cout << "STARTING AS CALLEE";
        setupPeerConnection();
        addMediaTracks();
        waitForOffer();
    }
private:
    void setupPeerConnection(){

    }   
    void addMediaTracks(){

    } 
    void createOffer(){

    }
    void waitForCall(){

    }
    void waitForOffer(){

    }
};

int main() {
    cout << "TEST";
    return 0;
}


