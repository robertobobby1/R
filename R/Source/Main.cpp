#define CLIENT
#define SERVER

#include "Client.h"
#include "Server.h"

#include <thread>

void server() {
    bool isRunning = NB::Server::run();
    if (!isRunning) {
        printf("[Server] ERROR\n");
    }

    bool openConexion = true;
    char buffer[512];

    // iterate till infinite
    while (true) {
        Socket newConnection = NB::Server::acceptNewConnection();
        if (newConnection == -1) {
            continue;
        }
        while (openConexion) {
            NB::Network::Buffer buff = NB::Server::readMessage(newConnection);
            if (buff.size > 0) {
                std::cout << buff.size << std::endl;
                std::cout << buff.ini.get() << std::endl;
            } else {
                openConexion = false;
            }
        }
    }
}

int main() {
    std::thread SERVER_THREAD = std::thread(server);
    sleep(5);
    bool isRunning = NB::Client::run("localhost", 3000);
    if (!isRunning) {
        printf("[Client] ERROR\n");
    }

    NB::Client::sendMessage({"My name is Roberto", 19});
    SERVER_THREAD.join();
}
