#include "Client.h"
#include "Server.h"
#include "Utils.h"

#include <thread>

void server() {
    auto server = R::Net::Server::makeAndRun();
    if (!server->isRunning) {
        RLog("[Server] Error starting the server\n");
        return;
    }

    bool openConexion = true;
    char buffer[512];

    // iterate till infinite
    while (true) {
        R::Net::Socket newConnection = server->acceptNewConnection();
        if (newConnection == -1) {
            continue;
        }
        while (openConexion) {
            auto buff = server->readMessage(newConnection);
            if (buff.size > 0) {
                RLog("[Server] size: %i, message: %s\n", (int)buff.size, buff.ini);
            } else {
                openConexion = false;
            }
        }
    }
}

int main() {
    std::thread SERVER_THREAD = std::thread(server);
    sleep(1);
    auto client = R::Net::Client::makeAndRun("localhost", 3000);
    while (client->isRunning) {
        sleep(2);
        auto messageLength = R::Utils::randomNumber(10, 30);
        auto message = R::Utils::generateUUID(messageLength);

        auto buffer = R::Buffer(30);
        buffer.write(message.c_str(), messageLength);
        client->sendMessage(buffer);
    }

    SERVER_THREAD.join();
}
