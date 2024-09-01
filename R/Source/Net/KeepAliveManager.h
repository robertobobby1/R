#pragma once

#include "Net.h"
#include "P2P.h"

#include <chrono>
#include <vector>
#include <functional>
#include <thread>

namespace R::Net::P2P {

    typedef std::function<Socket()> LogCallbackFunction;
    inline const int timerInSeconds = 100;
    inline const char* KeepAliveHeader = "\xFF";

    class KeepAliveManager {
        ~KeepAliveManager() {
            delete runningThread;
        }

        inline void run() {
            int sendResponse = 0;
            auto buffer = createSecuredBuffer();
            buffer.write(KeepAliveHeader, 1);

            while (keepRunning) {
                std::this_thread::sleep_for(std::chrono::seconds(timerInSeconds));
                for (auto& socket : keepAliveSockets) {
                    sendResponse = Net::sendMessage(socket, buffer, "[Keep Alive] Error while sending a keep alive message");
                    if (sendResponse != -1) {
                        continue;
                    }

                    RLog("ERROR sending to other socket");
                    keepAliveSockets.erase(std::remove(keepAliveSockets.begin(), keepAliveSockets.end(), socket));
                }
            }
        }

        inline void runInNewThread() {
            runningThread = new std::thread(run);
        }

        inline void addNewSocketToKeepAlive(Socket _socket) {
            keepAliveSockets.push_back(_socket);
        }

        inline void addOnConnectionClosedCallback(std::function<Socket()> func) {
            onClosedCallback = func;
        }

        std::vector<Socket> keepAliveSockets;
        std::function<Socket()> onClosedCallback = nullptr;
        std::thread* runningThread;

        // flag to be able to stop it
        bool keepRunning = true;
    };
}  // namespace R::Net::P2P