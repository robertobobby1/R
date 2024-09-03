#pragma once

#include "Net.h"
#include "P2P.h"

#include <chrono>
#include <vector>
#include <functional>
#include <thread>

namespace R::Net::P2P {

    typedef std::function<Socket()> LogCallbackFunction;
    inline const int defaultTimerInSeconds = 10;
    inline uint8_t KeepAliveHeader = 255;

    class KeepAliveManager {
       public:
        KeepAliveManager(int _timerInSeconds)
            : timerInSeconds(_timerInSeconds) {}
        KeepAliveManager()
            : timerInSeconds(defaultTimerInSeconds) {}

        static inline std::shared_ptr<KeepAliveManager> make(int _timerInSeconds = defaultTimerInSeconds) {
            return std::make_shared<KeepAliveManager>(_timerInSeconds);
        }

        static inline std::shared_ptr<KeepAliveManager> makeAndRun(int _timerInSeconds = defaultTimerInSeconds) {
            auto instance = make(_timerInSeconds);
            instance->runInNewThread();
            return instance;
        }

        static inline bool isKeepAlivePackage(Buffer& buffer) {
            return isValidAuthedRequest(buffer) && getProtocolHeader(buffer) == KeepAliveHeader;
        }

        static inline int sendKeepAlivePackage(Socket socket) {
            auto buffer = createSecuredBuffer();
            buffer.write(KeepAliveHeader);

            return sendKeepAlivePackage(socket, buffer);
        }

        static inline int sendKeepAlivePackage(Socket socket, Buffer& buffer) {
            return Net::sendMessage(socket, buffer, "[Keep Alive] Client socket disconected!");
        }

        static inline bool isSocketActive(Socket socket) {
            auto sendResponse = sendKeepAlivePackage(socket);
            if (sendResponse == -1) {
                return false;
            }
            return true;
        }

        inline void run() {
            int sendResponse = 0;
            auto buffer = createSecuredBuffer();
            buffer.write(KeepAliveHeader);

            while (keepRunning) {
                std::this_thread::sleep_for(std::chrono::seconds(timerInSeconds));
                for (auto& socket : keepAliveSockets) {
                    sendResponse = sendKeepAlivePackage(socket, buffer);
                    if (sendResponse != -1) {
                        continue;
                    }

                    removeSocketToKeepAlive(socket);
                    if (onClosedCallback != nullptr) {
                        onClosedCallback(socket);
                    }
                }
            }
        }

        inline void runInNewThread() {
            runningThread = std::thread(BIND_FN(KeepAliveManager::run));
        }

        inline void addNewSocketToKeepAlive(Socket _socket) {
            keepAliveSockets.push_back(_socket);
        }

        inline void removeSocketToKeepAlive(Socket _socket) {
            Utils::removeFromVector(keepAliveSockets, _socket);
        }

        inline void addOnConnectionClosedCallback(std::function<void(Socket)> func) {
            onClosedCallback = func;
        }

        std::vector<Socket> keepAliveSockets;
        std::function<void(Socket)> onClosedCallback = nullptr;
        std::thread runningThread;

        // flag to be able to stop it
        bool keepRunning = true;
        int timerInSeconds;
    };
}  // namespace R::Net::P2P