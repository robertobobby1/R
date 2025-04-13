#pragma once

#include "Net.h"
#include "P2P.h"

#include <chrono>
#include <vector>
#include <functional>
#include <thread>

namespace R::Net::P2P {

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
            auto forceRecheck = false;
            buffer.write(KeepAliveHeader);

            while (keepRunning) {
                if (!forceRecheck) {
                    std::this_thread::sleep_for(std::chrono::seconds(timerInSeconds));
                }

                forceRecheck = false;
                if (keepAliveSockets.size() == 0) {
                    continue;
                }
                for (auto& socket : keepAliveSockets) {
                    sendResponse = sendKeepAlivePackage(socket.first, buffer);
                    if (maxPackagesToSend == ++socket.second) {
                        if (onMaxPackagesArrivedCallback != nullptr) {
                            onMaxPackagesArrivedCallback(socket.first);
                        }
                    } else if (sendResponse != -1) {
                        continue;
                    }

                    removeSocketToKeepAlive(socket.first);
                    if (onClosedCallback != nullptr) {
                        onClosedCallback(socket.first);
                    }

                    forceRecheck = true;
                    break;
                }
            }
        }

        inline void runInNewThread() {
            runningThread = std::thread(BIND_FN(KeepAliveManager::run));
        }

        inline void addNewSocketToKeepAlive(Socket _socket) {
            keepAliveSockets[_socket] = 0;
        }

        inline void removeSocketToKeepAlive(Socket _socket) {
            keepAliveSockets.erase(_socket);
        }

        inline void addOnConnectionClosedCallback(std::function<void(Socket)> func) {
            onClosedCallback = func;
        }

        inline void addOnKeepAliveMaxPackagesSent(uint16_t maxPackages, std::function<void(Socket)> func = nullptr) {
            maxPackagesToSend = maxPackages;

            if (func != nullptr) {
                onMaxPackagesArrivedCallback = func;
            }
        }

        std::unordered_map<Socket, int> keepAliveSockets;
        std::function<void(Socket)> onClosedCallback = nullptr;
        std::function<void(Socket)> onMaxPackagesArrivedCallback = nullptr;
        std::thread runningThread;

        // flag to be able to stop it
        bool keepRunning = true;
        int timerInSeconds;
        int maxPackagesToSend = -1;
    };
}  // namespace R::Net::P2P