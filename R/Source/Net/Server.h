#pragma once

#include "Net.h"
#include "Macros.h"

namespace R::Net {

    class Server {
       public:
        Socket _socket;
        bool isRunning = false;

        static std::shared_ptr<Server> make() {
            return std::make_shared<Server>();
        }

        static std::shared_ptr<Server> makeAndRun(int port = 3000, int backlog = 10) {
            auto server = make();
            server->run(port, backlog);
            return server;
        }

#if defined(PLATFORM_MACOS) || defined(PLATFORM_LINUX)

        inline bool run(int port = 3000, int backlog = 10) {
            _socket = socket(AF_INET, SOCK_STREAM, 0);

            sockaddr_in serverAddress;
            serverAddress.sin_family = AF_INET;
            serverAddress.sin_port = htons(port);
            serverAddress.sin_addr.s_addr = INADDR_ANY;

            if (checkForErrors(bind(_socket, (sockaddr *)&serverAddress, sizeof(serverAddress)), -1, "[Server] Error on socket binding", true)) {
                return false;
            }

            if (checkForErrors(listen(_socket, backlog), -1, "[Server] Error while starting to listen on port", true)) {
                return false;
            }

            RLog("[Server] Started listening in port %i\n", port);
            isRunning = true;
            return true;
        }

#elif defined(PLATFORM_WINDOWS)

        inline bool run(int port = 3000, int backlog = 10) {
            WSADATA wsaData;
            sockaddr_in service;
            service.sin_family = AF_INET;
            service.sin_port = htons(port);
            inet_pton(AF_INET, "127.0.0.1", &service.sin_addr);

            int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
            if (iResult != NO_ERROR) {
                onError(_socket, false, "");
                return false;
            }

            _socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (checkForErrors(_socket, INVALID_SOCKET, "[Server] Error on socket creation", false))
                return false;

            // If error on socket binding it may mean that the port is in use, we can search a new one!
            if (checkForErrors(bind(_socket, (SOCKADDR *)&service, sizeof(service)), SOCKET_ERROR, "[Server] Error on socket binding", true))
                return false;

            if (checkForErrors(listen(_socket, 1), SOCKET_ERROR, "[Server] Error while starting to listen on port", true))
                return false;

            unsigned long blocking_mode = 0;
            if (checkForErrors(ioctlsocket(_socket, FIONBIO, &blocking_mode), -1, "[Server] Error while setting the blocking mode", true))
                return false;

            RLog("[Server] Started listening in port %i\n", port);
            isRunning = true;
            return true;
        }

#endif

        inline void terminate() {
            onError(_socket, true, "[Server] Closing the server socket!");
        }

        inline Socket acceptNewConnection(bool checkErrors = true) {
            if (!isRunning) {
                RLog("[Server] Cannot accept connections if server is not running");
                return -1;
            }

            Socket AcceptSocket = accept(_socket, NULL, NULL);
            if (checkErrors && checkForErrors(AcceptSocket, SocketError, "[Server] Error while accepting new connections", true))
                return -1;

            return AcceptSocket;
        }

        inline int sendMessage(Socket socket, Buffer buff) {
            return Net::sendMessage(socket, buff, "[Server] Couldn't send message");
        }

        inline Buffer readMessage(Socket socket) {
            return Net::readMessage(socket, "[Server] Couldn't read message");
        }
    };

}  // namespace R::Net