#pragma once

#include "Net.h"
#include "Macros.h"
#include "NetImports.h"

#include <string>

namespace R::Net {

    class Client {
       public:
        Socket _socket;
        bool isRunning = false;

        static std::shared_ptr<Client> make() {
            return std::make_shared<Client>();
        }

        static std::shared_ptr<Client> makeAndRun(const char *hostname, int port) {
            auto client = make();
            client->run(hostname, port);
            return client;
        }

        static std::shared_ptr<Client> makeAndSet(Socket socket) {
            auto client = make();
            client->_socket = socket;
            client->isRunning = true;
            return client;
        }

#if defined(PLATFORM_MACOS) || defined(PLATFORM_LINUX)

        inline bool run(const char *hostname, int port) {
            struct sockaddr_in socketAddress;
            struct hostent *server;

            _socket = socket(AF_INET, SOCK_STREAM, 0);

            server = gethostbyname(hostname);
            if (server == NULL) {
                onError(_socket, false, "[Client] ERROR getting host name");
                return false;
            }

            bzero((char *)&socketAddress, sizeof(socketAddress));
            socketAddress.sin_family = AF_INET;
            bcopy((char *)server->h_addr, (char *)&socketAddress.sin_addr.s_addr, server->h_length);
            socketAddress.sin_port = htons(port);

            if (connect(_socket, (struct sockaddr *)&socketAddress, sizeof(socketAddress)) < 0) {
                onError(_socket, false, "[Client] Couldn't connect to the host");
                return false;
            }

            RLog("[Client] Connected to hostname %s and port %i\n", hostname, port);
            isRunning = true;
            return true;
        }

#elif defined(PLATFORM_WINDOWS)

        inline bool run(const char *hostname, int port) {
            WSADATA wsaData;
            int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
            if (iResult != NO_ERROR) {
                onError(_socket, false, "[Client] Error on WSAStartup");
                return false;
            }

            struct addrinfo *result = NULL,
                            *ptr = NULL,
                            hints;

            ZeroMemory(&hints, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;

            iResult = getaddrinfo(hostname, std::to_string(port).c_str(), &hints, &result);
            if (iResult != 0) {
                onError(_socket, false, "[Client] Error on getaddrinfo");
                return false;
            }

            ptr = result;
            Socket ConnectSocket = INVALID_SOCKET;

            for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
                ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
                if (checkForErrors(ConnectSocket, INVALID_SOCKET, "[Client] Error on socket creation", false)) {
                    freeaddrinfo(result);
                    return false;
                }

                iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
                if (iResult == SOCKET_ERROR) {
                    closesocket(ConnectSocket);
                    ConnectSocket = INVALID_SOCKET;
                    continue;
                }
            }

            freeaddrinfo(result);
            if (checkForErrors(ConnectSocket, INVALID_SOCKET, "[Client] Couldn't connect to the server", true)) {
                return false;
            }

            RLog("[Client] Connected to hostname %s and port %i\n", hostname, port);
            isRunning = true;
            return true;
        }

#endif

        inline void terminate() {
            isRunning = false;
            onError(_socket, true, "[Client] Closing the client socket!");
        }

        inline int sendMessage(Buffer buff) {
            auto sendResponse = Net::sendMessage(_socket, buff, "[Client] Couldn't send message");
            if (sendResponse == -1) {
                isRunning = false;
            }
            return sendResponse;
        }

        inline Buffer readMessage() {
            auto readResponse = Net::readMessage(_socket, "[Client] Couldn't read message");
            if (readResponse.size <= 0) {
                isRunning = false;
            }
            return readResponse;
        }
    };

}  // namespace R::Net