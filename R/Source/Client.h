#include "Network.h"

namespace R::Network {

    class Client {
       public:
        Socket clientSocket;
        bool isRunning = false;

        static std::shared_ptr<Client> make() {
            return std::make_shared<Client>();
        }

        static std::shared_ptr<Client> makeAndRun(const char *hostname, int port) {
            auto client = make();
            client->run(hostname, port);
            return client;
        }

#if defined(PLATFORM_MACOS) || defined(PLATFORM_LINUX)

        bool run(const char *hostname, int port) {
            struct sockaddr_in socketAddress;
            struct hostent *server;

            clientSocket = socket(AF_INET, SOCK_STREAM, 0);

            server = gethostbyname(hostname);
            if (server == NULL) {
                Network::onError(clientSocket, false, "[Client] ERROR getting host name");
                return false;
            }

            bzero((char *)&socketAddress, sizeof(socketAddress));
            socketAddress.sin_family = AF_INET;
            bcopy((char *)server->h_addr, (char *)&socketAddress.sin_addr.s_addr, server->h_length);
            socketAddress.sin_port = htons(port);

            if (connect(clientSocket, (struct sockaddr *)&socketAddress, sizeof(socketAddress)) < 0) {
                Network::onError(clientSocket, false, "[Client] Couldn't connect to the host");
                return false;
            }

            printf("[Client] Connected to hostname %s and port %i\n", hostname, port);
            isRunning = true;
            return true;
        }

#elif defined(PLATFORM_WINDOWS)

        bool run(const char *hostname, int port) {
            WSADATA wsaData;
            int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
            if (iResult != NO_ERROR) {
                onError(clientSocket, false, "[Client] Error on WSAStartup");
                return false;
            }

            struct addrinfo *result = NULL,
                            *ptr = NULL,
                            hints;

            ZeroMemory(&hints, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;

            iResult = getaddrinfo(hostname, port, &hints, &result);
            if (iResult != 0) {
                onError(clientSocket, false, "[Client] Error on getaddrinfo");
                return false;
            }

            ptr = result;
            Socket ConnectSocket = INVALID_SOCKET;

            for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
                ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
                if (Network::checkForErrors(ConnectSocket, INVALID_SOCKET, false, "[Client] Error on socket creation")) {
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
            if (Network::checkForErrors(ConnectSocket, INVALID_SOCKET, true, "[Client] Couldn't connect to the server")) {
                return false;
            }

            printf("[Client] Connected to hostname %s and port %i\n", hostname, port);
            isRunning = true;
            return true;
        }

#endif

        void terminate() {
            Network::onError(clientSocket, true, "[Client] Closing the client socket!");
        }

        void sendMessage(Network::Buffer buff) {
            Network::sendMessage(clientSocket, buff, "[Client] Couldn't send message");
        }

        Network::Buffer readMessage(Socket socket) {
            return Network::readMessage(clientSocket, "[Client] Couldn't read message");
        }
    };

}  // namespace R