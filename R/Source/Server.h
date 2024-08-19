
#include "Network.h"

namespace R::Network {

    class Server {
       public:
        Socket serverSocket;
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

        bool run(int port = 3000, int backlog = 10) {
            serverSocket = socket(AF_INET, SOCK_STREAM, 0);

            sockaddr_in serverAddress;
            serverAddress.sin_family = AF_INET;
            serverAddress.sin_port = htons(port);
            serverAddress.sin_addr.s_addr = INADDR_ANY;

            if (Network::checkForErrors(bind(serverSocket, (sockaddr *)&serverAddress, sizeof(serverAddress)), -1, "[Server] Error on socket binding", true)) {
                return false;
            }

            if (Network::checkForErrors(listen(serverSocket, backlog), -1, "[Server] Error while starting to listen on port", true)) {
                return false;
            }

            printf("[Server] Started listening in port %i\n", port);
            isRunning = true;
            return true;
        }

#elif defined(PLATFORM_WINDOWS)

        bool run(int port = 3000, int backlog = 10) {
            WSADATA wsaData;
            sockaddr_in service;
            service.sin_family = AF_INET;
            service.sin_port = htons(port);
            inet_pton(AF_INET, "127.0.0.1", &service.sin_addr);

            int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
            if (iResult != NO_ERROR) {
                onError(serverSocket, false, "");
                return false;
            }

            serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (Network::checkForErrors(serverSocket, INVALID_SOCKET, "[Server] Error on socket creation", false))
                return false;

            // If error on socket binding it may mean that the port is in use, we can search a new one!
            if (Network::checkForErrors(bind(serverSocket, (SOCKADDR *)&service, sizeof(service)), SOCKET_ERROR, "[Server] Error on socket binding", true))
                return false;

            if (Network::checkForErrors(listen(serverSocket, 1), SOCKET_ERROR, "[Server] Error while starting to listen on port", true))
                return false;

            unsigned long blocking_mode = 0;
            if (Network::checkForErrors(ioctlsocket(serverSocket, FIONBIO, &blocking_mode), -1, "[Server] Error while setting the blocking mode", true))
                return false;

            printf("[Server] Started listening in port %i\n", port);
            isRunning = true;
            return true;
        }

#endif

        void terminate() {
            Network::onError(serverSocket, true, "[Server] Closing the server socket!");
        }

        Socket acceptNewConnection() {
            Socket AcceptSocket = accept(serverSocket, NULL, NULL);
            if (Network::checkForErrors(AcceptSocket, NoBiggyAcceptSocketError, "[Server] Error while accepting new connections", true))
                return -1;

            return AcceptSocket;
        }

        void sendMessage(Network::Buffer buff) {
            Network::sendMessage(serverSocket, buff, "[Server] Couldn't send message");
        }

        Network::Buffer readMessage(Socket socket) {
            return Network::readMessage(socket, "[Server] Couldn't read message");
        }
    };

}  // namespace R