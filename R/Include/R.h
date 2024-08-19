

// begin --- Utils.h --- 

#pragma once

#include <cstdint>
#include <queue>

namespace R::Utils {

    inline bool isInRange(int value, int lowRange, int highRange) {
        return value <= highRange && value >= lowRange;
    }

    inline bool isFlagSet(uint8_t flagObject, uint8_t flag) {
        return 0 != (flagObject & flag);
    }

    inline void setFlag(uint8_t &flagObject, uint8_t flag) {
        flagObject |= flag;
    }

    inline void unsetFlag(uint8_t &flagObject, uint8_t flag) {
        flagObject &= ~flag;
    }

    template <typename T>
    inline T getFromQueue(std::queue<T> &queue) {
        if (queue.empty()) {
            if constexpr (std::is_same_v<T, std::string>) {
                return "";
            } else if constexpr (std::is_same_v<T, int>) {
                return -1;
            } else {
                return nullptr;
            }
        }

        auto value = queue.front();
        queue.pop();
        return value;
    }

    template <typename T>
    inline T getThreadSafeFromQueue(std::queue<T> &queue, std::mutex &queueMutex) {
        std::lock_guard<std::mutex> lock(queueMutex);
        return getFromQueue(queue);
    }

    template <typename T>
    inline T getThreadSafeFromQueue(std::queue<T> &queue, std::mutex &queueMutex, std::condition_variable &condition) {
        std::unique_lock<std::mutex> lock(queueMutex);
        condition.wait(lock);
        return getFromQueue(queue);
    }

    template <typename T>
    inline void setThreadSafeToQueue(std::queue<T> &queue, std::mutex &queueMutex, T value) {
        std::lock_guard<std::mutex> lock(queueMutex);
        queue.push(value);
    }

    inline std::string generateUUID(int length) {
        static const char alphanum[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";
        std::string uuid;
        uuid.reserve(length);

        for (int i = 0; i < length; ++i) {
            uuid += alphanum[rand() % (sizeof(alphanum) - 1)];
        }
        return uuid;
    };

    inline int randomNumber(int min, int max) {
        return rand() % (max - min + 1) + min;
    }

    inline unsigned int randomUintNumber(int min, int max) {
        return (unsigned int)(rand() % (max - min + 1) + min);
    }
}  // namespace R::Utils

// end --- Utils.h --- 



// begin --- Client.h --- 



// begin --- Network.h --- 

#pragma once
#include <iostream>

// begin --- Platform.h --- 

#pragma once

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#    pragma message("WIN32 || _WIN32 || __WIN32__ || __NT__")
#    ifndef PLATFORM_WINDOWS
#        define PLATFORM_WINDOWS
#    endif
#    ifdef _WIN64
#    endif

#elif __APPLE__
#    include <TargetConditionals.h>
#    if TARGET_IPHONE_SIMULATOR
#    elif TARGET_OS_MACCATALYST
#    elif TARGET_OS_IPHONE
#    elif TARGET_OS_MAC
#        ifndef PLATFORM_MACOS
#            define PLATFORM_MACOS
#        endif
#    else
#        error "Unknown Apple platform"
#    endif

#elif __ANDROID__
#    ifndef PLATFORM_LINUX
#        define PLATFORM_LINUX
#    endif
#elif __linux__
#    ifndef PLATFORM_LINUX
#        define PLATFORM_LINUX
#    endif
#elif __unix__
#    ifndef PLATFORM_LINUX
#        define PLATFORM_LINUX
#    endif
#elif defined(_POSIX_VERSION)
#    ifndef PLATFORM_LINUX
#        define PLATFORM_LINUX
#    endif
#else
#    error("Unknown compiler")
#endif

#ifdef PLATFORM_LINUX
#    pragma message("This is linux")
#elif defined(PLATFORM_MACOS)
#    pragma message("This is MacOS")
#elif defined(PLATFORM_WINDOWS)
#    pragma message("This is Windows")
#else
#    pragma message("This is an unknown OS")
#endif

#if defined(PLATFORM_MACOS) || defined(PLATFORM_LINUX)
#    include <sys/socket.h>
#    include <netinet/in.h>
#    include <netinet/tcp.h>
#    include <arpa/inet.h>
#    include <unistd.h>
#    include <fcntl.h>
#    include <netdb.h>
#elif defined(PLATFORM_WINDOWS)
#    include <WinSock2.h>
#    include <ws2tcpip.h>
#    pragma comment(lib, "winmm.lib")
#    pragma comment(lib, "WS2_32.lib")
#    include <Windows.h>
#endif


// end --- Platform.h --- 



namespace R::Network {
#if defined(PLATFORM_MACOS) || defined(PLATFORM_LINUX)
    typedef int Socket;
#    define NoBiggyAcceptSocketError -1
#elif defined(PLATFORM_WINDOWS)
    typedef SOCKET Socket;
#    define NoBiggyAcceptSocketError INVALID_SOCKET
#endif

    struct Buffer {
        std::shared_ptr<char[]> ini;
        int size;

        Buffer(std::shared_ptr<char[]> _ini, int _size)
            : ini(_ini), size(_size) {}

        Buffer(const char *buffer, int _size) : size(_size) {
            ini = std::shared_ptr<char[]>(new char[size]);
            memcpy(ini.get(), buffer, size);
        }
    };

#if defined(PLATFORM_MACOS)

    uint32_t getRTTOfClient(Socket clientSocket) {
        struct tcp_connection_info info;
        socklen_t info_len = sizeof(info);

        int result = getsockopt(clientSocket, IPPROTO_TCP, TCP_CONNECTION_INFO, &info, &info_len);

        return info.tcpi_srtt;
    }

#elif defined(PLATFORM_LINUX)

    uint32_t getRTTOfClient(Socket clientSocket) {
        struct tcp_info info;
        socklen_t info_len = sizeof(info);

        int result = getsockopt(clientSocket, IPPROTO_TCP, TCP_INFO, &info, &info_len);

        return info.tcpi_srtt;
    }

#endif

#if defined(PLATFORM_MACOS) || defined(PLATFORM_LINUX)

    bool setServerNonBlockingMode(Socket socket) {
        int flags = fcntl(socket, F_GETFL, 0);
        flags = flags | O_NONBLOCK;
        return (fcntl(socket, F_SETFL, flags) == 0);
    }

    void onError(Socket socket, bool closeSocket, const char *errorMessage) {
        printf("%s - errno %i\n", errorMessage, errno);
        if (closeSocket) {
            close(socket);
        }
    }

#elif defined(PLATFORM_WINDOWS)

    uint32_t getRTTOfClient(Socket clientSocket) {
        // TODO how to get RTT in windows
    }

    void setServerNonBlockingMode(Socket socket) {
        unsigned long mode = 1;
        return (ioctlsocket(fd, FIONBIO, &mode) == 0);
    }

    void onError(Socket socket, bool closeSocket, const char *errorMessage) {
        if (closeSocket) {
            closesocket(socket);
        }
        printf("%s --- winsock2 error code is: %i\n", errorMessage, WSAGetLastError());
        WSACleanup();
    }
#endif

    void sendMessage(Socket socket, Buffer buff, const char *message) {
        if (send(socket, buff.ini.get(), buff.size, NULL) < 0)
            onError(socket, false, message);
    }

    Buffer readMessage(Socket socket, const char *message) {
        char buffer[255];
        int bufferSize = read(socket, buffer, 255);
        if (bufferSize < 0)
            onError(socket, false, message);

        return {buffer, bufferSize};
    }

    bool checkForErrors(Socket socket, int errorMacro, const char *errorMessage, bool closeSocket) {
        if (socket == errorMacro) {
            onError(socket, closeSocket, errorMessage);
            return true;
        }
        return false;
    }
}  // namespace R::Network

// end --- Network.h --- 



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

// end --- Client.h --- 



// begin --- Server.h --- 



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

// end --- Server.h --- 

