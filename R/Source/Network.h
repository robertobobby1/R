#pragma once
#include <iostream>
#include "Platform.h"

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