#pragma once

#include <iostream>

#include "Platform.h"
#include "Buffer.h"

namespace R::Net {

#if defined(PLATFORM_MACOS) || defined(PLATFORM_LINUX)
    typedef int Socket;
#    define SocketError -1
#elif defined(PLATFORM_WINDOWS)
    typedef SOCKET Socket;
#    define SocketError INVALID_SOCKET
#endif

#if defined(PLATFORM_MACOS)

    inline uint32_t getRTTOfClient(Socket _socket) {
        struct tcp_connection_info info;
        socklen_t info_len = sizeof(info);

        int result = getsockopt(_socket, IPPROTO_TCP, TCP_CONNECTION_INFO, &info, &info_len);

        return info.tcpi_srtt;
    }

#elif defined(PLATFORM_LINUX)

    inline uint32_t getRTTOfClient(Socket _socket) {
        struct tcp_info info;
        socklen_t info_len = sizeof(info);

        int result = getsockopt(_socket, IPPROTO_TCP, TCP_INFO, &info, &info_len);

        return info.tcpi_srtt;
    }

#endif

#if defined(PLATFORM_MACOS) || defined(PLATFORM_LINUX)

    inline bool setServerNonBlockingMode(Socket socket) {
        int flags = fcntl(socket, F_GETFL, 0);
        flags = flags | O_NONBLOCK;
        return (fcntl(socket, F_SETFL, flags) == 0);
    }

    inline void onError(Socket socket, bool closeSocket, const char *errorMessage) {
        printf("%s - errno %i\n", errorMessage, errno);
        if (closeSocket) {
            close(socket);
        }
    }

#elif defined(PLATFORM_WINDOWS)

    inline uint32_t getRTTOfClient(Socket _socket) {
        // TODO how to get RTT in windows
    }

    inline void setServerNonBlockingMode(Socket socket) {
        unsigned long mode = 1;
        return (ioctlsocket(fd, FIONBIO, &mode) == 0);
    }

    inline void onError(Socket socket, bool closeSocket, const char *errorMessage) {
        if (closeSocket) {
            closesocket(socket);
        }
        printf("%s --- winsock2 error code is: %i\n", errorMessage, WSAGetLastError());
        WSACleanup();
    }
#endif

    inline int sendMessage(Socket socket, Buffer buff, const char *message) {
        auto sendResponse = send(socket, buff.ini, buff.size, 0);
        if (sendResponse < 0)
            onError(socket, false, message);

        return sendResponse;
    }

    inline Buffer readMessage(Socket socket, const char *message) {
        char stackBuffer[255];
        auto buffer = Buffer(255);
        int bufferSize = read(socket, stackBuffer, 255);
        if (bufferSize < 0) {
            onError(socket, false, message);
        } else {
            buffer.write(stackBuffer, bufferSize);
        }

        return buffer;
    }

    inline bool checkForErrors(Socket socket, int errorMacro, const char *errorMessage, bool closeSocket) {
        if (socket == errorMacro) {
            onError(socket, closeSocket, errorMessage);
            return true;
        }
        return false;
    }
}  // namespace R::Net