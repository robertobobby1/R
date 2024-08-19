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
