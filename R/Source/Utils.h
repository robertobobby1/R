#pragma once

#include <cstdint>
#include <queue>
#include <mutex>
#include <unordered_map>

#include "Buffer.h"
#include "Macros.h"
#include "NetImports.h"

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

    template <class ADAPTER>
    const auto &getQueueCObject(ADAPTER &a) {
        struct hack : private ADAPTER {
            static auto &get(ADAPTER &a) {
                return a.*(&hack::c);
            }
        };

        return hack::get(a);
    }

    template <typename T>
    void removeFromVector(std::vector<T> &vector, T value) {
        auto it = std::find(vector.begin(), vector.end(), value);
        if (it != vector.end()) {
            vector.erase(it);
        }
    }

    template <typename T, typename K>
    inline bool keyExistsInMap(std::unordered_map<T, K> &map, T &key) {
        auto it = map.find(key);
        if (it == map.end()) {
            return false;
        }
        return true;
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

#if defined(PLATFORM_MACOS) || defined(PLATFORM_LINUX)

    inline void onExceptionHandler(int sig) {
        void *array[10];
        size_t size;

        // get void*'s for all entries on the stack
        size = backtrace(array, 10);

        // print out all the frames to stderr
        RLog("[Expception Handler]: signal %d:\n", sig);
        backtrace_symbols_fd(array, size, STDERR_FILENO);
        exit(1);
    }

    inline void stackTracing() {
        signal(SIGSEGV, onExceptionHandler);
    }

#endif

    inline void hexDump(Buffer buffer) {
        unsigned char *buf = (unsigned char *)buffer.ini;
        unsigned int i, j;
        for (i = 0; i < buffer.size; i += 16) {
            RLog("%06x: ", i);
            for (j = 0; j < 16; j++)
                if (i + j < buffer.size)
                    RLog("%02x ", buf[i + j]);
                else
                    RLog("   ");
            RLog(" ");
            for (j = 0; j < 16; j++)
                if (i + j < buffer.size)
                    RLog("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
            RLog("\n");
        }
    }
}  // namespace R::Utils