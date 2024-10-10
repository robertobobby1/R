#pragma once

#include <cstdint>
#include <queue>
#include <mutex>
#include <unordered_map>
#include <condition_variable>

#include "Buffer.h"
#include "Macros.h"
#include "NetImports.h"
#include "Tempo.h"
#include "Random.h"

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
    inline void removeFromQueue(std::queue<T> &queue, T &value) {
        auto queueC = getQueueCObject(queue);

        for (auto it = queueC.begin(); it != queueC.end(); ++it) {
            if (*it == value) {
                queueC.erase(it);
            }
        }
    }

    template <typename T>
    inline T getFromQueue(std::queue<T> &queue) {
        if (queue.empty()) {
            if constexpr (std::is_same_v<T, std::string>) {
                return "";
            } else if constexpr (std::is_same_v<T, int>) {
                return -1;
            } else if constexpr (std::is_same_v<T, unsigned int>) {
                return -1;
            } else {
                return NULL;
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
        return RVendor::Random::GetString(RVendor::Random::Charset::AlphaNum, length);
    };

    inline int randomNumber(int min, int max) {
        return RVendor::Random::GetInt(min, max);
    }

    inline unsigned int randomUintNumber(unsigned int min, unsigned int max) {
        return (unsigned int)RVendor::Random::GetInt(min, max);
    }

    template <class Rep, class Period>
    inline void sleepThread(Time::Duration<Rep, Period> duration) {
        std::this_thread::sleep_for(duration);
    }

#if defined(PLATFORM_MACOS) || defined(PLATFORM_LINUX)

    inline void makeXChildren(int childProcesses) {
        pid_t pid = 1;
        for (auto i = 0; i < childProcesses; i++) {
            if (pid > 0) {
                pid = fork();
            }
        }
    }

#elif defined(PLATFORM_WINDOWS)

    void makeXChildren(int childProcesses) {}

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