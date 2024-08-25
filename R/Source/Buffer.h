#pragma once

#include "Platform.h"

#include <iostream>
#include <stdio.h>
#include <string.h>

namespace R {
    class Buffer {
       public:
        char *ini;
        size_t size = 0;
        size_t maxSize = 0;

        // destructor
        ~Buffer() {
            delete[] ini;
        }

        // Constructor
        explicit Buffer(int n)
            : ini(new char[n]{0}), maxSize(n) {}

        // Copy Constructor
        Buffer(const Buffer &otherBuff) {
            ini = new char[otherBuff.maxSize];
            size = otherBuff.size;
            maxSize = otherBuff.maxSize;

            memcpy(ini, otherBuff.ini, otherBuff.size);
        }

        uint8_t operator[](int position) {
            return ini[position];
        }

        // Copy assignment
        Buffer &operator=(const Buffer &otherBuff) {
            if (this == &otherBuff)
                return *this;

            delete[] ini;

            ini = new char[otherBuff.maxSize];
            size = otherBuff.size;
            maxSize = otherBuff.maxSize;

            memcpy(ini, otherBuff.ini, otherBuff.size);
            return *this;
        }

        // Move Constructor
        Buffer(Buffer &&otherBuff) {
            ini = otherBuff.ini;
            size = otherBuff.size;
            maxSize = otherBuff.maxSize;

            otherBuff.ini = nullptr;
        }

        // Move Assignment
        Buffer &operator=(Buffer &&other_bfr) {
            ini = other_bfr.ini;
            size = other_bfr.size;
            maxSize = other_bfr.maxSize;

            other_bfr.ini = nullptr;

            return *this;
        }

        template <typename T>
        bool inBoundOffset(std::size_t const offset) {
            if (offset + sizeof(T) >= maxSize || offset < 0) {
                printf("[Buffer] Can't access out of bounds");
                return false;
            }
            return true;
        }

        // -- Methods
        template <typename T>
        T read(std::size_t const offset) {
            if (!inBoundOffset<T>(offset))
                return 0;

            return static_cast<T>(ini[offset]);
        }

        template <>
        uint16_t read<uint16_t>(std::size_t const offset) {
            if (!inBoundOffset<uint16_t>(offset))
                return 0;

            auto value = static_cast<uint16_t>(ini[offset]);
            return ntohs(value);
        }

        template <>
        uint32_t read<uint32_t>(std::size_t const offset) {
            if (!inBoundOffset<uint32_t>(offset))
                return 0;

            auto value = static_cast<uint32_t>(ini[offset]);
            return ntohs(value);
        }

        // expects real values such as uint8_t and not pointers
        template <typename T>
        void write(T const value) {
            this->write(&value, sizeof(T));
        }

        template <>
        void write<uint16_t>(uint16_t const value) {
            uint16_t invertedBytes = htons(value);
            this->write(&invertedBytes, sizeof(uint16_t));
        }

        template <>
        void write<uint32_t>(uint32_t const value) {
            uint32_t invertedBytes = htonl(value);
            this->write(&invertedBytes, sizeof(uint32_t));
        }

        // expects pointers to values
        template <typename T>
        void write(T const value, int appendLength) {
            increaseBufferSizeIfNecessary(appendLength);

            memcpy(ini + size, value, appendLength);
            size += appendLength;
        }

        void increaseBufferSizeIfNecessary(int appendLength) {
            if (appendLength + size >= maxSize) {
                // allocate new & bigger memory
                maxSize = (appendLength + size) * 2;
                char *newBuffer = new char[maxSize];
                memcpy(newBuffer, ini, size);

                delete[] ini;
                ini = newBuffer;
            }
        }
    };
}  // namespace R