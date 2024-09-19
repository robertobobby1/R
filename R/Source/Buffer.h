#pragma once

#include <iostream>
#include <stdio.h>
#include <string.h>

#include "Platform.h"
#include "Macros.h"

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
                RLog("[Buffer] Can't access out of bounds");
                return false;
            }
            return true;
        }

        // -- Methods
        template <typename T>
        T read(std::size_t const offset) {
            if (offset + sizeof(T) >= maxSize || offset < 0)
                RLog("[Buffer] Can't access out of bounds");

            T value;
            memcpy(&value, ini + offset, sizeof(T));
            return value;
        }

        // expects real values such as uint8_t and not pointers
        template <typename T>
        void write(T const value) {
            this->write(&value, sizeof(T));
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

        void print() {
            RLog("[Buffer] message: %s, size: %i\n", ini, (int)size);
        }
    };
}  // namespace R