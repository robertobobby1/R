#pragma once

#include <stdio.h>

#include "Platform.h"

#ifdef DISABLE_LOGGING
#    define RLog(msg, ...) ()

#else
#    define RLog(msg, ...) printf(msg, ##__VA_ARGS__)

#endif

#define BIND_FN(fn)                                             \
    [this](auto&&... args) -> decltype(auto) {                  \
        return this->fn(std::forward<decltype(args)>(args)...); \
    }
