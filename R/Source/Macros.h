#pragma once

#include <stdio.h>

#include "Platform.h"

#ifdef DISABLE_LOGGING
#    define RLog(msg, ...) ()

#else
#    define RLog(msg, ...) printf(msg, ##__VA_ARGS__)

#endif
