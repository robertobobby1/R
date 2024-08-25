#pragma once

#include <stdio.h>

#include "Platform.h"

#ifdef DISABLE_LOGGING
#    define RLog(f_, ...) ()

#else
#    define RLog(f_, ...) printf((f_), ##__VA_ARGS__)

#endif
