#pragma once
#ifndef INC_MAIN_H
#define INC_MAIN_H


#include "SDK/amx/amx.h"
#include "SDK/plugincommon.h"

typedef void (*logprintf_t)(char* format, ...);

#define AMX_ADD_NATIVE(name) \
{#name, name},


#endif // INC_MAIN_H
