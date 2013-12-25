#if defined(__LINUX__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__linux__)
	#include "Botan/Linux/botan_all.h"
#elif defined(WIN32) || defined(_WIN32) || defined(__WIN32__)
	#include "Botan\Windows\botan_all.h"
#else
	#error "You must define one of WIN32, LINUX or FREEBSD"
#endif

Botan::LibraryInitializer init;

#include <thread>
#include <vector>
#include <mutex>

#include "SDK/amx/amx.h"
#include "SDK/plugincommon.h"

#include "bcrypt_queue.h"

typedef void (*logprintf_t)(char* format, ...);
