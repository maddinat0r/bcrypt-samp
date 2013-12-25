/*
Bcrypt plugin for SA-MP
Copyright (c) Lassi R. 2013

Based on Botan crypto library (http://botan.randombit.net/).

Copyright (C) 1999-2013 Jack Lloyd
2001 Peter J Jones
2004-2007 Justin Karneges
2004 Vaclav Ovsik
2005 Matthew Gregan
2005-2006 Matt Johnston
2006 Luca Piccarreta
2007 Yves Jerschow
2007-2008 FlexSecure GmbH
2007-2008 Technische Universitat Darmstadt
2007-2008 Falko Strenzke
2007-2008 Martin Doering
2007 Manuel Hartl
2007 Christoph Ludwig
2007 Patrick Sona
2010 Olivier de Gaalon
2012 Vojtech Kral
2012 Markus Wanner
2013 Joel Low
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
this list of conditions, and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions, and the following disclaimer in the
documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/

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
