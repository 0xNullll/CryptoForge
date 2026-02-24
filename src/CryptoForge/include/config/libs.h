/*
 * CryptoForge - libs.h / Standard Library Includes
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef LIBS_H
#define LIBS_H

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#if defined(_WIN32) && defined(_MSC_VER)
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <wincrypt.h>
#endif
#else
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#if defined(__linux__)
#include <sys/random.h>
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <math.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#endif // LIBS_H