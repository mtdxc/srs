/*
The MIT License (MIT)

Copyright (c) 2013-2015 SRS(ossrs)

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef SRS_CORE_HPP
#define SRS_CORE_HPP

/*
#include <srs_core.hpp>
*/

// current release version
#define VERSION_MAJOR       2
#define VERSION_MINOR       0
#define VERSION_REVISION    221

// generated by configure, only macros.
#include <srs_auto_headers.hpp>

// provider info.
#define RTMP_SIG_SRS_KEY "SRS"
#define RTMP_SIG_SRS_CODE "ZhouGuowen"
#define RTMP_SIG_SRS_AUTHROS "winlin,wenjie.zhao"
// contact info.
#define RTMP_SIG_SRS_WEB "http://ossrs.net"
#define RTMP_SIG_SRS_EMAIL "winlin@vip.126.com"
// debug info.
#define RTMP_SIG_SRS_ROLE "cluster"
#define RTMP_SIG_SRS_NAME RTMP_SIG_SRS_KEY "(Simple RTMP Server)"
#define RTMP_SIG_SRS_URL_SHORT "github.com/ossrs/srs"
#define RTMP_SIG_SRS_URL "https://" RTMP_SIG_SRS_URL_SHORT
#define RTMP_SIG_SRS_LICENSE "The MIT License (MIT)"
#define RTMP_SIG_SRS_COPYRIGHT "Copyright (c) 2013-2015 SRS(ossrs)"
#define RTMP_SIG_SRS_PRIMARY RTMP_SIG_SRS_KEY "/" VERSION_STABLE_BRANCH
#define RTMP_SIG_SRS_CONTRIBUTORS_URL RTMP_SIG_SRS_URL "/blob/master/AUTHORS.txt"
#define RTMP_SIG_SRS_HANDSHAKE RTMP_SIG_SRS_KEY "(" RTMP_SIG_SRS_VERSION ")"
#define RTMP_SIG_SRS_RELEASE RTMP_SIG_SRS_URL "/tree/" VERSION_STABLE_BRANCH ".0release"
#define RTMP_SIG_SRS_ISSUES(id) RTMP_SIG_SRS_URL "/issues/" #id
#define RTMP_SIG_SRS_VERSION SRS_XSTR(VERSION_MAJOR) "." SRS_XSTR(VERSION_MINOR) "." SRS_XSTR(VERSION_REVISION)
#define RTMP_SIG_SRS_SERVER RTMP_SIG_SRS_KEY "/" RTMP_SIG_SRS_VERSION "(" RTMP_SIG_SRS_CODE ")"

// stable major version
#define VERSION_STABLE 1
#define VERSION_STABLE_BRANCH SRS_XSTR(VERSION_STABLE)".0release"

// internal macros, covert macro values to str,
// see: read https://gcc.gnu.org/onlinedocs/cpp/Stringification.html#Stringification
#define SRS_XSTR(v) SRS_INTERNAL_STR(v)
#define SRS_INTERNAL_STR(v) #v

/**
* the core provides the common defined macros, utilities,
* user must include the srs_core.hpp before any header, or maybe 
* build failed.
*/

// for 32bit os, 2G big file limit for unistd io, 
// ie. read/write/lseek to use 64bits size for huge file.
#ifndef _FILE_OFFSET_BITS
    #define _FILE_OFFSET_BITS 64
#endif

// for int64_t print using PRId64 format.
#ifndef __STDC_FORMAT_MACROS
    #define __STDC_FORMAT_MACROS
#endif

/*************************************************************
**************************************************************
* Windows SRS-LIBRTMP solution
**************************************************************
*************************************************************/
// for srs-librtmp, @see https://github.com/ossrs/srs/issues/213
#ifdef _WIN32
#include <stdint.h>
typedef uint64_t u_int64_t;
typedef uint32_t u_int32_t;
typedef uint16_t u_int16_t;
typedef uint8_t u_int8_t;
typedef int ssize_t;
typedef int socklen_t;
typedef char* sockopt_t;
#define PRId64 "lld"

//#define _CRT_SECURE_NO_WARNINGS
// for mkdir().
#include <direct.h>
// for time.
#include <time.h>
#include <sys/stat.h>
#ifdef __cplusplus
extern "C"{
#endif

typedef int64_t useconds_t;
int usleep(useconds_t usec);
int gettimeofday(struct timeval* tv, struct timezone* tz);

// for open().
typedef int mode_t;
#define S_IRUSR S_IREAD
#define S_IWUSR S_IWRITE
#define S_IXUSR 0
#define S_IRGRP 0
#define S_IWGRP 0
#define S_IXGRP 0
#define S_IROTH 0
#define S_IXOTH 0
#define S_IRWXU 0
// for pid.
typedef int pid_t;
pid_t getpid(void);

// for socket.
ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
int socket_setup();
int socket_cleanup();
#ifdef __cplusplus
}
#endif

/* for file seek.
#include "win32_io.h"
*/
struct iovec
{
  void *iov_base;
  size_t iov_len;
};
#if _MSC_VER < 1900
#define snprintf _snprintf
#endif
#else
#include <sys/uio.h>
#include <inttypes.h>
typedef int* sockopt_t;
#define O_BINARY 0
#endif

#include <assert.h>
#define srs_assert(expression) assert(expression)

#include <stddef.h>
#include <sys/types.h>

// important performance options.
#include <srs_core_performance.hpp>

// free the p and set to NULL.
// p must be a T*.
#define srs_freep(p) \
    if (p) { \
        delete p; \
        p = NULL; \
    } \
    (void)0
// please use the freepa(T[]) to free an array,
// or the behavior is undefined.
#define srs_freepa(pa) \
    if (pa) { \
        delete[] pa; \
        pa = NULL; \
    } \
    (void)0

/**
* disable copy constructor of class,
* to avoid the memory leak or corrupt by copy instance.
*/
#define disable_default_copy(className)\
    private:\
        /** \
        * disable the copy constructor and operator=, donot allow directly copy. \
        */ \
        className(const className&); \
        className& operator= (const className&)

#ifdef _WIN32
#ifdef SRS_EXPORT
#define SRS_API __declspec(dllexport)
#else
#define SRS_API __declspec(dllimport)
#endif
#define __i386__
#endif

/**
 * important check for st(state-threads),
 * only support the following cpus: i386/amd64/x86_64/arm
 * @reamrk to patch ST for arm, read https://github.com/ossrs/state-threads/issues/1
 
#if !defined(__amd64__) && !defined(__x86_64__) && !defined(__i386__) && !defined(__arm__)
    #error "only support i386/amd64/x86_64/arm cpu"
#endif
*/
#endif
