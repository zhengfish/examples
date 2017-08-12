/**
 * File: uv_xport.cpp
 *
 * Build @ Win32
 * -------------
 *
 * cl -TP -EHsc -MTd -DLIBUV_STABLE -I..\libuv-stable\include uv-xport.cpp -Fexport.exe -link /LTCG ws2_32.lib advapi32.lib psapi.lib iphlpapi.lib ..\libuv-stable\Release\lib\libuv.lib /nodefaultlib:libcmt
 *
 */

/**
 *                                         : 80  --- HTTP
 *              2468                       : 7   --- ECHO
 *                :                        :
 * [Client] +-----+ [ Proxy ] +------------+ [Server]
 *                |           |
 *              Local       Remote
 *
 */

/**
 * iperf
 * -----
 * # iperf -s -p 7
 * # iperf -c 192.168.53.1 -p 2468 -M 536 -w 100000 -n 10
 * # iperf -c 192.168.53.2 -p 2468 -M 536 -w 100000 -t 30
 * $ iperf -c 192.168.11.1 -p 2468 -M 536 -w 100000 -t 3
 *
 * netperf
 * -------
 * ftp://ftp.netperf.org/netperf/netperf-2.6.0.tar.bz2
 *
 * # netserver -4 -p 7
 * # netperf -4 -H 192.168.53.1 -p 2468 -l 2
 *
 */

/**
 *
 * valgrind --leak-check=full --show-reachable=yes ./xport

==2575== HEAP SUMMARY:
==2575==     in use at exit: 345 bytes in 3 blocks
==2575==   total heap usage: 2,151 allocs, 2,148 frees, 70,410,609 bytes allocated
==2575==
==2575== 25 bytes in 1 blocks are possibly lost in loss record 1 of 3
==2575==    at 0x402569A: operator new(unsigned int) (vg_replace_malloc.c:255)
==2575==    by 0x4115D05: std::string::_Rep::_S_create(unsigned int, unsigned int, std::allocator<char> const&) (in /usr/lib/libstdc++.so.6.0.13)
==2575==    by 0x4116B10: ??? (in /usr/lib/libstdc++.so.6.0.13)
==2575==    by 0x4116CF5: std::basic_string<char, std::char_traits<char>, std::allocator<char> >::basic_string(char const*, std::allocator<char> const&) (in /usr/lib/libstdc++.so.6.0.13)
==2575==    by 0x804AE21: main (uv-xport.cpp:1068)
==2575==
==2575== 64 bytes in 1 blocks are still reachable in loss record 2 of 3
==2575==    at 0x4025016: realloc (vg_replace_malloc.c:525)
==2575==    by 0x4031C01: maybe_resize (core.c:605)
==2575==    by 0x4031E27: uv__io_start (core.c:642)
==2575==    by 0x4030DB1: uv__async_start (async.c:218)
==2575==    by 0x4030838: uv_async_init (async.c:42)
==2575==    by 0x4035EB5: uv__loop_init (loop.c:75)
==2575==    by 0x4031422: uv_default_loop (core.c:236)
==2575==    by 0x804AEAA: main (uv-xport.cpp:1081)
==2575==
==2575== 256 bytes in 1 blocks are definitely lost in loss record 3 of 3
==2575==    at 0x402569A: operator new(unsigned int) (vg_replace_malloc.c:255)
==2575==    by 0x804AA6A: local_connection_cb(uv_stream_s*, int) (uv-xport.cpp:1016)
==2575==    by 0x403AA06: uv__server_io (stream.c:533)
==2575==    by 0x404439D: uv__io_poll (linux-core.c:211)
==2575==    by 0x403165B: uv_run (core.c:317)
==2575==    by 0x804B0CE: main (uv-xport.cpp:1120)
==2575==
==2575== LEAK SUMMARY:
==2575==    definitely lost: 256 bytes in 1 blocks
==2575==    indirectly lost: 0 bytes in 0 blocks
==2575==      possibly lost: 25 bytes in 1 blocks
==2575==    still reachable: 64 bytes in 1 blocks
==2575==         suppressed: 0 bytes in 0 blocks
==2575==
==2575== For counts of detected and suppressed errors, rerun with: -v
==2575== ERROR SUMMARY: 2 errors from 2 contexts (suppressed: 25 from 6)
 *
 */

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <assert.h>
#if !defined(_WIN32)
#include <unistd.h>
#endif

#include <string>

#include "uv.h"

//------------------------------------------------------------------------------
#if defined(_DEBUG)
#define FUNCTION_CALL                              \
    do                                             \
    {                                              \
        fprintf(stdout, "--> %s\n", __FUNCTION__); \
    } while (0);
#else
#define FUNCTION_CALL
#endif

/**
 * Have our own assert, so we are sure it does not get optimized away in a release build.
 */
#define ASSERT(expr)                                           \
    do                                                         \
    {                                                          \
        if (!(expr))                                           \
        {                                                      \
            fprintf(stderr,                                    \
                    "Assertion failed in %s on line %d: %s\n", \
                    __FILE__,                                  \
                    __LINE__,                                  \
                    #expr);                                    \
            abort();                                           \
        }                                                      \
    } while (0)

/**
 * Die with fatal error.
 */
#define FATAL(msg)                               \
    do                                           \
    {                                            \
        fprintf(stderr,                          \
                "[%s: %d], Fatal Error in %s\n", \
                __FILE__,                        \
                __LINE__,                        \
                msg);                            \
        fflush(stderr);                          \
        abort();                                 \
    } while (0)

#define SHOW_UV_ERROR(loop)                            \
    do                                                 \
    {                                                  \
        fprintf(stderr, "[%s: %d], libuv Error: %s\n", \
                __FILE__,                              \
                __LINE__,                              \
                uv_strerror(uv_last_error(loop)));     \
    } while (0)

#define SHOW_UV_ERROR_AND_EXIT(loop)              \
    do                                            \
    {                                             \
        SHOW_UV_ERROR(loop);                      \
        fprintf(stderr, "Fatal ERR, exit ...\n"); \
        exit(1);                                  \
    } while (0)

// This is the time format for log, see strftime(3) for more information
#define TIME_FORMAT "%F %T"

#if defined(_WIN32)
#define LOGI(format, ...)                                                 \
    do                                                                    \
    {                                                                     \
        time_t now;                                                       \
        time(&now);                                                       \
        struct tm sTm;                                                    \
        localtime_s(&sTm, &now);                                          \
        char timestr[24] = {0};                                           \
        strftime(timestr, sizeof(timestr), "%Y-%m-%d ", &sTm);            \
        fprintf(stderr, "%s INFO: " format "\n", timestr, ##__VA_ARGS__); \
    } while (0)

#define LOGE(format, ...)                                                                                                  \
    do                                                                                                                     \
    {                                                                                                                      \
        time_t now;                                                                                                        \
        time(&now);                                                                                                        \
        struct tm sTm;                                                                                                     \
        localtime_s(&sTm, &now);                                                                                           \
        char timestr[24] = {0};                                                                                            \
        strftime(timestr, sizeof(timestr), "%Y-%m-%d ", &sTm);                                                             \
        fprintf(stderr, "%s ERROR: " format " on File: %s Line: %s\n", timestr, ##__VA_ARGS__, __FILE__, TOSTR(__LINE__)); \
    } while (0)
#else

#define LOGI(format, ...)                                                               \
    do                                                                                  \
    {                                                                                   \
        time_t now = time(NULL);                                                        \
        char timestr[20];                                                               \
        strftime(timestr, 20, TIME_FORMAT, localtime(&now));                            \
        fprintf(stderr, "\e[01;32m%s INFO: \e[0m" format "\n", timestr, ##__VA_ARGS__); \
    } while (0)

#define LOGE(format, ...)                                                                                                                \
    do                                                                                                                                   \
    {                                                                                                                                    \
        time_t now = time(NULL);                                                                                                         \
        char timestr[20];                                                                                                                \
        strftime(timestr, 20, TIME_FORMAT, localtime(&now));                                                                             \
        fprintf(stderr, "\e[01;35m%s ERROR: \e[0m" format " on File: %s Line: %s\n", timestr, ##__VA_ARGS__, __FILE__, TOSTR(__LINE__)); \
    } while (0)
#endif /* defined ( _WIN32 ) */

#define LOGCONN(stream, message)                                                     \
    do                                                                               \
    {                                                                                \
        struct sockaddr_storage remote_addr;                                         \
        memset(&remote_addr, 0, sizeof(remote_addr));                                \
        int namelen = sizeof(remote_addr);                                           \
        if (uv_tcp_getpeername((stream), (struct sockaddr *)&remote_addr, &namelen)) \
            break;                                                                   \
        char *ip_str = sockaddr_to_str(&remote_addr);                                \
        if (!ip_str)                                                                 \
            FATAL("unknown address type");                                           \
        LOGI(message, ip_str);                                                       \
        free(ip_str);                                                                \
    } while (0)

// Convert IPv4 or IPv6 sockaddr to string, DO NOT forget to free the buffer after use!
char *sockaddr_to_str(struct sockaddr_storage *addr)
{
    char *result;
    if (addr->ss_family == AF_INET)
    { // IPv4
        result = (char *)malloc(INET_ADDRSTRLEN);
        if (!result)
            FATAL("malloc() failed!");
        int n = uv_ip4_name((struct sockaddr_in *)addr, result, INET_ADDRSTRLEN);
        if (n)
        {
            free(result);
            result = NULL;
        }
    }
    else if (addr->ss_family == AF_INET6)
    { // IPv4
        result = (char *)malloc(INET6_ADDRSTRLEN);
        if (!result)
            FATAL("malloc() failed!");
        int n = uv_ip6_name((struct sockaddr_in6 *)addr, result, INET6_ADDRSTRLEN);
        if (n)
        {
            free(result);
            result = NULL;
        }
    }
    else
    {
        result = NULL;
    }
    return result;
}
//------------------------------------------------------------------------------
//typedef unsigned char byte_t;
const int numBytesPerLine = 16;
const int numSpaces = 5;
const int numBytesForHex = numBytesPerLine * 3;
const int numBytesInString = numBytesForHex + numSpaces + numBytesPerLine;

void hexdump(const char *ptr, const int buf_size)
{
    char strbuffer[numBytesInString + 1];
    char *curStr = NULL;
    int numBytes = 0;
    int idx = 0;
    int size = buf_size;

    strbuffer[numBytesInString] = '\0';
    while (size)
    {
        memset(strbuffer, ' ', numBytesInString);
        numBytes = (size > numBytesPerLine) ? numBytesPerLine : size;

        curStr = strbuffer;
        for (idx = 0; idx < numBytes; idx++)
        {
            char c1, c2;

            c2 = (*(ptr + idx) & 0xF) + '0';
            c1 = ((*(ptr + idx) & 0xF0) >> 4) + '0';
            if (c1 > '9')
                c1 += ('A' - '9' - 1);
            if (c2 > '9')
                c2 += ('A' - '9' - 1);
            *(curStr++) = c1;
            *(curStr++) = c2;
            curStr++;
        }
        curStr = strbuffer + numBytesForHex + numSpaces;
        for (idx = 0; idx < numBytes; idx++)
        {
            if (isprint(*(ptr + idx)))
            {
                *(curStr++) = *(ptr + idx);
            }
            else
            {
                *(curStr++) = '.';
            }
        }
        puts(strbuffer);

        size -= numBytes;
        ptr += numBytes;
    }
}

//------------------------------------------------------------------------------

// This is the number of max allowed pending write to client request, if you are running out of memory (which is very unlikely), you may want to decrease this a little
// The max possible memory usage of this program is BUFFER_LIMIT * MAX_PENDING_PER_CONN * Concurrent connection number, but this is kind of situation almost impossible to happen
// In most case, increase this value will better your performance
#if 1
const unsigned long MAX_PENDING_PER_CONN = 10;
#else
const unsigned long MAX_PENDING_PER_CONN = 1024;
#endif

typedef struct _st_server_info_t
{
    struct sockaddr_in &sa_remote_; // remote addr
    ///unsigned short      remote_ip_;       // remote ip
    ///unsigned short      remote_port_;     // remote port
} server_info_t;

typedef struct _st_session_ctx_t
{
    unsigned int id_; // id for this session

    uv_buf_t buf_init_; // it's initiate, it's transparent, so NO handshake needed.

    uv_tcp_t local_;                // handle
    unsigned long local_connected_; // flag

    uv_tcp_t remote_; // handle
    struct sockaddr_in *sa_remote_;
    unsigned long buf_count_;
} session_ctx_t;

//------------------------------------------------------------------------------
// Forward
static uv_buf_t local_alloc_cb(uv_handle_t *handle, size_t suggested_size);
static void local_read_cb(uv_stream_t *stream_local, ssize_t nread, uv_buf_t buf);
static void local_write_cb(uv_write_t *req, int status);
static void local_close_cb(uv_handle_t *handle);
static void local_remote_shutdown_cb(uv_shutdown_t *req, int status);

//------------------------------------------------------------------------------
static void
session_free_cb(uv_handle_t *handle)
{
    FUNCTION_CALL

    session_ctx_t *tcp_sess = (session_ctx_t *)handle->data;

    tcp_sess->local_connected_ = 0;

#if defined(_DEBUG)
    fprintf(stdout, "free session.id=%d\n", tcp_sess->id_);
#endif

    if (tcp_sess)
    {
        delete (tcp_sess); // free session
        tcp_sess = NULL;
    }

    return;
}

//------------------------------------------------------------------------------
#ifndef LIBUV_STABLE
static void
remote_alloc_cb(uv_handle_t *stream_remote,
                size_t suggested_size,
                uv_buf_t *buf)
{
    //FUNCTION_CALL

    buf->base = (char *)malloc(suggested_size);
    buf->len = suggested_size;
}
#else
static uv_buf_t
remote_alloc_cb(uv_handle_t *handle, size_t suggested_size)
{
//FUNCTION_CALL

#ifdef BUFFER_LIMIT
    void *buf = malloc(BUFFER_LIMIT);
#else
    void *buf = malloc(suggested_size);
#endif /* BUFFER_LIMIT */
    if (!buf)
    {
        FATAL("malloc() failed!");
    }
#ifdef BUFFER_LIMIT
    return uv_buf_init(buf, BUFFER_LIMIT);
#else
    return uv_buf_init((char *)buf, suggested_size);
#endif /* BUFFER_LIMIT */
}
#endif

static void
remote_close_cb(uv_handle_t *handle)
{
    FUNCTION_CALL

    session_ctx_t *tcp_sess = (session_ctx_t *)handle->data;

#if defined(_DEBUG)
    //fprintf ( stdout, "handle closed, type: %d\n", handle->type );
    fprintf(stdout, "2 session.id=%d, local_connected_ = %lu\n", tcp_sess->id_, tcp_sess->local_connected_);
#endif

    // stop local handle
    uv_read_stop((uv_stream_t *)(void *)&tcp_sess->local_);

    uv_shutdown_t *req = (uv_shutdown_t *)malloc(sizeof *req);
    req->data = handle->data;
    int n = uv_shutdown(req, (uv_stream_t *)(void *)&tcp_sess->local_, local_remote_shutdown_cb);
    if (n)
    {
        fprintf(stderr, "shutdown local side write stream failed!\n");
        uv_close((uv_handle_t *)(void *)&tcp_sess->local_, session_free_cb);
        free(req);
    }

#if 0
    ///TODO, why not free it?
    free ( handle );
#endif
}

static void
remote_write_cb(uv_write_t *req, int status)
{
    FUNCTION_CALL

    ///session_ctx_t * tcp_sess = ( session_ctx_t * ) req->handle->data;

    if (status)
    {
#if defined(_DEBUG)
        fprintf(stdout, "write failed\n");
#endif
        SHOW_UV_ERROR(req->handle->loop);
        if (uv_last_error(req->handle->loop).code != UV_ECANCELED)
        {
            ///HANDLE_CLOSE ( ( uv_handle_t * ) req->handle, local_close_cb );
            uv_close((uv_handle_t *)req->handle, NULL);
        }
        free(req->data); // Free buffer
        free(req);
        return;
    }
    else
    {
#if 0 ///defined( _DEBUG )
        fprintf ( stdout, "write ok\n" );
#endif
    }

    free(req->data); // Free buffer
    free(req);

#if 0
    /**
    * @refer
    * Here it use c language tricky to get the buffer * ptr after the uv_write_t * ptr.
    */
    /* Free the read/write buffer and the request */
    write_req_t * wr = ( write_req_t * ) req;
    free ( wr->buf.base );
    free ( wr );

    //fprintf ( stderr, "uv_write error: %s\n", uv_strerror ( status ) );
    SHOW_UV_ERROR ( req->handle->loop );

    if ( status == UV_ECANCELED )
        return;

    ASSERT ( status == UV_EPIPE );

    uv_close ( ( uv_handle_t * ) req->handle, remote_close_cb );
#endif
}

static void
local_remote_shutdown_cb(uv_shutdown_t *req, int status)
{
    FUNCTION_CALL

    if (status)
    {
#if defined(_DEBUG)
        fprintf(stderr, "shutdown failed, status = %d\n", status);
#endif
    }

#if 0
    /// re-stored the tcp_sess as a void* data filed in order to avoid global varible
    session_ctx_t * tcp_sess = ( session_ctx_t * ) req->data;

    if ( ( uv_tcp_t * ) req->handle == &tcp_sess->local_ ) {
        uv_close ( ( uv_handle_t * ) ( void * ) & tcp_sess->remote_, session_free_cb );
    } else { //
        uv_close ( ( uv_handle_t * ) ( void * ) & tcp_sess->local_, session_free_cb );
    }
#else
    uv_close((uv_handle_t *)req->handle, session_free_cb);
#endif

    ///free ( req->data );    /// free session, moved @ session_free_cb()
    free(req);

    return;
}

/// TODO
/// Why both of them are ok?
#ifndef LIBUV_STABLE
static void
remote_read_cb(uv_stream_t *stream_remote, ssize_t nread, const uv_buf_t *buf)
#else
static void
remote_read_cb(uv_stream_t *stream_remote, ssize_t nread, uv_buf_t buf)
#endif
{
    FUNCTION_CALL

    /// re-stored the tcp_sess as a void* data filed in order to avoid global varible
    session_ctx_t *tcp_sess = (session_ctx_t *)stream_remote->data;

    if (nread == 0)
    {
/* Everything OK, but nothing read. */
#if defined(_DEBUG)
        fprintf(stdout, "Everything OK, but nothing read.\n");
#endif
        free(buf.base);
        return;
    }
    else if (nread < 0)
    { // EOF
      ///TODO
      /* Error or EOF */
#if defined(_DEBUG)
        fprintf(stdout, "Error or EOF @ %s.\n", __FUNCTION__);
#endif
        //ASSERT ( nread == UV_EOF );
        if (buf.base && (buf.len > 0))
        {
            free(buf.base);
        }

        LOGCONN(&tcp_sess->remote_, "remote peer: %s EOF, closing;");

        // Then close the connection
        if (!(uv_is_closing((uv_handle_t *)(void *)&tcp_sess->remote_) || uv_is_closing((uv_handle_t *)(void *)&tcp_sess->local_)))
        {
            uv_close((uv_handle_t *)stream_remote, remote_close_cb);
        }

        return;
    }

    if (!uv_is_closing((uv_handle_t *)(void *)&tcp_sess->local_))
    {
///TODO after here is commented out, it will crash on Win32
#if defined(_DEBUG)
        fprintf(stdout, "uv_write to local: id_=%d, local_connected_ = %lu\n", tcp_sess->id_, tcp_sess->local_connected_);
#endif
        tcp_sess->local_connected_++;

        uv_write_t *req_2 = (uv_write_t *)malloc(sizeof(uv_write_t));
        req_2->data = buf.base;
        buf.len = nread;

        if (uv_write(req_2, (uv_stream_t *)(void *)&tcp_sess->local_, &buf, 1, local_write_cb))
        {
            SHOW_UV_ERROR(stream_remote->loop);
            FATAL("uv_write failed, WHY?");
        }
    }
    else
    {
        fprintf(stdout, "local connect broken, id_=%d, local_connected_ = %lu\n", tcp_sess->id_, tcp_sess->local_connected_);
    }

    if (tcp_sess->buf_count_ >= MAX_PENDING_PER_CONN)
    { // buf_count_ used as pending write request counter
#if defined(_DEBUG)
        fprintf(stdout, "tcp_sess->buf_count_ = %lu, pending ...\n", tcp_sess->buf_count_);
#endif
        uv_read_stop(stream_remote);
    }
    tcp_sess->buf_count_++;

    return;
}

/**
 * TODO
 * How to trigger this function?
 */
#if 0
static void
remote_connect_cb ( uv_connect_t * stream_remote, int status )
#else
static void
remote_connect_cb(uv_connect_t *req, int status)
#endif
{
    FUNCTION_CALL

    int n = 0;
    /// re-stored the tcp_sess as a void* data filed in order to avoid global varible
    session_ctx_t *tcp_sess = (session_ctx_t *)req->data;

    if (!status)
    {
#if defined(_DEBUG)
        fprintf(stdout, "remote connected\n");
#endif
    }
    else
    {
        fprintf(stdout, "remote connection failed, run 'xinetd -d' to enable: echo service\n");

        if (uv_last_error(req->handle->loop).code != UV_ECANCELED)
        {
            //SHOW_UV_ERROR ( ctx->client.loop );
            SHOW_UV_ERROR(req->handle->loop);
            //uv_close ( ( uv_handle_t* ) ( void * ) &ctx->remote, remote_established_close_cb );
            free(req->data);
            free(req);
        }
        return;
    }

#if defined(_DEBUG)
    fprintf(stdout, "session.id = %u\n", tcp_sess->id_);
//hexdump ( tcp_sess->buf_init_.base, tcp_sess->buf_init_.len );
#endif

#if defined(_DEBUG)
    /// zheng @ 2013-10-07 23:05:01, Mon/40
    /// to get the detail peer_ address( ip and port )
    struct sockaddr peer_sa;
    int namelen = sizeof peer_sa;
    memset(&peer_sa, -1, namelen);
    n = uv_tcp_getpeername((uv_tcp_t *)&tcp_sess->remote_, &peer_sa, &namelen);
    ASSERT(n == 0);

    struct sockaddr_in peer_sa_in;
    peer_sa_in = *(struct sockaddr_in *)&peer_sa;
    unsigned int peer_ip = ntohl(peer_sa_in.sin_addr.s_addr);
    unsigned short peer_port = ntohs(peer_sa_in.sin_port);

    fprintf(stdout, "connected remote : %08X:%u\n", peer_ip, peer_port);
#endif

    /// wait stream_local's data
    tcp_sess->local_.data = req->data;
    n = uv_read_start((uv_stream_t *)(void *)&tcp_sess->local_, local_alloc_cb, local_read_cb);
    if (n)
    {
        SHOW_UV_ERROR(req->handle->loop);
        //HANDLE_CLOSE ( ( uv_handle_t * ) ( void * ) &ctx->local, local_established_close_cb );
        uv_close((uv_handle_t *)&tcp_sess->local_, NULL);
        free(req->data); // Free buffer
        free(req);
        return;
    }

    /// wait stream_remote's data
    tcp_sess->remote_.data = req->data;
    n = uv_read_start((uv_stream_t *)(void *)&tcp_sess->remote_, remote_alloc_cb, remote_read_cb);
    if (n)
    {
        SHOW_UV_ERROR(req->handle->loop);
        //HANDLE_CLOSE ( ( uv_handle_t * ) ( void * ) &ctx->remote, remote_established_close_cb );
        uv_close((uv_handle_t *)&tcp_sess->remote_, NULL);
        free(req->data); // Free buffer
        free(req);
        return;
    }

#if 1
    uv_write_t *req_2 = (uv_write_t *)malloc(sizeof(uv_write_t));
    req_2->data = tcp_sess->buf_init_.base;

    if (uv_write(req_2, (uv_stream_t *)(void *)&tcp_sess->remote_, &tcp_sess->buf_init_, 1, remote_write_cb))
    {
        SHOW_UV_ERROR(req->handle->loop);
        FATAL("uv_write failed");
    }
#endif

    ///free ( req->data );
    free(req);

    return;
}

//------------------------------------------------------------------------------
static void
local_write_cb(uv_write_t *req, int status)
{
    FUNCTION_CALL

    session_ctx_t *tcp_sess = (session_ctx_t *)req->handle->data;

    if (status)
    {
#if defined(_DEBUG)
        fprintf(stdout, "write failed, error code: %d\n", uv_last_error(req->handle->loop).code);
#endif
        SHOW_UV_ERROR(req->handle->loop);
        if (uv_last_error(req->handle->loop).code != UV_ECANCELED)
        {
            uv_close((uv_handle_t *)req->handle, session_free_cb);
            ///uv_close ( ( uv_handle_t * ) req->handle, local_close_cb );
        }

        free(req->data); // Free buffer
        free(req);
        return;
    }
    else
    {
#if 0 ///defined( _DEBUG )
        fprintf ( stdout, "write ok\n" );
#endif
    }

    if (tcp_sess->buf_count_ == (MAX_PENDING_PER_CONN / 2) && !uv_is_closing((uv_handle_t *)(void *)&tcp_sess->remote_))
    {
#if 1 ///defined(_DEBUG)
        fprintf(stdout, "tcp_sess->buf_count_ <= %lu, re-starting uv_read_start...\n", (MAX_PENDING_PER_CONN / 2));
#endif
        int n = uv_read_start((uv_stream_t *)(void *)&tcp_sess->remote_, remote_alloc_cb, remote_read_cb);
        if (n)
        {
            SHOW_UV_ERROR(req->handle->loop);
            //HANDLE_CLOSE ( ( uv_handle_t * ) ( void * ) &tcp_sess->remote_, remote_established_close_cb );
            uv_close((uv_handle_t *)&tcp_sess->remote_, remote_close_cb);
            free(req->data); // Free buffer
            free(req);
            return;
        }
    }
    tcp_sess->buf_count_--;

    free(req->data); // Free buffer
    free(req);
}

static void
local_close_cb(uv_handle_t *handle)
{
    FUNCTION_CALL

    session_ctx_t *tcp_sess = (session_ctx_t *)handle->data;

#if defined(_DEBUG)
    //fprintf ( stdout, "handle closed, type: %d\n", handle->type );
    fprintf(stdout, "1 session.id=%d, local_connected_ = %lu\n", tcp_sess->id_, tcp_sess->local_connected_);
#endif

    if (tcp_sess->local_connected_ > 1)
    {
        // stop remote handle
        uv_read_stop((uv_stream_t *)(void *)&tcp_sess->remote_);

        uv_shutdown_t *req_2 = (uv_shutdown_t *)malloc(sizeof *req_2);
        req_2->data = handle->data;
        int n = uv_shutdown(req_2, (uv_stream_t *)(void *)&tcp_sess->remote_, local_remote_shutdown_cb);
        if (n)
        {
            fprintf(stderr, "shutdown remote side write stream failed!\n");
            uv_close((uv_handle_t *)(void *)&tcp_sess->remote_, session_free_cb);
            free(req_2);
        }
    }
    else
    {
        fprintf(stderr, "local stream quit and shutdown without any payload, why?!\n");
#if 0
        //uv_close ( ( uv_handle_t * ) ( void * ) & tcp_sess->local_, session_free_cb );
#endif
    }

#if 0
    ///TODO, why not free it?
    free ( handle );
#endif
}

static uv_buf_t
local_alloc_cb(uv_handle_t *handle, size_t suggested_size)
{
//FUNCTION_CALL

#ifdef BUFFER_LIMIT
    void *buf = malloc(BUFFER_LIMIT);
#else
    void *buf = malloc(suggested_size);
#endif /* BUFFER_LIMIT */
    if (!buf)
    {
        FATAL("malloc() failed!");
    }
#ifdef BUFFER_LIMIT
    return uv_buf_init(buf, BUFFER_LIMIT);
#else
    return uv_buf_init((char *)buf, suggested_size);
#endif /* BUFFER_LIMIT */
}

static void
local_read_cb(uv_stream_t *stream_local, ssize_t nread, uv_buf_t buf)
{
    FUNCTION_CALL

    /// re-stored the tcp_sess as a void* data filed in order to avoid global varible
    session_ctx_t *tcp_sess = (session_ctx_t *)stream_local->data;

    if (nread == 0)
    {
/* Everything OK, but nothing read. */
#if defined(_DEBUG)
        fprintf(stdout, "Everything OK, but nothing read.\n");
#endif
        free(buf.base);
        return;
    }
    else if (nread < 0)
    { // EOF
      ///TODO
      /* Error or EOF */
#if defined(_DEBUG)
        fprintf(stdout, "Error or EOF @ %s.\n", __FUNCTION__);
#endif
        //ASSERT ( nread == UV_EOF );
        if (buf.base && (buf.len > 0))
        {
            free(buf.base);
        }

        LOGCONN(&tcp_sess->local_, "2 local peer: %s EOF, closing;");

        // Then close the connection
        if (!(uv_is_closing((uv_handle_t *)(void *)&tcp_sess->remote_) || uv_is_closing((uv_handle_t *)(void *)&tcp_sess->local_)))
        {
            uv_close((uv_handle_t *)stream_local, local_close_cb);
        }

        return;
    }

    if ((tcp_sess->local_connected_ > 1) && !uv_is_closing((uv_handle_t *)(void *)&tcp_sess->remote_))
    {
        uv_write_t *req_2 = (uv_write_t *)malloc(sizeof(uv_write_t));
        req_2->data = buf.base;
        buf.len = nread;
        if (uv_write(req_2, (uv_stream_t *)(void *)&tcp_sess->remote_, &buf, 1, remote_write_cb))
        {
            SHOW_UV_ERROR_AND_EXIT(stream_local->loop);
            FATAL("uv_write failed");
        }
    }
    else
    {
#if defined(_WIN32)
        Sleep(1000);
#else
///sleep ( 1 );
#endif
        fprintf(stdout, "3 session.id=%d, local_connected_ = %lu\n", tcp_sess->id_, tcp_sess->local_connected_);
        fprintf(stdout, "TODO?\n");
        ///uv_close ( ( uv_handle_t * ) stream_local, NULL );
    }

    return;
}

// once called only while initiating session
static void
local_init_read_cb(uv_stream_t *stream_local, ssize_t nread, uv_buf_t buf)
{
    FUNCTION_CALL

    /// re-stored the tcp_sess as a void* data filed in order to avoid global varible
    session_ctx_t *tcp_sess = (session_ctx_t *)stream_local->data;

    if (nread == 0)
    {
/* Everything OK, but nothing read. */
#if defined(_DEBUG)
        fprintf(stdout, "Everything OK, but nothing read.\n");
#endif
        free(buf.base);
        return;
    }
    else if (nread < 0)
    { // EOF
#if defined(_DEBUG)
        fprintf(stdout, "@ %s, Error or EOF. nread=%d\n", __FUNCTION__, nread);
#endif
        //ASSERT ( nread == UV_EOF );
        LOGCONN(&tcp_sess->local_, "1 local peer: %s EOF, closing;");

        if (buf.base && (buf.len > 0))
        {
            free(buf.base);
        }

        // Then close the connection
        if (!(uv_is_closing((uv_handle_t *)(void *)&tcp_sess->remote_) || uv_is_closing((uv_handle_t *)(void *)&tcp_sess->local_)))
        {
            uv_close((uv_handle_t *)stream_local, local_close_cb);
        }

        return;
    }

    if (tcp_sess->local_connected_ != 1)
    {
        fprintf(stdout, "tcp_sess->local_connected_ = %lu, why? and quit?\n", tcp_sess->local_connected_);
        return;
    }
    else
    {
        tcp_sess->local_connected_ = 2;
    }

#if defined(_DEBUG)
    fprintf(stdout, "session.id = %u\n", tcp_sess->id_);
    //hexdump ( tcp_sess->buf_init_.base, nread );

    fprintf(stdout, "\ninitiate one connect to remote_ ...\n");
#endif

    // write buffer back
    int n = uv_tcp_init(stream_local->loop, &tcp_sess->remote_);
    if (n)
        SHOW_UV_ERROR_AND_EXIT(stream_local->loop);

    tcp_sess->buf_init_.base = buf.base;
    tcp_sess->buf_init_.len = nread;

    uv_connect_t *req_1 = (uv_connect_t *)malloc(sizeof(uv_connect_t));

    req_1->data = tcp_sess;
    n = uv_tcp_connect(req_1,
                       &tcp_sess->remote_,
                       *tcp_sess->sa_remote_,
                       remote_connect_cb);
    if (n)
    {
        SHOW_UV_ERROR(stream_local->loop);

        //static uv_shutdown_t shutdown_req;
        //n = uv_shutdown ( & shutdown_req, ( uv_stream_t * ) & remote_, local_remote_shutdown_cb );
        //assert ( n == 0 );
        free(req_1);
        return;
    }

    ///NOTE need to stop it first?
    uv_read_stop(stream_local);

    return;
}

static void
local_connection_cb(uv_stream_t *server, int status)
{
    FUNCTION_CALL

    server_info_t *server_info = (server_info_t *)server->data;

    int n = 0;

    if (status != 0)
    {
        SHOW_UV_ERROR(server->loop);
    }
    ASSERT(status == 0);

    /* associate server with stream_local */
    static unsigned int id_count = 1000;
    id_count++;

    session_ctx_t *tcp_sess = new (session_ctx_t);
    tcp_sess->id_ = id_count;
    tcp_sess->local_connected_ = 1;
    tcp_sess->buf_count_ = 0;

    n = uv_tcp_init(server->loop, &tcp_sess->local_);
    ASSERT(n == 0);

    tcp_sess->sa_remote_ = &server_info->sa_remote_;

    n = uv_accept(server, (uv_stream_t *)&tcp_sess->local_);
    ASSERT(n == 0);

    n = uv_tcp_nodelay(&tcp_sess->local_, 1);
    if (n)
        SHOW_UV_ERROR_AND_EXIT(server->loop);

    /// stored the tcp_client as a void* data filed in order to avoid global varible
    tcp_sess->local_.data = tcp_sess;

#if defined(_DEBUG)
    /// zheng @ 2013-10-07 23:05:01, Mon/40
    /// to get the detail peer_ address( ip and port )
    struct sockaddr peer_sa;
    int namelen = sizeof peer_sa;
    memset(&peer_sa, -1, namelen);
    n = uv_tcp_getpeername(&tcp_sess->local_, &peer_sa, &namelen);
    ASSERT(n == 0);

    struct sockaddr_in peer_sa_in;
    peer_sa_in = *(struct sockaddr_in *)&peer_sa;
    unsigned int peer_ip = ntohl(peer_sa_in.sin_addr.s_addr);
    unsigned short peer_port = ntohs(peer_sa_in.sin_port);

    fprintf(stdout, "connected stream_peer_ address is: %08X:%u\n", peer_ip, peer_port);
#endif

    n = uv_read_start((uv_stream_t *)&tcp_sess->local_, local_alloc_cb, local_init_read_cb);
    ASSERT(n == 0);
}

#ifndef NDEBUG

void signal_cb(uv_signal_t *handle, int signum)
{
    if (uv_signal_stop(handle))
        SHOW_UV_ERROR_AND_EXIT(handle->loop);

    ///free ( handle );

    LOGI("Ctrl+C Pressed\n");

#if 1
    uv_loop_delete(uv_default_loop()); // Make Valgrind Happy
#else
    uv_stop(handle->loop);        // Make Valgrind Happy
    uv_loop_delete(handle->loop); // Make Valgrind Happy
#endif

#if 0
    exit ( 0 );
#else
    return;
#endif
}

void setup_signal_handler(uv_loop_t *loop)
{
#if !defined(_WIN32)
    signal(SIGPIPE, SIG_IGN);
#endif

    uv_signal_t *hup = (uv_signal_t *)malloc(sizeof(uv_signal_t));
    if (!hup)
        FATAL("malloc() failed!");

    int n = uv_signal_init(loop, hup);
    if (n)
        SHOW_UV_ERROR_AND_EXIT(loop);

    n = uv_signal_start(hup, signal_cb, SIGINT);
    if (n)
        SHOW_UV_ERROR_AND_EXIT(loop);
}
#endif /* !NDEBUG */

int main(int argc, char *argv[])
{
    fprintf(stdout, "uv_xport-v0.0.1, built @ %s, %s; Based libuv-v0x%08X\n\n", __DATE__, __TIME__, uv_version());

    ///FUNCTION_CALL

    // Get inputted command line
    std::string remote_addr = "192.168.53.2";
    unsigned short remote_port = 80;
    if (argc == 3)
    {
        remote_addr = argv[1];
#if defined(_WIN32)
        remote_port = std::stoi(argv[2]);
#else
        remote_port = atoi(argv[2]);
#endif
    }

    static uv_loop_t *loop = uv_default_loop();
    assert(loop != NULL);
    int n = 0;

    const struct sockaddr_in addr = uv_ip4_addr("0.0.0.0", 2468);

    static uv_tcp_t tcp_server;
    n = uv_tcp_init(loop, &tcp_server);
    if (n)
    {
        /* TODO: Error codes */
        fprintf(stderr, "Socket creation error\n");
        return 1;
    }
    n = uv_tcp_bind(&tcp_server, addr);
    if (n)
    {
        /* TODO: Error codes */
        fprintf(stderr, "Bind error\n");
        return 1;
    }

    static struct sockaddr_in sa_remote = uv_ip4_addr(remote_addr.c_str(), remote_port);
    sa_remote.sin_family = AF_INET;

    static server_info_t server_info = {sa_remote};
    tcp_server.data = &server_info;

    //typedef void ( *uv_connect_cb ) ( uv_connect_t * req, int status );
    //typedef void ( *uv_connection_cb ) ( uv_stream_t * server, int status );
    n = uv_listen((uv_stream_t *)&tcp_server, SOMAXCONN, local_connection_cb);
    if (n)
    {
        /* TODO: Error codes */
        fprintf(stderr, "Listen error\n");
        return 1;
    }

#ifndef NDEBUG
    setup_signal_handler(loop);
#endif /* !NDEBUG */

    n = uv_run(loop, UV_RUN_DEFAULT);
    assert(n == 0);

    fprintf(stdout, "Exiting ...\n");

    return 0;
}
