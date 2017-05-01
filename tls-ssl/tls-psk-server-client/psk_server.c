//
// copyright https://bitbucket.org/tiebingzhang/
// from: https://bitbucket.org/tiebingzhang/tls-psk-server-client-example/src
//
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#define PORT 10443
#undef BUFSIZZ
#define BUFSIZZ 16 * 1024
#define INVALID_SOCKET (-1)

#define log_info(args...) BIO_printf(bio_s_out, args);
#define log_error(args...) BIO_printf(bio_err, args)

BIO *bio_err = NULL;

static int bufsize = BUFSIZZ;
static char *cipher = "PSK-AES256-CBC-SHA";
static SSL_CTX *ctx = NULL;
static BIO *bio_s_out = NULL;
static char *psk_identity = "Client_identity";
char *psk_key = "1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A";

static inline int cval(char c)
{
    if (c >= 'a')
        return c - 'a' + 0x0a;
    if (c >= 'A')
        return c - 'A' + 0x0a;
    return c - '0';
}

/* return value: number of bytes in out, <=0 if error */
static int hex2bin(char *str, unsigned char *out)
{
    int i;
    for (i = 0; str[i] && str[i + 1]; i += 2)
    {
        if (!isxdigit(str[i]) && !isxdigit(str[i + 1]))
            return -1;
        out[i / 2] = (cval(str[i]) << 4) + cval(str[i + 1]);
    }
    return i / 2;
}

static unsigned int
psk_server_cb(SSL *ssl,
              const char *identity,
              unsigned char *psk,
              unsigned int max_psk_len)
{
    int ret;

    (void)(ssl);

    if (!identity)
    {
        log_error("Error: client did not send PSK identity\n");
        return 0;
    }

    if (strcmp(identity, psk_identity) != 0)
    {
        log_info("PSK error: (got '%s' expected '%s')\n",
                 identity, psk_identity);
        return 0;
    }
    if (strlen(psk_key) >= (max_psk_len * 2))
    {
        log_error("Error, psk_key too long\n");
        return 0;
    }

    /* convert the PSK key to binary */
    ret = hex2bin(psk_key, psk);
    if (ret <= 0)
    {
        log_error("Could not convert PSK key '%s' to binary key\n", psk_key);
        return 0;
    }
    return ret;
}

static int init_server(int *sock, int port, char *ip, int type)
{
    int ret = 0;
    struct sockaddr_in server;
    int s = -1;
    int j = 1;

    memset((char *)&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons((unsigned short)port);
    if (ip == NULL)
        server.sin_addr.s_addr = INADDR_ANY;
    else
        memcpy(&server.sin_addr.s_addr, ip, 4);

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
        goto err;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (void *)&j, sizeof j);

    if (bind(s, (struct sockaddr *)&server, sizeof(server)) == -1)
    {
        perror("bind");
        goto err;
    }

    if (type == SOCK_STREAM && listen(s, 128) == -1)
        goto err;

    *sock = s;
    ret = 1;

err:
    if ((ret == 0) && (s != -1))
    {
        close(s);
    }
    return (ret);
}

static int do_accept(int acc_sock, int *sock)
{
    int ret;
    static struct sockaddr_in from;
    int len;

    memset((char *)&from, 0, sizeof(from));
    len = sizeof(from);
    ret = accept(acc_sock, (struct sockaddr *)&from, (void *)&len);
    if (ret == INVALID_SOCKET)
    {
        if (errno == EINTR)
        {
            /*check_timeout(); */
            printf("accept interrupted\n");
        }
        fprintf(stderr, "errno=%d ", errno);
        perror("accept");
        return (0);
    }

    *sock = ret;
    return (1);
}

static int server_body(int s)
{
    char *buf = NULL;
    fd_set readfds;
    int ret = 1, width;
    int i;
    SSL *con = NULL;
    BIO *sbio;

    if ((buf = OPENSSL_malloc(bufsize)) == NULL)
    {
        log_error("out of memory\n");
        goto err;
    }

    con = SSL_new(ctx);
    SSL_clear(con);
    sbio = BIO_new_socket(s, BIO_NOCLOSE);
    SSL_set_bio(con, sbio, sbio);
    SSL_set_accept_state(con);

    if (!SSL_is_init_finished(con))
    {
        i = SSL_accept(con);
        if (i <= 0)
        {
            log_error("Handshake ERROR\n");
            goto err;
        }
    }

    width = s + 1;
    for (;;)
    {
        FD_ZERO(&readfds);
        FD_SET(fileno(stdin), &readfds);
        FD_SET(s, &readfds);
        i = select(width, (void *)&readfds, NULL, NULL, NULL);
        if (i <= 0)
            continue;
        if (FD_ISSET(fileno(stdin), &readfds))
        {
            int l, k;
            if (fgets(buf, bufsize, stdin) == NULL)
            {
                printf("fgets from stdin error\n");
                i = 0;
            }
            else
            {
                i = strlen(buf);
            }

            l = k = 0;
            for (;;)
            {
                k = SSL_write(con, &(buf[l]), (unsigned int)i);
                switch (SSL_get_error(con, k))
                {
                case SSL_ERROR_NONE:
                    break;
                case SSL_ERROR_WANT_WRITE:
                case SSL_ERROR_WANT_READ:
                case SSL_ERROR_WANT_X509_LOOKUP:
                    log_info("Write BLOCK\n");
                    break;
                case SSL_ERROR_SYSCALL:
                case SSL_ERROR_SSL:
                    log_info("ERROR write\n");
                    ERR_print_errors(bio_err);
                    ret = 1;
                    goto err;
                /* break; */
                case SSL_ERROR_ZERO_RETURN:
                    log_info("DONE\n");
                    ret = 1;
                    goto err;
                }
                l += k;
                i -= k;
                if (i <= 0)
                    break;
            }
        }

        if (FD_ISSET(s, &readfds))
        {
        again:
            i = SSL_read(con, (char *)buf, bufsize);
            switch (SSL_get_error(con, i))
            {
            case SSL_ERROR_NONE:
                printf("got %d bytes\n", (int)i);
                if (SSL_pending(con))
                    goto again;
                break;
            case SSL_ERROR_WANT_WRITE:
            case SSL_ERROR_WANT_READ:
                log_info("Read BLOCK\n");
                break;
            case SSL_ERROR_SYSCALL:
            case SSL_ERROR_SSL:
                log_info("ERROR Reading\n");
                ERR_print_errors(bio_err);
                ret = 1;
                goto err;
            case SSL_ERROR_ZERO_RETURN:
                log_info("TLS Closed\n");
                ret = 1;
                goto err;
            }
        }
    }

err:
    if (con != NULL)
    {
        SSL_set_shutdown(con, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        SSL_free(con);
    }

    log_info("CONNECTION CLOSED\n");
    if (buf != NULL)
    {
        OPENSSL_cleanse(buf, bufsize);
        OPENSSL_free(buf);
    }

    if (ret >= 0)
        log_info("\nACCEPT\n");
    close(s);

    return (ret);
}

int main(void)
{
    short port = PORT;
    int off = SSL_OP_NO_SSLv2;
    const SSL_METHOD *meth = NULL;
    int sock;
    int accept_socket = 0;
    int i;

    ERR_load_crypto_strings();
    SSL_library_init();
    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    bio_s_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    meth = TLSv1_server_method();
    ctx = SSL_CTX_new(meth);
    if (ctx == NULL)
    {
        log_error(" SSL_CTX_new error\n");
        return -1;
    }

    SSL_CTX_set_quiet_shutdown(ctx, 1);
    SSL_CTX_set_options(ctx, off);
    SSL_CTX_set_psk_server_callback(ctx, psk_server_cb);
    if (!SSL_CTX_set_cipher_list(ctx, cipher))
    {
        ERR_print_errors(bio_err);
        return -2;
    }

    log_info("ACCEPT\n");

    if (!init_server(&accept_socket, port, NULL, SOCK_STREAM))
        return (-3);

    while (1)
    {
        if (do_accept(accept_socket, &sock) == 0)
        {
            close(accept_socket);
            return (0);
        }
        i = server_body(sock);
        if (i < 0)
        {
            close(accept_socket);
            return i;
        }
    }
    return 0;
}
