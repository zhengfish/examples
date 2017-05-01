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
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#define get_last_socket_error() errno

#define PORT 10443
#undef BUFSIZZ
#define BUFSIZZ 16 * 1024
#define INVALID_SOCKET (-1)

#define log_info(args...) BIO_printf(bio_c_out, args);
#define log_error(args...) BIO_printf(bio_err, args)

CONF *config = NULL;
BIO *bio_err = NULL;

static char *cipher = "PSK-AES256-CBC-SHA";
static SSL_CTX *ctx = NULL;
static BIO *bio_c_out = NULL;
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
psk_client_cb(SSL *ssl,
              const char *hint,
              char *identity,
              unsigned int max_identity_len,
              unsigned char *psk,
              unsigned int max_psk_len)
{
    int ret;

    (void)(ssl); //unused; prevent gcc warning;

    if (!hint)
    {
        log_info("NULL received PSK identity hint, continuing anyway\n");
    }
    else
    {
        log_info("Received PSK identity hint '%s'\n", hint);
    }

    ret = snprintf(identity, max_identity_len, "%s", psk_identity);
    if (ret < 0 || (unsigned int)ret > max_identity_len)
    {
        log_error("Error, psk_identify too long\n");
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
        log_error("Error, Could not convert PSK key '%s' to binary key\n", psk_key);
        return 0;
    }
    return ret;
}

static void apps_startup()
{
    ERR_load_crypto_strings();
    ERR_load_SSL_strings();
    OpenSSL_add_all_algorithms();
    SSL_library_init();
}

static int init_client_ip(int *sock, unsigned char ip[4], int port, int type)
{
    unsigned long addr;
    struct sockaddr_in them;
    int s, i;

    memset((char *)&them, 0, sizeof(them));
    them.sin_family = AF_INET;
    them.sin_port = htons((unsigned short)port);
    addr = (unsigned long)((unsigned long)ip[0] << 24L) |
           ((unsigned long)ip[1] << 16L) |
           ((unsigned long)ip[2] << 8L) |
           ((unsigned long)ip[3]);
    them.sin_addr.s_addr = htonl(addr);

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (s == INVALID_SOCKET)
    {
        perror("socket");
        return (0);
    }

    if (type == SOCK_STREAM)
    {
        i = 0;
        i = setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char *)&i, sizeof(i));
        if (i < 0)
        {
            perror("keepalive");
            return (0);
        }
    }

    if (connect(s, (struct sockaddr *)&them, sizeof(them)) == -1)
    {
        close(s);
        perror("connect");
        return (0);
    }
    *sock = s;
    return (1);
}
static int host_ip(char *str, unsigned char ip[4])
{
    unsigned int in[4];
    int i;

    if (sscanf(str, "%u.%u.%u.%u", &(in[0]), &(in[1]), &(in[2]), &(in[3])) == 4)
    {
        for (i = 0; i < 4; i++)
            if (in[i] > 255)
            {
                log_error("invalid IP address\n");
                goto err;
            }
        ip[0] = in[0];
        ip[1] = in[1];
        ip[2] = in[2];
        ip[3] = in[3];
    }

    return (1);
err:
    return (0);
}

int init_client(int *sock, char *host, int port, int type)
{
    unsigned char ip[4];

    memset(ip, '\0', sizeof ip);
    if (!host_ip(host, &(ip[0])))
        return 0;
    return init_client_ip(sock, ip, port, type);
}

int main(void)
{
    short port = PORT;
    const SSL_METHOD *meth = NULL;
    char *host = "127.0.0.1";
    int s;
    SSL *con = NULL;
    BIO *sbio;

    apps_startup();
    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    bio_c_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    if (init_client(&s, host, port, SOCK_STREAM) == 0)
    {
        log_error("connect:errno=%d\n", get_last_socket_error());
        return -1;
    }
    log_info("TCP CONNECTED(%08X)\n", s);

    meth = TLSv1_client_method();
    ctx = SSL_CTX_new(meth);
    if (ctx == NULL)
    {
        log_error(" SSL_CTX_new error\n");
        return -1;
    }

    SSL_CTX_set_psk_client_callback(ctx, psk_client_cb);
    SSL_CTX_set_cipher_list(ctx, cipher);

    con = SSL_new(ctx);
    SSL_CTX_set_cipher_list(ctx, cipher);
    sbio = BIO_new_socket(s, BIO_NOCLOSE);
    SSL_set_bio(con, sbio, sbio);
    SSL_set_connect_state(con);
    SSL_connect(con);

    char *cbuf = NULL, *sbuf = NULL;
    if (((cbuf = OPENSSL_malloc(BUFSIZZ)) == NULL) ||
        ((sbuf = OPENSSL_malloc(BUFSIZZ)) == NULL))
    {
        log_error("out of memory\n");
        goto end;
    }

#if 0
    //the initial write seems to finish the handshake
    SSL_write(con,cbuf,0);
    sprintf(cbuf,"123456\n12345678\n");
    SSL_write(con,cbuf,17);
#endif
    printf("Waiting for data from server...\n");
    int k = SSL_read(con, sbuf, BUFSIZZ);
    sbuf[k] = '\0';
    printf("got %d bytes: %s\n", k, sbuf);

    SSL_shutdown(con);
    close(SSL_get_fd(con));

end:
    if (con != NULL)
        SSL_free(con);
    if (ctx != NULL)
        SSL_CTX_free(ctx);
    if (bio_c_out != NULL)
    {
        BIO_free(bio_c_out);
        bio_c_out = NULL;
    }

    return (0);
}
