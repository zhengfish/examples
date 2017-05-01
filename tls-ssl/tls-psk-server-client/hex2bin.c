#include <stdio.h>
#include <ctype.h>

inline int cval(char c)
{
    if (c >= 'a')
        return c - 'a' + 0x0a;
    if (c >= 'A')
        return c - 'A' + 0x0a;
    return c - '0';
}

/* return value: number of bytes in out, <=0 if error */
int hex2bin(char *str, unsigned char *out)
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

int main()
{
    unsigned char bbuf[128];
    int i;
    int len = hex2bin("1234567890abcdef", bbuf);
    printf("len=%d\n", len);
    if (len > 0)
    {
        for (i = 0; i < len; i++)
        {
            printf("%02X", bbuf[i]);
        }
        printf("\n");
    }
    return 0;
}
