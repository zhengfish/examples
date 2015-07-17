#include <stdio.h>
#include <stdlib.h>
#include "amessage.pb-c.h"
#define MAX_MSG_SIZE 1024

static size_t
read_buffer ( unsigned max_length, uint8_t *out )
{
    size_t cur_len = 0;
    size_t nread = 0;
    while ( ( nread = fread ( out + cur_len, 1, max_length - cur_len, stdin ) ) != 0 )
    {
        cur_len += nread;
        if ( cur_len == max_length )
        {
            fprintf ( stderr, "max message length exceeded\n" );
            exit ( 1 );
        }
    }
    return cur_len;
}


int main ( int argc, const char * argv[] )
{
    AMessage *msg = NULL;

    // Read packed message from standard-input.
    uint8_t buf[MAX_MSG_SIZE];
    size_t msg_len = read_buffer ( MAX_MSG_SIZE, buf );

    // Unpack the message using protobuf-c.
    msg = amessage__unpack ( NULL, msg_len, buf );
    if ( msg == NULL )
    {
        fprintf ( stderr, "error unpacking incoming message\n" );
        exit ( 1 );
    }

    // display the message's fields.
    printf ( "Received: a=%d", msg->a );    // required field
    if ( msg->has_b )                       // handle optional field
        printf ( "  b=%d", msg->b );
    printf ( "\n" );

    // Free the unpacked message
    amessage__free_unpacked ( msg, NULL );
    return 0;
}

