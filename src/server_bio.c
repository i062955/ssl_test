#include "common.h"

void do_server_loop(BIO *conn)
{
    int err, nread;
    char buff[80];

    do {
        for (nread=0; nread < sizeof(buff); nread += err){
            err = BIO_read(conn, buff + nread, sizeof(buff) - nread);
            fprintf(stderr, "BIO_read %d bytes\n", err);
            if (err <= 0)
                break;
        }
        fprintf(stderr, "BIO_read totally %d bytes\n", nread);
        fwrite(buff, 1, nread, stderr);
    }while (err > 0);
}

void THREAD_CC server_thread(void *arg)
{
    BIO * client = (BIO *)arg;

    pthread_detach(pthread_self());

    fprintf(stderr, "Connection opened\n");
    do_server_loop(client);
    fprintf(stderr, "Connection closed\n");

    BIO_free(client);
    ERR_remove_state(0);
}


int main(int argc, char*argv[])
{
    BIO *acc;
    BIO *client;
    THREAD_TYPE tid;

    init_OpenSSL();

    acc = BIO_new_accept(PORT);
    if (!acc)
        int_error("Error creating server socket");

    if (BIO_do_accept(acc) <= 0)
        int_error("Error binding server socket");

    for (;;){
        if (BIO_do_accept(acc) <= 0)
            int_error("Error accepting connection");

        client = BIO_pop(acc);
        THREAD_CREATE(tid, server_thread, client);
    }

    BIO_free(acc);
    return 0;
}
