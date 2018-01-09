#include <string.h>

#include "common.h"

#define CAFILE   "../ca/cacert.pem"
#define CADIR    NULL
#define CERTFILE "../ca/client.pem"

SSL_CTX *setup_client_ctx(void)
{
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_method());

    if (SSL_CTX_load_verify_locations(ctx, CAFILE, CADIR) != 1)
        int_error("Error loading CA file and/or directory");

    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        int_error("Error loading default CA file and/or directory");

    if (SSL_CTX_use_certificate_chain_file(ctx, CERTFILE) != 1)
        int_error("Error loading certificate from file");

    if (SSL_CTX_use_PrivateKey_file(ctx, CERTFILE, SSL_FILETYPE_PEM) != 1)
        int_error("Eoor loading private key from file");

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    SSL_CTX_set_verify_depth(ctx, 4);

    return ctx;
}

void do_client_loop_bio(BIO *conn)
{
    int err;
    unsigned int nwritten;
    char buff[80];

    for (;;){
        if (!fgets(buff, sizeof(buff), stdin)){
            break;
        }

        for (nwritten=0; nwritten < sizeof(buff); nwritten += err){
            err = BIO_write(conn, buff + nwritten, strlen(buff) - nwritten);
            if (err <= 0){
                // fprintf(stderr, "Client finish BIO_write, totally %d bytes written\n", nwritten);
                return;
            }
        }
    }
}

int do_client_loop(SSL *ssl)
{
    int err;
    unsigned int nwritten = 0;
    char buff[80];

    for (;;){
        if (!fgets(buff, sizeof(buff), stdin)){
            break;
        }

        for (nwritten=0; nwritten < sizeof(buff); nwritten += err){
            err = SSL_write(ssl, buff + nwritten, strlen(buff) - nwritten);
            if (err <= 0){
                fprintf(stderr, "Client finish SSL_write, totally %d bytes written\n", nwritten);
                return 0;
            }
        }
    }
    return nwritten;
}

int main(int argc, char*argv[])
{
    BIO *conn;
    SSL *ssl;
    long err;

    init_OpenSSL();
    seed_prng(10);

    SSL_CTX *ctx = setup_client_ctx();

    conn = BIO_new_connect(SERVER":"PORT);
    if (!conn)
        int_error("Error creating connection BIO");

    if (BIO_do_connect(conn) <= 0)
        int_error("Error connecting to remote machine");

    // create SSL object and copy the settings in SSL_CTX to it.
    if (!(ssl = SSL_new(ctx)))
        int_error("Error creating an SSL context");

    // pass BIO twice, to operate on two one-way IO types, 
    // instead of requiring a single full-duplex IO 
    // basically, we shall specify the BIO to use for writing separately from the BIO for reading.
    // they are teh same object in this case since sockets allow 2-way communication.
    SSL_set_bio(ssl, conn, conn);

    // initiate the protocol using the underlying I/O
    // begin the SSL handshake with the application on the other end of the underlying BIO.
    if (SSL_connect(ssl) <= 0)
        int_error("Error connecting SSL object");

    if ((err = post_connection_check(ssl, SERVER_NAME)) != X509_V_OK){
        fprintf(stderr, "-Error: peer certificate: %s\n", X509_verify_cert_error_string(err));
        int_error("Error checking SSL object after connection");
    }

    fprintf(stderr, "SSL Connection opened\n");
    if (do_client_loop(ssl))
        SSL_shutdown(ssl);
    else {
        // force OpenSSL to remove any session with errors from the session cache
        SSL_clear(ssl);
    }
    fprintf(stderr, "SSL Connection closed\n");

    // underlying BIO got free automatically by SSL_freee
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}
