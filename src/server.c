#include "common.h"

#define CAFILE   "../ca/cacert.pem"
#define CADIR    NULL
#define CERTFILE "../ca/server.pem"

SSL_CTX * setup_server_ctx(void)
{
    SSL_CTX *ctx = SSL_CTX_new (SSLv23_method());

    if (SSL_CTX_load_verify_locations(ctx, CAFILE, CADIR) != 1)
        int_error("Error loading CA file and/or directory");

    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        int_error("Error loading default CA file and/or directory");

    if (SSL_CTX_use_certificate_chain_file(ctx, CERTFILE) != 1)
        int_error("Error loading certificate from file");

    if (SSL_CTX_use_PrivateKey_file(ctx, CERTFILE, SSL_FILETYPE_PEM) != 1)
        int_error("Error loading private key from file");

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
    SSL_CTX_set_verify_depth(ctx,4);

    return ctx;
}

  
int do_server_loop(SSL *ssl)
{
    int err, nread;
    char buff[80];

    do {
        for (nread=0; nread < sizeof(buff); nread += err){
            err = SSL_read(ssl, buff + nread, sizeof(buff) - nread);
            fprintf(stderr, "BIO_read %d bytes\n", err);
            if (err <= 0)
                break;
        }
        fprintf(stderr, "BIO_read totally %d bytes\n", nread);
        fwrite(buff, 1, nread, stderr);
    }while (err > 0);

    // if SSL_RECEIVED_SHUTDOWN set, the seesion hasn't had an error
    // and it's safe to cache.
    return (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) ? 1 : 0;
}

void server_thread(void *arg)
{
    SSL * ssl = (SSL *)arg;
    long err;

    pthread_detach(pthread_self());

    if (SSL_accept(ssl) <= 0)
        int_error("Error accepting SSL connection");

    if ((err = post_connection_check(ssl, CLIENT_NAME)) != X509_V_OK) {
        fprintf(stderr, "-Error: peer certificate: %s\n", X509_verify_cert_error_string(err));
        int_error("Error checking SSL object after connection");
    }

    fprintf(stderr, "SSL connection opened\n");
    if (do_server_loop(ssl))
        SSL_shutdown(ssl);
    else
        SSL_clear(ssl);

    fprintf(stderr, "SSL connection closed\n");

    SSL_free(ssl);
    ERR_remove_state(0);
}


int main(int argc, char*argv[])
{
    init_OpenSSL();
    seed_prng(10);

    SSL_CTX *ctx = setup_server_ctx();

    BIO * acc = BIO_new_accept(PORT);
    if (!acc)
        int_error("Error creating server socket");

    if (BIO_do_accept(acc) <= 0)
        int_error("Error binding server socket");

    SSL *ssl;
    BIO *client;
    pthread_t tid;

    for (;;){
        if (BIO_do_accept(acc) <= 0)
            int_error("Error accepting connection");

        client = BIO_pop(acc);
        if (!(ssl = SSL_new(ctx)))
            int_error("Error creating SSL context");

        SSL_set_bio(ssl, client, client);
        pthread_create(&tid, NULL, server_thread, ssl);
    }

    SSL_CTX_free(ctx);
    BIO_free(acc);
    return 0;
}
