#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>

#include <pthread.h>

#define PORT "6001"
#define SERVER "localhost"
#define SERVER_NAME "server.localdomain"
#define CLIENT_NAME "client.localdomain"

#define int_error(msg) handle_error(__FILE__, __LINE__, msg)

// declaration of fucntions here
void handle_error (const char *file, int linenumber, const char *msg);
void init_OpenSSL(void);
int  seed_prng(int);
int  verify_callback(int ok, X509_STORE_CTX *store);
long post_connection_check(SSL *ssl, char *host);
