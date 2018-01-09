#include "common.h"

void handle_error(const char * file, int number, const char *msg)
{
    fprintf(stderr, "** %s: %i %s\n", file, number, msg);
    ERR_print_errors_fp(stderr);
    exit(-1);
}

void init_OpenSSL(void)
{
//    if (!THREAD_setup() || !SSL_library_init()){
    if (!SSL_library_init()){
        fprintf(stderr, "** OpenSSL initialization failed!\n");
        exit(-1);
    }
    SSL_load_error_strings();
}

int seed_prng(int bytes)
{
    if (!RAND_load_file("/dev/random", bytes))
        return 0;
    return 1;
}

int verify_callback(int ok, X509_STORE_CTX *store)
{
    if (!ok){
        char data[256];

        X509 *cert = X509_STORE_CTX_get_current_cert(store);
        int depth  = X509_STORE_CTX_get_error_depth(store);
        int err    = X509_STORE_CTX_get_error(store);

        fprintf(stderr, "-Error with certificate at depth: %i\n", depth);
        X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
        fprintf(stderr, "  issuer   = %s\n", data);

        X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
        fprintf(stderr, "  subject  = %s\n", data);

        fprintf(stderr, "  err %i:%s\n", err, X509_verify_cert_error_string(err));
    }
    return ok;
}

long post_connection_check(SSL *ssl, char *host)
{
    char data[256];
    int  extcount;
    int  ok = 0;

    /*
     * Checking the return from SSL_get_peer_certificate here is not strictly necessary.
     * with our example programs, it's not possible for it to return NULL. however, it's
     * good form to check the return since it can return NULL if the examples are modified 
     * to enable anonymous ciphers or for the server to not require  a client certificate
     */
    if (!host){
        fprintf(stderr, "null host passed into post_connection_check\n");
        return X509_V_ERR_APPLICATION_VERIFICATION;
    }

    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert){
        fprintf(stderr, "Failed to get cert from peer\n");
        return X509_V_ERR_APPLICATION_VERIFICATION;
    }

    extcount = X509_get_ext_count(cert);
    fprintf(stderr, "X509_get_ext_count returns %d\n", extcount);

    if (extcount > 0){
        for (int i=0; i < extcount; ++i){
            X509_EXTENSION *ext = X509_get_ext(cert, i);
            char * extstr = OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(ext)));
            fprintf(stderr, "extstr at level %d is %s\n", i, extstr);
            if (!strcmp(extstr, "subjectAltName")) {
                X509V3_EXT_METHOD *meth = X509V3_EXT_get(ext);
                if (!meth)
                    break;

                unsigned char *data = ext->value->data;
                STACK_OF(CONFG_VALUE) * val = meth->i2v(meth, meth->d2i(NULL, &data, ext->value->length), NULL);
                for (int j=0; j<sk_CONF_VALUE_num(val); ++j){
                    CONF_VALUE *nval = sk_CONF_VALUE_value(val, j);
                    fprintf(stderr, "CONF_VALUE[%d][%d]: %s -- %s\n", i, j, nval->name, nval->value);
                    if (!strcmp(nval->name, "DNS") && !strcmp(nval->value, host)) {
                        ok = 1;
                        break;
                    }
                }
            }
            if (ok)
                break;
        }
    }

    int result = 1;
    X509_NAME * subj = X509_get_subject_name(cert);
    if (!ok && subj &&
        X509_NAME_get_text_by_NID(subj, NID_commonName, data, 256) > 0){
        data[255] = 0;
        if (strcasecmp(data, host) != 0){
            fprintf(stderr, "get X509_NAME: %s, expected host is: %s\n", data, host);
            result = 0;
        }
    }

    X509_free(cert);
    if (result)
        return SSL_get_verify_result(ssl);
    else
        return X509_V_ERR_APPLICATION_VERIFICATION;
}
