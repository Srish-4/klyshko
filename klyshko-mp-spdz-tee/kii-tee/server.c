/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *               2020, Intel Labs
 */

/*
 * SSL server demonstration program (with RA-TLS)
 * This program is originally based on an mbedTLS example ssl_server.c but uses RA-TLS flows (SGX
 * Remote Attestation flows) if RA-TLS library is required by user.
 * Note that this program builds against mbedTLS 3.x.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/build_info.h"
//***$$$***
#include "macshares.pb-c.h"
//***$$$***

//****$$$$****//
#include <ctype.h>
#include <stdbool.h>
#define MBEDTLS_EXIT_SUCCESS EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE EXIT_FAILURE
//****$$$$****//

#define mbedtls_fprintf fprintf
#define mbedtls_printf  printf

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"
#include "ra_tls.h"

#define HTTP_RESPONSE                                    \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n"                  \
    "<p>Successful connection using: %s</p>\r\n"

#define DEBUG_LEVEL 0

#define MALICIOUS_STR "MALICIOUS DATA"

#define MAX_MSG_SIZE 1024

static void my_debug(void* ctx, int level, const char* file, int line, const char* str) {
    ((void)level);

    mbedtls_fprintf((FILE*)ctx, "%s:%04d: %s\n", file, line, str);
    fflush((FILE*)ctx);
}

static ssize_t file_read(const char* path, char* buf, size_t count) {
    FILE* f = fopen(path, "r");
    if (!f)
        return -errno;

    ssize_t bytes = fread(buf, 1, count, f);
    if (bytes <= 0) {
        int errsv = errno;
        fclose(f);
        return -errsv;
    }

    int close_ret = fclose(f);
    if (close_ret < 0)
        return -errno;

    return bytes;
}

int main(int argc, char** argv) {
    int ret;
    size_t len;
    mbedtls_net_context listen_fd;
    mbedtls_net_context client_fd;
    unsigned char buf[1024];
    const char* pers = "ssl_server";
    char* error;

    void* ra_tls_attest_lib;
    int (*ra_tls_create_key_and_crt_der_f)(uint8_t** der_key, size_t* der_key_size,
                                           uint8_t** der_crt, size_t* der_crt_size);

    uint8_t* der_key = NULL;
    uint8_t* der_crt = NULL;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;

    mbedtls_net_init(&listen_fd);
    mbedtls_net_init(&client_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    char attestation_type_str[32] = {0};
    ret = file_read("/dev/attestation/attestation_type", attestation_type_str,
                    sizeof(attestation_type_str) - 1);
    if (ret < 0 && ret != -ENOENT) {
        mbedtls_printf(
            "User requested RA-TLS attestation but cannot read SGX-specific file "
            "/dev/attestation/attestation_type\n");
        return 1;
    }

    if (ret == -ENOENT || !strcmp(attestation_type_str, "none")) {
        ra_tls_attest_lib               = NULL;
        ra_tls_create_key_and_crt_der_f = NULL;
    } else if (!strcmp(attestation_type_str, "dcap")) {
        ra_tls_attest_lib = dlopen("libra_tls_attest.so", RTLD_LAZY);
        if (!ra_tls_attest_lib) {
            mbedtls_printf("User requested RA-TLS attestation but cannot find lib\n");
            return 1;
        }

        char* error;
        ra_tls_create_key_and_crt_der_f = dlsym(ra_tls_attest_lib, "ra_tls_create_key_and_crt_der");
        if ((error = dlerror()) != NULL) {
            mbedtls_printf("%s\n", error);
            return 1;
        }
    } else {
        mbedtls_printf("Unrecognized remote attestation type: %s\n", attestation_type_str);
        return 1;
    }

    mbedtls_printf("  . Seeding the random number generator...");
    fflush(stdout);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    if (ra_tls_attest_lib) {
        mbedtls_printf(
            "\n  . Creating the RA-TLS server cert and key (using \"%s\" as "
            "attestation type)...",
            attestation_type_str);
        fflush(stdout);

        size_t der_key_size;
        size_t der_crt_size;

        ret = (*ra_tls_create_key_and_crt_der_f)(&der_key, &der_key_size, &der_crt, &der_crt_size);
        if (ret != 0) {
            mbedtls_printf(" failed\n  !  ra_tls_create_key_and_crt_der returned %d\n\n", ret);
            goto exit;
        }

        ret = mbedtls_x509_crt_parse(&srvcert, (unsigned char*)der_crt, der_crt_size);
        if (ret != 0) {
            mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
            goto exit;
        }

        ret = mbedtls_pk_parse_key(&pkey, (unsigned char*)der_key, der_key_size, /*pwd=*/NULL, 0,
                                   mbedtls_ctr_drbg_random, &ctr_drbg);
        if (ret != 0) {
            mbedtls_printf(" failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret);
            goto exit;
        }
    }

    mbedtls_printf(" ok\n");

    mbedtls_printf("  . Bind on https://localhost:4433/ ...");
    fflush(stdout);

    ret = mbedtls_net_bind(&listen_fd, NULL, "4433", MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_net_bind returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    mbedtls_printf("  . Setting up the SSL data....");
    fflush(stdout);

    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

    ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        goto exit;
    }

    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    // reset:
    // #ifdef MBEDTLS_ERROR_C
    //     if (ret != 0) {
    //         char error_buf[100];
    //         mbedtls_strerror(ret, error_buf, sizeof(error_buf));
    //         mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    //     }
    // #endif

    mbedtls_net_free(&client_fd);

    mbedtls_ssl_session_reset(&ssl);

    mbedtls_printf("  . Waiting for a remote connection ...");
    fflush(stdout);

    ret = mbedtls_net_accept(&listen_fd, &client_fd, NULL, 0, NULL);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_net_accept returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    mbedtls_printf(" ok\n");

    mbedtls_printf("  . Performing the SSL/TLS handshake...");
    fflush(stdout);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned %d\n\n", ret);
            goto reset;
        }
    }

    mbedtls_printf(" ok\n");

    // PROTOBUFF STARTING - UNPACKING OF DATA
    //  code for macshares and reading
    uint8_t buffer[MAX_MSG_SIZE];
    size_t msg_len;
    do {
        msg_len = sizeof(buffer) - 1;
        memset(buf, 0, sizeof(buffer));
        ret = mbedtls_ssl_read(&ssl, buffer, msg_len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;

        if (ret <= 0) {
            switch (ret) {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    mbedtls_printf(" connection was closed gracefully\n");
                    break;

                case MBEDTLS_ERR_NET_CONN_RESET:
                    mbedtls_printf(" connection was reset by peer\n");
                    break;

                default:
                    mbedtls_printf(" mbedtls_ssl_read returned -0x%x\n", -ret);
                    break;
            }

            break;
        }

        msg_len = ret;
        mbedtls_printf(" %ld bytes read\n\n%s", msg_len, (char*)buffer);

        if (ret > 0)
            break;
    } while (1);

    SecretShare* message;
    message = secret_share__unpack(NULL, msg_len, buffer);
    if (message == NULL) {
        fprintf(stderr, "Error unpacking incoming message\n");
    }

    // Display the message's fields
    printf("Received: mackeyshare_2=%s", message->mackeyshare_2);  // required field
    printf("  mackeyshare_p=%s\n", message->mackeyshare_p);
    // Free the unpacked message
    secret_share__free_unpacked(message, NULL);

    // PROTOBUFF ENDING - UNPACKING

    mbedtls_printf("  . Closing the connection...");

    while ((ret = mbedtls_ssl_close_notify(&ssl)) < 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_close_notify returned %d\n\n", ret);
            goto reset;
        }
    }

    mbedtls_printf(" ok\n");

    ret = 0;
    // goto reset;

reset:
#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

exit:
#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    if (ra_tls_attest_lib)
        dlclose(ra_tls_attest_lib);

    mbedtls_net_free(&client_fd);
    mbedtls_net_free(&listen_fd);

    mbedtls_x509_crt_free(&srvcert);
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    free(der_key);
    free(der_crt);

    return ret;
}
