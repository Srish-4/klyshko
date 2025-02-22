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

//****$$$$****//
#include <ctype.h>
#include <stdbool.h>
#define MBEDTLS_EXIT_SUCCESS EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE EXIT_FAILURE
//****$$$$****//

#define mbedtls_fprintf fprintf
#define mbedtls_printf printf

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

//****$$$$****//

#define SERVER_PORT "4433"
#define SERVER_NAME "localhost"
#define GET_REQUEST "GET / HTTP/1.0\r\n\r\n"

int (*ra_tls_verify_callback_extended_der_f)(uint8_t *der_crt, size_t der_crt_size,
                                             struct ra_tls_verify_callback_results *results);

/* RA-TLS: if specified in command-line options, use our own callback to verify SGX measurements */
void (*ra_tls_set_measurement_callback_f)(int (*f_cb)(const char *mrenclave, const char *mrsigner,
                                                      const char *isv_prod_id,
                                                      const char *isv_svn));

static int parse_hex(const char *hex, void *buffer, size_t buffer_size)
{
    if (strlen(hex) != buffer_size * 2)
        return -1;

    for (size_t i = 0; i < buffer_size; i++)
    {
        if (!isxdigit(hex[i * 2]) || !isxdigit(hex[i * 2 + 1]))
            return -1;
        sscanf(hex + i * 2, "%02hhx", &((uint8_t *)buffer)[i]);
    }
    return 0;
}

/* expected SGX measurements in binary form */
static char g_expected_mrenclave[32];
static char g_expected_mrsigner[32];
static char g_expected_isv_prod_id[2];
static char g_expected_isv_svn[2];

static bool g_verify_mrenclave = false;
static bool g_verify_mrsigner = false;
static bool g_verify_isv_prod_id = false;
static bool g_verify_isv_svn = false;

/* RA-TLS: our own callback to verify SGX measurements */
static int my_verify_measurements(const char *mrenclave, const char *mrsigner,
                                  const char *isv_prod_id, const char *isv_svn)
{
    assert(mrenclave && mrsigner && isv_prod_id && isv_svn);

    if (g_verify_mrenclave && memcmp(mrenclave, g_expected_mrenclave, sizeof(g_expected_mrenclave)))
        return -1;

    if (g_verify_mrsigner && memcmp(mrsigner, g_expected_mrsigner, sizeof(g_expected_mrsigner)))
        return -1;

    if (g_verify_isv_prod_id &&
        memcmp(isv_prod_id, g_expected_isv_prod_id, sizeof(g_expected_isv_prod_id)))
        return -1;

    if (g_verify_isv_svn && memcmp(isv_svn, g_expected_isv_svn, sizeof(g_expected_isv_svn)))
        return -1;

    return 0;
}

/* RA-TLS: mbedTLS-specific callback to verify the x509 certificate */
static int my_verify_callback(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    if (depth != 0)
    {
        /* the cert chain in RA-TLS consists of single self-signed cert, so we expect depth 0 */
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    }
    if (flags)
    {
        /* mbedTLS sets flags to signal that the cert is not to be trusted (e.g., it is not
         * correctly signed by a trusted CA; since RA-TLS uses self-signed certs, we don't care
         * what mbedTLS thinks and ignore internal cert verification logic of mbedTLS */
        *flags = 0;
    }
    return ra_tls_verify_callback_extended_der_f(crt->raw.p, crt->raw.len,
                                                 (struct ra_tls_verify_callback_results *)data);
}

//****$$$$****//

static void my_debug(void *ctx, int level, const char *file, int line, const char *str)
{
    ((void)level);

    mbedtls_fprintf((FILE *)ctx, "%s:%04d: %s\n", file, line, str);
    fflush((FILE *)ctx);
}

static ssize_t file_read(const char *path, char *buf, size_t count)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -errno;

    ssize_t bytes = fread(buf, 1, count, f);
    if (bytes <= 0)
    {
        int errsv = errno;
        fclose(f);
        return -errsv;
    }

    int close_ret = fclose(f);
    if (close_ret < 0)
        return -errno;

    return bytes;
}

int main(int argc, char **argv)
{
    int ret;
    size_t len;
    mbedtls_net_context listen_fd;
    mbedtls_net_context client_fd;
    unsigned char buf[1024];
    const char *pers = "ssl_server";
    char *error;

    //****$$$$****//
    int exit_code = MBEDTLS_EXIT_FAILURE;
    uint32_t flags;
    void *ra_tls_verify_lib = NULL;
    ra_tls_verify_callback_extended_der_f = NULL;
    ra_tls_set_measurement_callback_f = NULL;
    struct ra_tls_verify_callback_results my_verify_callback_results = {0};
    //****$$$$****//

    void *ra_tls_attest_lib;
    int (*ra_tls_create_key_and_crt_der_f)(uint8_t **der_key, size_t *der_key_size,
                                           uint8_t **der_crt, size_t *der_crt_size);

    uint8_t *der_key = NULL;
    uint8_t *der_crt = NULL;

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
    //****$$$$****//
    ra_tls_verify_lib = dlopen("libra_tls_verify_dcap_gramine.so", RTLD_LAZY);
    if (!ra_tls_verify_lib)
    {
        mbedtls_printf("%s\n", dlerror());
        mbedtls_printf(
            "User requested RA-TLS verification with DCAP inside SGX but cannot find lib\n");
        mbedtls_printf("Please make sure that you are using client_dcap.manifest\n");
        return 1;
    }

    if (ra_tls_verify_lib)
    {
        ra_tls_verify_callback_extended_der_f =
            dlsym(ra_tls_verify_lib, "ra_tls_verify_callback_extended_der");
        if ((error = dlerror()) != NULL)
        {
            mbedtls_printf("%s\n", error);
            return 1;
        }

        ra_tls_set_measurement_callback_f =
            dlsym(ra_tls_verify_lib, "ra_tls_set_measurement_callback");
        if ((error = dlerror()) != NULL)
        {
            mbedtls_printf("%s\n", error);
            return 1;
        }
    }

    if (argc > 2 && ra_tls_verify_lib)
    {
        if (argc != 5)
        {
            mbedtls_printf(
                "USAGE: %s %s <expected mrenclave> <expected mrsigner>"
                " <expected isv_prod_id> <expected isv_svn>\n"
                "       (first two in hex, last two as decimal; set to 0 to ignore)\n",
                argv[0], argv[1]);
            return 1;
        }

        mbedtls_printf(
            "[ using our own SGX-measurement verification callback"
            " (via command line options) ]\n");

        g_verify_mrenclave = true;
        g_verify_mrsigner = true;
        g_verify_isv_prod_id = true;
        g_verify_isv_svn = true;

        (*ra_tls_set_measurement_callback_f)(my_verify_measurements);

        if (!strcmp(argv[1], "0"))
        {
            mbedtls_printf("  - ignoring MRENCLAVE\n");
            g_verify_mrenclave = false;
        }
        else if (parse_hex(argv[1], g_expected_mrenclave, sizeof(g_expected_mrenclave)) < 0)
        {
            mbedtls_printf("Cannot parse MRENCLAVE!\n");
            return 1;
        }

        if (!strcmp(argv[2], "0"))
        {
            mbedtls_printf("  - ignoring MRSIGNER\n");
            g_verify_mrsigner = false;
        }
        else if (parse_hex(argv[2], g_expected_mrsigner, sizeof(g_expected_mrsigner)) < 0)
        {
            mbedtls_printf("Cannot parse MRSIGNER!\n");
            return 1;
        }

        if (!strcmp(argv[3], "0"))
        {
            mbedtls_printf("  - ignoring ISV_PROD_ID\n");
            g_verify_isv_prod_id = false;
        }
        else
        {
            errno = 0;
            uint16_t isv_prod_id = (uint16_t)strtoul(argv[3], NULL, 10);
            if (errno)
            {
                mbedtls_printf("Cannot parse ISV_PROD_ID!\n");
                return 1;
            }
            memcpy(g_expected_isv_prod_id, &isv_prod_id, sizeof(isv_prod_id));
        }

        if (!strcmp(argv[4], "0"))
        {
            mbedtls_printf("  - ignoring ISV_SVN\n");
            g_verify_isv_svn = false;
        }
        else
        {
            errno = 0;
            uint16_t isv_svn = (uint16_t)strtoul(argv[4], NULL, 10);
            if (errno)
            {
                mbedtls_printf("Cannot parse ISV_SVN\n");
                return 1;
            }
            memcpy(g_expected_isv_svn, &isv_svn, sizeof(isv_svn));
        }
    }

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_printf(" ok\n");

    if (ra_tls_verify_lib)
    {
        /* use RA-TLS verification callback; this will overwrite CA chain set up above */
        mbedtls_printf("  . Installing RA-TLS callback ...");
        mbedtls_ssl_conf_verify(&conf, &my_verify_callback, &my_verify_callback_results);
        mbedtls_printf(" ok\n");
    }

    //****$$$$****//

    char attestation_type_str[32] = {0};
    ret = file_read("/dev/attestation/attestation_type", attestation_type_str,
                    sizeof(attestation_type_str) - 1);
    if (ret < 0 && ret != -ENOENT)
    {
        mbedtls_printf(
            "User requested RA-TLS attestation but cannot read SGX-specific file "
            "/dev/attestation/attestation_type\n");
        return 1;
    }

    if (ret == -ENOENT || !strcmp(attestation_type_str, "none"))
    {
        ra_tls_attest_lib = NULL;
        ra_tls_create_key_and_crt_der_f = NULL;
    }
    else if (!strcmp(attestation_type_str, "dcap"))
    {
        ra_tls_attest_lib = dlopen("libra_tls_attest.so", RTLD_LAZY);
        if (!ra_tls_attest_lib)
        {
            mbedtls_printf("User requested RA-TLS attestation but cannot find lib\n");
            return 1;
        }

        char *error;
        ra_tls_create_key_and_crt_der_f = dlsym(ra_tls_attest_lib, "ra_tls_create_key_and_crt_der");
        if ((error = dlerror()) != NULL)
        {
            mbedtls_printf("%s\n", error);
            return 1;
        }
    }
    else
    {
        mbedtls_printf("Unrecognized remote attestation type: %s\n", attestation_type_str);
        return 1;
    }

    mbedtls_printf("  . Seeding the random number generator...");
    fflush(stdout);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char *)pers, strlen(pers));
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    if (ra_tls_attest_lib)
    {
        mbedtls_printf(
            "\n  . Creating the RA-TLS server cert and key (using \"%s\" as "
            "attestation type)...",
            attestation_type_str);
        fflush(stdout);

        size_t der_key_size;
        size_t der_crt_size;

        ret = (*ra_tls_create_key_and_crt_der_f)(&der_key, &der_key_size, &der_crt, &der_crt_size);
        if (ret != 0)
        {
            mbedtls_printf(" failed\n  !  ra_tls_create_key_and_crt_der returned %d\n\n", ret);
            goto exit;
        }

        ret = mbedtls_x509_crt_parse(&srvcert, (unsigned char *)der_crt, der_crt_size);
        if (ret != 0)
        {
            mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
            goto exit;
        }

        ret = mbedtls_pk_parse_key(&pkey, (unsigned char *)der_key, der_key_size, /*pwd=*/NULL, 0,
                                   mbedtls_ctr_drbg_random, &ctr_drbg);
        if (ret != 0)
        {
            mbedtls_printf(" failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret);
            goto exit;
        }
    }

    mbedtls_printf(" ok\n");

    mbedtls_printf("  . Bind on https://localhost:4433/ ...");
    fflush(stdout);

    ret = mbedtls_net_bind(&listen_fd, NULL, "4433", MBEDTLS_NET_PROTO_TCP);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_net_bind returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    mbedtls_printf("  . Setting up the SSL data....");
    fflush(stdout);

    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

    ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        goto exit;
    }

    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

reset:
#ifdef MBEDTLS_ERROR_C
    if (ret != 0)
    {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    mbedtls_net_free(&client_fd);

    mbedtls_ssl_session_reset(&ssl);

    mbedtls_printf("  . Waiting for a remote connection ...");
    fflush(stdout);

    ret = mbedtls_net_accept(&listen_fd, &client_fd, NULL, 0, NULL);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_net_accept returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    mbedtls_printf(" ok\n");

    mbedtls_printf("  . Performing the SSL/TLS handshake...");
    fflush(stdout);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n", -ret);
            mbedtls_printf(
                "  ! ra_tls_verify_callback_results:\n"
                "    attestation_scheme=%d, err_loc=%d, \n",
                my_verify_callback_results.attestation_scheme, my_verify_callback_results.err_loc);
            switch (my_verify_callback_results.attestation_scheme)
            {
            case RA_TLS_ATTESTATION_SCHEME_DCAP:
                mbedtls_printf(
                    "    dcap.func_verify_quote_result=0x%x, "
                    "dcap.quote_verification_result=0x%x\n\n",
                    my_verify_callback_results.dcap.func_verify_quote_result,
                    my_verify_callback_results.dcap.quote_verification_result);
                break;
            default:
                mbedtls_printf("  ! unknown attestation scheme!\n\n");
                break;
            }
        }
    }

    mbedtls_printf(" ok\n");

    //****$$****
    flags = mbedtls_ssl_get_verify_result(&ssl);
    if (flags != 0)
    {
        char vrfy_buf[512];
        mbedtls_printf(" failed\n");
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        mbedtls_printf("%s\n", vrfy_buf);

        /* verification failed for whatever reason, fail loudly */
        goto exit;
    }
    else
    {
        mbedtls_printf(" ok\n");
    }
    //****$$****

    mbedtls_printf("  < Read from client:");
    fflush(stdout);

    do
    {
        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        ret = mbedtls_ssl_read(&ssl, buf, len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;

        if (ret <= 0)
        {
            switch (ret)
            {
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

        len = ret;
        mbedtls_printf(" %lu bytes read\n\n%s", len, (char *)buf);

        if (ret > 0)
            break;
    } while (1);

    mbedtls_printf("  > Write to client:");
    fflush(stdout);

    len = sprintf((char *)buf, HTTP_RESPONSE, mbedtls_ssl_get_ciphersuite(&ssl));

    while ((ret = mbedtls_ssl_write(&ssl, buf, len)) <= 0)
    {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET)
        {
            mbedtls_printf(" failed\n  ! peer closed the connection\n\n");
            goto reset;
        }

        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            goto exit;
        }
    }

    len = ret;
    mbedtls_printf(" %lu bytes written\n\n%s\n", len, (char *)buf);

    mbedtls_printf("  . Closing the connection...");

    while ((ret = mbedtls_ssl_close_notify(&ssl)) < 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_close_notify returned %d\n\n", ret);
            goto reset;
        }
    }

    mbedtls_printf(" ok\n");

    ret = 0;
    goto reset;

exit:
#ifdef MBEDTLS_ERROR_C
    if (ret != 0)
    {
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
