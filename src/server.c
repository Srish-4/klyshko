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
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "secretsharing.pb-c.h"

#include "mbedtls/build_info.h"
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

#define DEBUG_LEVEL 0

#define MALICIOUS_STR "MALICIOUS DATA"
// edited
#define CA_CRT_PATH          "ssl/ca.crt"
#define SRV_CRT_PATH         "ssl/server.crt"
#define SRV_KEY_PATH         "ssl/server.key"
#define SERVER_PORT          "4444"
#define SERVER_NAME          "localhost"
#define GET_REQUEST          "GET / HTTP/1.0\r\n\r\n"
#define MBEDTLS_EXIT_SUCCESS EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE EXIT_FAILURE
#define DEBUG_LEVEL          0
#define MAX_MSG_SIZE 1024
#define CA_CRT_PATH "ssl/ca.crt"
#define RETRY_DELAY 
// edited
// edited ash06
int (*ra_tls_verify_callback_extended_der_f)(uint8_t* der_crt, size_t der_crt_size,
                                             struct ra_tls_verify_callback_results* results);

/* RA-TLS: if specified in command-line options, use our own callback to verify SGX measurements */
void (*ra_tls_set_measurement_callback_f)(int (*f_cb)(const char* mrenclave, const char* mrsigner,
                                                      const char* isv_prod_id,
                                                      const char* isv_svn));
// ash06

static void my_debug(void* ctx, int level, const char* file, int line, const char* str) {
    ((void)level);

    mbedtls_fprintf((FILE*)ctx, "%s:%04d: %s\n", file, line, str);
    fflush((FILE*)ctx);
}
// edited
static int parse_hex(const char* hex, void* buffer, size_t buffer_size) {
    if (strlen(hex) != buffer_size * 2)
        return -1;

    for (size_t i = 0; i < buffer_size; i++) {
        if (!isxdigit(hex[i * 2]) || !isxdigit(hex[i * 2 + 1]))
            return -1;
        sscanf(hex + i * 2, "%02hhx", &((uint8_t*)buffer)[i]);
    }
    return 0;
}

int verify_player_details(char* kii_job_id, int player_number, char* kii_job_id_defined, int player_number_defined) {
    if (strcmp(kii_job_id, kii_job_id_defined) == 0 && player_number == player_number_defined) {
        return 0;
    } else {
        return -1;
    }
}
// edited
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

/* expected SGX measurements in binary form */
static char g_expected_mrenclave[32];
static char g_expected_mrsigner[32];
static char g_expected_isv_prod_id[2];
static char g_expected_isv_svn[2];

static bool g_verify_mrenclave   = false;
static bool g_verify_mrsigner    = false;
static bool g_verify_isv_prod_id = false;
static bool g_verify_isv_svn     = false;

/* RA-TLS: our own callback to verify SGX measurements */
static int my_verify_measurements(const char* mrenclave, const char* mrsigner,
                                  const char* isv_prod_id, const char* isv_svn) {
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
static int my_verify_callback(void* data, mbedtls_x509_crt* crt, int depth, uint32_t* flags) {
    if (depth != 0) {
        /* the cert chain in RA-TLS consists of single self-signed cert, so we expect depth 0 */
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    }
    if (flags) {
        /* mbedTLS sets flags to signal that the cert is not to be trusted (e.g., it is not
         * correctly signed by a trusted CA; since RA-TLS uses self-signed certs, we don't care
         * what mbedTLS thinks and ignore internal cert verification logic of mbedTLS */
        *flags = 0;
    }
    return ra_tls_verify_callback_extended_der_f(crt->raw.p, crt->raw.len,
                                                 (struct ra_tls_verify_callback_results*)data);
}
// commented because the env is inside SGX
static bool getenv_client_inside_sgx() {
    char* str = getenv("RA_TLS_CLIENT_INSIDE_SGX");
    if (!str)
        return false;

    return !strcmp(str, "1") || !strcmp(str, "true") || !strcmp(str, "TRUE");
}

//initiate the connection and then make 

int main(int argc, char** argv) {
    int ret;
    size_t len;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_net_context listen_fd;
    mbedtls_net_context client_fd;
    unsigned char buf[1024];
    const char* pers = "ssl_server";
    bool in_sgx      = getenv_client_inside_sgx();
    //get i(player_number) from the env variables and have a global variable other_player_number(k)(which is from 0 to i-1);
    int other_player_number = 0;
    void* ra_tls_attest_lib;
    // creating cert, need to do that in client side also
    int (*ra_tls_create_key_and_crt_der_f)(uint8_t** der_key, size_t* der_key_size,
                                           uint8_t** der_crt, size_t* der_crt_size);
    char* error;
    uint32_t flags;
    void* ra_tls_verify_lib                                          = NULL;
    ra_tls_verify_callback_extended_der_f                            = NULL;
    ra_tls_set_measurement_callback_f                                = NULL;
    struct ra_tls_verify_callback_results my_verify_callback_results = {0};
    uint8_t* der_key                                                 = NULL;
    uint8_t* der_crt                                                 = NULL;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_x509_crt cacert;
    mbedtls_pk_context pkey;
    mbedtls_x509_crt clicert;
   

    mbedtls_net_init(&listen_fd);
    mbedtls_net_init(&client_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_x509_crt_init(&cacert);  // edited
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_x509_crt_init(&clicert);
//code for getting the environment variables inside the main function
    const char *env_names[] = {
        "KII_TUPLES_PER_JOB", "KII_SHARED_FOLDER", "KII_TUPLE_FILE", 
        "KII_PLAYER_NUMBER", "KII_PLAYER_COUNT", "KII_JOB_ID", 
        "KII_TUPLE_TYPE", "KII_PLAYER_ENDPOINT_1", "KII_PLAYER_ENDPOINT_0"
    };
    
    char *env_values[sizeof(env_names) / sizeof(env_names[0])];

    // Loop through each environment variable
    for (int i = 0; i < sizeof(env_names) / sizeof(env_names[0]); i++) {
        env_values[i] = getenv(env_names[i]);

        // Check if the environment variable exists and print the appropriate message
        if (env_values[i] == NULL) {
            fprintf(stderr, "Error: Environment variable %s not found.\n", env_names[i]); 
        }
    }
    
    char *kii_job_id_str = env_values[5];  // KII_JOB_ID
    char *player_number_str = env_values[3];  // KII_PLAYER_NUMBER
    char *number_of_players_str = env_values[4];
    // Convert to integers
    //int kii_job_id_defined = kii_job_id_str ? atoi(kii_job_id_str) : 0;  // Check for NULL first
    int player_number_defined = player_number_str ? atoi(player_number_str) : 0;
    int number_of_players = number_of_players_str ? atoi(number_of_players_str) : 0;
//EOC for getting the env variables and storing them inside main fuction

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    char attestation_type_str[32] = {0};
    ret = file_read("/dev/attestation/attestation_type", attestation_type_str,
                    sizeof(attestation_type_str) - 1);

    // code for dcap attestation
    if (in_sgx) {
        /*
         * RA-TLS verification with DCAP inside SGX enclave uses dummies instead of real
         * functions from libsgx_urts.so, thus we don't need to load this helper library.
         */
        ra_tls_verify_lib = dlopen("libra_tls_verify_dcap_gramine.so", RTLD_LAZY);
        if (!ra_tls_verify_lib) {
            mbedtls_printf("%s\n", dlerror());
            mbedtls_printf(
                "User requested RA-TLS verification with DCAP inside SGX but cannot find lib\n");
            mbedtls_printf("Please make sure that you are using client_dcap.manifest\n");
            return 1;
        }
    }
    // review
    else {
        void* helper_sgx_urts_lib = dlopen("libsgx_urts.so", RTLD_NOW | RTLD_GLOBAL);
        if (!helper_sgx_urts_lib) {
            mbedtls_printf("%s\n", dlerror());
            mbedtls_printf(
                "User requested RA-TLS verification with DCAP but cannot find helper"
                " libsgx_urts.so lib\n");
            return 1;
        }

        ra_tls_verify_lib = dlopen("libra_tls_verify_dcap.so", RTLD_LAZY);
        if (!ra_tls_verify_lib) {
            mbedtls_printf("%s\n", dlerror());
            mbedtls_printf("User requested RA-TLS verification with DCAP but cannot find lib\n");
            return 1;
        }
    }
    // review

    if (ret < 0 && ret != -ENOENT) {
        mbedtls_printf(
            "User requested RA-TLS attestation but cannot read SGX-specific file "
            "/dev/attestation/attestation_type\n");
        return 1;
    }
    // code for the mr enclave and all for the server side if it gets used a s a client
    // ash06
    if (ra_tls_verify_lib) {
        ra_tls_verify_callback_extended_der_f =
            dlsym(ra_tls_verify_lib, "ra_tls_verify_callback_extended_der");
        if ((error = dlerror()) != NULL) {
            mbedtls_printf("%s\n", error);
            return 1;
        }

        ra_tls_set_measurement_callback_f =
            dlsym(ra_tls_verify_lib, "ra_tls_set_measurement_callback");
        if ((error = dlerror()) != NULL) {
            mbedtls_printf("%s\n", error);
            return 1;
        }
    }

    if (argc > 1 && ra_tls_verify_lib) {
        if (argc != 5) {
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

        
        g_verify_mrenclave   = true;
        g_verify_mrsigner    = true;
        g_verify_isv_prod_id = true;
        g_verify_isv_svn     = true;

        (*ra_tls_set_measurement_callback_f)(my_verify_measurements);
        
        if (!strcmp(argv[1], "0")) {
            mbedtls_printf("  - ignoring MRENCLAVE\n");
            g_verify_mrenclave = false;
        } else if (parse_hex(argv[1], g_expected_mrenclave, sizeof(g_expected_mrenclave)) < 0) {
            mbedtls_printf("Cannot parse MRENCLAVE!\n");
            return 1;
        }

        if (!strcmp(argv[2], "0")) {
            mbedtls_printf("  - ignoring MRSIGNER\n");
            g_verify_mrsigner = false;
        } else if (parse_hex(argv[2], g_expected_mrsigner, sizeof(g_expected_mrsigner)) < 0) {
            mbedtls_printf("Cannot parse MRSIGNER!\n");
            return 1;
        }

        if (!strcmp(argv[3], "0")) {
            mbedtls_printf("  - ignoring ISV_PROD_ID\n");
            g_verify_isv_prod_id = false;
        } else {
            errno                = 0;
            uint16_t isv_prod_id = (uint16_t)strtoul(argv[3], NULL, 10);
            if (errno) {
                mbedtls_printf("Cannot parse ISV_PROD_ID!\n");
                return 1;
            }
            memcpy(g_expected_isv_prod_id, &isv_prod_id, sizeof(isv_prod_id));
        }

        if (!strcmp(argv[4], "0")) {
            mbedtls_printf("  - ignoring ISV_SVN\n");
            g_verify_isv_svn = false;
        } else {
            errno            = 0;
            uint16_t isv_svn = (uint16_t)strtoul(argv[4], NULL, 10);
            if (errno) {
                mbedtls_printf("Cannot parse ISV_SVN\n");
                return 1;
            }
            memcpy(g_expected_isv_svn, &isv_svn, sizeof(isv_svn));
        }
    }
    // indices concern
    // end of the code ash06
    if (ret == -ENOENT || !strcmp(attestation_type_str, "none")) {
        ra_tls_attest_lib               = NULL;
        ra_tls_create_key_and_crt_der_f = NULL;
    } else if (!strcmp(attestation_type_str, "dcap")) {
        ra_tls_attest_lib =
            dlopen("libra_tls_attest.so", RTLD_LAZY);  // initializing the attestation lib
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

        mbedtls_printf(" ok\n");

    } else {
        mbedtls_printf("\n  . Creating normal server cert and key...");
        fflush(stdout);

        ret = mbedtls_x509_crt_parse_file(&srvcert, SRV_CRT_PATH);
        if (ret != 0) {
            mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse_file returned %d\n\n", ret);
            goto exit;
        }

        ret = mbedtls_x509_crt_parse_file(&cacert, CA_CRT_PATH);
        if (ret != 0) {
            mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse_file returned %d\n\n", ret);
            goto exit;
        }

        ret = mbedtls_pk_parse_keyfile(&pkey, SRV_KEY_PATH, /*password=*/NULL,
                                       mbedtls_ctr_drbg_random, &ctr_drbg);
        if (ret != 0) {
            mbedtls_printf(" failed\n  !  mbedtls_pk_parse_keyfile returned %d\n\n", ret);
            goto exit;
        }

        mbedtls_printf(" ok\n");
    }
    if(player_number_defined == 0)goto client; //edited line ash06
    mbedtls_printf("  . Bind on https://localhost:4444/ ...");
    fflush(stdout);

    ret = mbedtls_net_bind(&listen_fd, NULL, "4444", MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_net_bind returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    mbedtls_printf("  . Setting up the SSL data....");
    fflush(stdout);

    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    // extra code ash06
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    // ash06 eoc
    mbedtls_printf(" ok\n");
    if (ra_tls_verify_lib) {
        /* use RA-TLS verification callback; this will overwrite CA chain set up above */
        mbedtls_printf("  . Installing RA-TLS callback ...");
        mbedtls_ssl_conf_verify(&conf, &my_verify_callback, &my_verify_callback_results);
        mbedtls_printf(" ok\n");
    }

    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

    if (!ra_tls_attest_lib) {
        /* no RA-TLS attest library present, use embedded CA chain */
        mbedtls_ssl_conf_ca_chain(&conf, cacert.next, NULL);
    }

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

    mbedtls_printf("  . Performing the SSL/TLS handshake...");

//edit made ash06
reset:
//check if k <= i-1 and add the if else statements.
if(other_player_number  < player_number_defined){
    other_player_number++;
}else{
    goto client;
}
#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
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
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_net_accept returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    mbedtls_printf(" ok\n");

    mbedtls_printf("  . Performing the SSL/TLS handshake...");
    fflush(stdout);
    // Send over the SSL channel
   
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        printf("Entered server the while loop of handshake");
        fflush(stdout);
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n", -ret);
            mbedtls_printf(
                "  ! ra_tls_verify_callback_results:\n"
                "    attestation_scheme=%d, err_loc=%d, \n",
                my_verify_callback_results.attestation_scheme, my_verify_callback_results.err_loc);
            switch (my_verify_callback_results.attestation_scheme) {
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
            printf("while loop exit server");
            goto exit;
        }
    }

    mbedtls_printf(" ok\n");

    mbedtls_printf("  . Verifying peer X.509 certificate...");

    flags = mbedtls_ssl_get_verify_result(&ssl);
    if (flags != 0) {
        char vrfy_buf[512];
        mbedtls_printf(" failed\n");
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        mbedtls_printf("%s\n", vrfy_buf);

        /* verification failed for whatever reason, fail loudly */
        goto exit;
    } else {
        mbedtls_printf(" ok\n");
    }
    
    mbedtls_printf("  < Read from client:");
    fflush(stdout);
    PlayerInfo *msg;
    uint8_t buff[MAX_MSG_SIZE];
    size_t play_len;
  
    do {
        play_len = sizeof(buff) - 1;
        memset(buff, 0, sizeof(buff));
        ret = mbedtls_ssl_read(&ssl, buff, play_len);

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

        play_len = ret;
        mbedtls_printf(" %ld bytes read\n\n%s", play_len, (char*)buff);

        if (ret > 0)
            break;
    } while (1);

    msg = player_info__unpack(NULL, play_len, buff);
    if (msg == NULL) {
        fprintf(stderr, "Error unpacking incoming message\n");
    }


    // Display the message's fields
    printf("Received: kii_job_id=%s", msg->kii_job_id); // required field
    printf("  player_number=%d\n", msg->player_number);
    int returncode = verify_player_details(msg->kii_job_id,msg->player_number,kii_job_id_str,player_number_defined);
    if(returncode == -1){
        printf("KII_JOB_ID or PLAYER_ID not valid.\n");
        int rcd = mbedtls_ssl_close_notify(&ssl);
        while(rcd < 0){
            rcd = mbedtls_ssl_close_notify(&ssl);
        }
    }


    //code for macshares and reading
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
    
    SecretShare *message;
    message = secret_share__unpack(NULL, msg_len, buffer);
    if (message == NULL) {
        fprintf(stderr, "Error unpacking incoming message\n");
    }

    // Display the message's fields
    printf("Received: mackeyshare_2=%s", message->mackeyshare_2); // required field
    printf("  mackeyshare_p=%s\n", message->mackeyshare_p);
    printf("  seeds=%s\n", message->seeds);
    // Free the unpacked message
    secret_share__free_unpacked(message, NULL);


//code for sending the macshares and seed values from the server to client side 

    SecretShare secret_message = SECRET_SHARE__INIT;
    secret_message.mackeyshare_2 = "f0cf6099e629fd0bda2de3f9515ab72b";
    secret_message.mackeyshare_p = "-88222337191559387830816715872691188861";
    secret_message.seeds = "adedefwklrewernfserver";
    unsigned lenth = secret_share__get_packed_size(&secret_message);
    if(lenth == 0){
        fprintf(stderr, "packing or serialization error");
    }
    void *secret_buffer = malloc(lenth);
    if (!secret_buffer) {
        fprintf(stderr, "Memory allocation error\n");
    }

    secret_share__pack(&secret_message, secret_buffer);
    fprintf(stderr, "Writing %d serialized bytes\n", lenth);
    while ((ret = mbedtls_ssl_write(&ssl, secret_buffer, lenth)) <= 0) {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
            mbedtls_printf(" failed\n  ! peer closed the connection\n\n");
            goto reset;
        }

        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            goto exit;
        }
    }

    lenth = ret;
    mbedtls_printf(" %d bytes written\n\n%s\n", lenth, (char*)secret_buffer);

    fflush(stdout);

    //pack

    mbedtls_printf("  . Closing the connection...");

    while ((ret = mbedtls_ssl_close_notify(&ssl)) < 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_close_notify returned %d\n\n", ret);
            goto reset;
        }
    }

    mbedtls_printf(" ok\n");

    ret = 0;
    goto reset;

client:
//for loop for the client connection
for(other_player_number = number_of_players-1; other_player_number >= player_number_defined+1; other_player_number--){
    //logic for client connection and secret sharing.

    mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    //***$$$***
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

        ret = mbedtls_x509_crt_parse(&clicert, (unsigned char*)der_crt, der_crt_size);
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

        mbedtls_printf(" ok\n");
    }
    //***$$$***

    mbedtls_printf("  . Connecting to tcp/%s/%s...", SERVER_NAME, SERVER_PORT);
    fflush(stdout);

    while (1) {
        ret = mbedtls_net_connect(&listen_fd, SERVER_NAME, SERVER_PORT, MBEDTLS_NET_PROTO_TCP);
        if (ret == 0)
            break;
        else {
            mbedtls_printf(" failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
            // mbedtls_printf("Retrying in %d seconds...\n", RETRY_DELAY);

            mbedtls_net_free(&listen_fd);
            mbedtls_net_init(&listen_fd);
            sleep(RETRY_DELAY);
        }
    }

    mbedtls_printf(" ok\n");

    mbedtls_printf("  . Setting up the SSL/TLS structure...");
    fflush(stdout);

    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    fflush(stdout);

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_printf(" ok\n");

    if (ra_tls_verify_lib) {
        /* use RA-TLS verification callback; this will overwrite CA chain set up above */
        mbedtls_printf("  . Installing RA-TLS callback ...");
        mbedtls_ssl_conf_verify(&conf, &my_verify_callback, &my_verify_callback_results);
        mbedtls_printf(" ok\n");
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

    //***$$$***
    ret = mbedtls_ssl_conf_own_cert(&conf, &clicert, &pkey);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        goto exit;
    }
    //***$$$***

    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    ret = mbedtls_ssl_set_hostname(&ssl, SERVER_NAME);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        goto exit;
    }



    mbedtls_ssl_set_bio(&ssl, &listen_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    mbedtls_printf("  . Performing the SSL/TLS handshake...");
    fflush(stdout);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n", -ret);
            mbedtls_printf(
                "  ! ra_tls_verify_callback_results:\n"
                "    attestation_scheme=%d, err_loc=%d, \n",
                my_verify_callback_results.attestation_scheme, my_verify_callback_results.err_loc);
            switch (my_verify_callback_results.attestation_scheme) {
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

            goto exit;
        }
    }

    mbedtls_printf(" ok\n");

    mbedtls_printf("  . Verifying peer X.509 certificate...");

    flags = mbedtls_ssl_get_verify_result(&ssl);
    if (flags != 0) {
        char vrfy_buf[512];
        mbedtls_printf(" failed\n");
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        mbedtls_printf("%s\n", vrfy_buf);

        /* verification failed for whatever reason, fail loudly */
        goto exit;
    } else {
        mbedtls_printf(" ok\n");
    }

    mbedtls_printf("  > Write to server:");
    fflush(stdout);

    len = sprintf((char*)buf, GET_REQUEST);

    PlayerInfo msg = PLAYER_INFO__INIT;
    msg.kii_job_id = "1920bb26-dsee-dzfw-vdsdsa14fds4"; // Example initialization
    msg.player_number = 1; // Example initialization
    
    // Buffer for serialized data
    unsigned playlen = player_info__get_packed_size(&msg);
    if (playlen == 0) {
        fprintf(stderr, "Packing or serialization error\n");
    }

    void *buff = malloc(playlen);
    if (!buff) {
        fprintf(stderr, "Memory allocation error\n");
    }

    player_info__pack(&msg, buff);
    fprintf(stderr, "Writing %d serialized bytes\n", playlen);
    mbedtls_ssl_write(&ssl, buff, playlen);

//code for packing the macshares and sending over the TLS dconnection again to the server
    SecretShare message = SECRET_SHARE__INIT;
    message.mackeyshare_2 = "f0cf6099e629fd0bda2de3f9515ab72b";
    message.mackeyshare_p = "-88222337191559387830816715872691188861";
    message.seeds = "adedefwklrewernf";
    unsigned lent = secret_share__get_packed_size(&message);
    if(lent == 0){
        fprintf(stderr, "packing or serialization error");
    }
    void *buffer = malloc(lent);
    if (!buffer) {
        fprintf(stderr, "Memory allocation error\n");
    }

    secret_share__pack(&message, buffer);
    fprintf(stderr, "Writing %d serialized bytes\n", lent);
    mbedtls_ssl_write(&ssl, buffer, lent);
//EOC for sending
// code for unpacking the files from server side and result displaying
    uint8_t secret_buffer[MAX_MSG_SIZE];
    size_t secret_len = mbedtls_ssl_read(&ssl, secret_buffer, sizeof(secret_buffer));
    
    if (secret_len <= 0) {
        fprintf(stderr, "SSL read error: %ld\n", secret_len);
    }
    SecretShare *secret_message;
    secret_message = secret_share__unpack(NULL, secret_len, secret_buffer);
    if (secret_message == NULL) {
        fprintf(stderr, "Error unpacking incoming message\n");
    }

    // Display the message's fields
    printf("Received: mackeyshare_2=%s", secret_message->mackeyshare_2); // required field
    printf("  mackeyshare_p=%s\n", secret_message->mackeyshare_p);
    printf("  seeds=%s\n", secret_message->seeds);
    // Free the unpacked message
    secret_share__free_unpacked(secret_message, NULL);
    mbedtls_ssl_close_notify(&ssl);
    exit_code = MBEDTLS_EXIT_SUCCESS;
}
exit:

#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif
    if (ra_tls_verify_lib)
        dlclose(ra_tls_verify_lib);

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
