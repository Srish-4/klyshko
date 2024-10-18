/* Copyright (C) 2023 Gramine contributors
 * SPDX-License-Identifier: BSD-3-Clause */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "secret_prov.h"
#define CA_CRT_PATH "ca.crt"

int main(void) {
    int ret;

    uint8_t* secret1     = NULL;
    size_t secret1_size  = 0;
    char* mac_key_share1 = NULL;
    char* mac_key_share2 = NULL;

    struct ra_tls_ctx* ctx = NULL;
    ret = secret_provision_start("dummyserver:80;localhost:4433;anotherdummy:4433", CA_CRT_PATH,
                                 &ctx);
    if (ret < 0) {
        fprintf(stderr, "[error] secret_provision_start() returned %d\n", ret);
        goto out;
    }

    ret = secret_provision_get(ctx, &secret1, &secret1_size);
    if (ret < 0) {
        fprintf(stderr, "[error] secret_provision_get() returned %d\n", ret);
        goto out;
    }
    if (!secret1_size) {
        fprintf(stderr, "[error] secret_provision_get() returned secret with size 0\n");
        goto out;
    }
    secret1[secret1_size - 1] = '\0';

    mac_key_share1 = strtok((char*)secret1, "|");  // Get the first key share
    mac_key_share2 = strtok(NULL, "|");            // Get the second key share

    // Check if both key shares were retrieved successfully
    if (!mac_key_share1 && !mac_key_share2) {
        fprintf(stderr, "[error] Failed to parse MAC key shares\n");
        goto out;
    }
    printf("--- Received secret1 = '%s', secret2 = '%s' ---\n", mac_key_share1, mac_key_share2);
    ret = 0;
out:
    free(secret1);
    secret_provision_close(ctx);
    return ret == 0 ? 0 : 1;
}
