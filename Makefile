# Copyright (C) 2023 Gramine contributors
# SPDX-License-Identifier: BSD-3-Clause

ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
CFLAGS += -O0 -ggdb3
else
GRAMINE_LOG_LEVEL = error
CFLAGS += -O2
endif

CFLAGS += -fPIE
LDFLAGS += -pie

RA_TYPE ?= none
RA_CLIENT_SPID ?=
RA_CLIENT_LINKABLE ?= 0

# Object files for the client and server
OBJS_CLIENT = src1/client.c src1/secretsharing.pb-c.c
OBJS_SERVER = src1/server.c src1/secretsharing.pb-c.c

.PHONY: all
all: app epid

.PHONY: app
app: ssl/server.crt server.manifest.sgx server.sig client server

.PHONY: epid
epid: client_epid.manifest.sgx client_epid.sig

.PHONY: dcap
dcap: client_dcap.manifest.sgx client_dcap.sig

############################# SSL DATA DEPENDENCY #############################

# SSL data: key and x.509 self-signed certificate
ssl/server.crt: ssl/ca_config.conf
	openssl genrsa -out ssl/ca.key 2048
	openssl req -x509 -new -nodes -key ssl/ca.key -sha256 -days 1024 -out ssl/ca.crt -config ssl/ca_config.conf
	openssl genrsa -out ssl/server.key 2048
	openssl req -new -key ssl/server.key -out ssl/server.csr -config ssl/ca_config.conf
	openssl x509 -req -days 360 -in ssl/server.csr -CA ssl/ca.crt -CAkey ssl/ca.key -CAcreateserial -out ssl/server.crt

######################### CLIENT/SERVER OBJECT FILES ###########################

# # Compile the source files into object files
# src1/client.o: src1/client.c
# 	$(CC) -c $< $(CFLAGS) -o $@

# src1/server.o: src1/server.c
# 	$(CC) -c $< $(CFLAGS) -o $@

# src1/PlayerInfo.pb-c.o: src1/PlayerInfo.pb-c.c
# 	$(CC) -c $< $(CFLAGS) -o $@

######################### CLIENT/SERVER EXECUTABLES ###########################

CFLAGS += $(shell pkg-config --cflags mbedtls_gramine) \
          $(shell pkg-config --cflags ra_tls_gramine)

LDFLAGS += -ldl -Wl,--enable-new-dtags $(shell pkg-config --libs mbedtls_gramine) -lprotobuf-c

client: $(OBJS_CLIENT)
	$(CC) $(OBJS_CLIENT) $(CFLAGS) $(LDFLAGS) -o $@

server: $(OBJS_SERVER)
	$(CC) $(OBJS_SERVER) $(CFLAGS) $(LDFLAGS) -o $@

############################### SERVER MANIFEST ###############################

server.manifest: server.manifest.template server
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dra_type=$(RA_TYPE) \
		-Dra_client_spid=$(RA_CLIENT_SPID) \
		-Dra_client_linkable=$(RA_CLIENT_LINKABLE) \
		$< > $@

server.manifest.sgx server.sig: sgx_sign_server
	@:

.INTERMEDIATE: sgx_sign_server
sgx_sign_server: server.manifest
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

########################### CLIENT (DCAP) MANIFEST ############################

client_dcap.manifest: client.manifest.template client
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		$< >$@

client_dcap.manifest.sgx client_dcap.sig: sgx_sign_client_dcap
	@:

.INTERMEDIATE: sgx_sign_client_dcap
sgx_sign_client_dcap: client_dcap.manifest
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

########################### CLIENT (EPID) MANIFEST ############################

client_epid.manifest: client.manifest.template client
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		$< >$@

client_epid.manifest.sgx client_epid.sig: sgx_sign_client_epid
	@:

.INTERMEDIATE: sgx_sign_client_epid
sgx_sign_client_epid: client_epid.manifest
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

############################### CLEANUP ####################################

.PHONY: clean
clean:
	$(RM) -r \
		*.token *.sig *.manifest.sgx *.manifest server client *.so *.so.* OUTPUT

.PHONY: distclean
distclean: clean
	$(RM) -r ssl/ca.* ssl/server.*