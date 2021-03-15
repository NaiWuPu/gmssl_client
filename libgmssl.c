#include "stdio.h"
#include "openssl/ssl.h"
#include "openssl/pkcs12.h"
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <fcntl.h>
#include "gmssl.h"

static SSL_CTX* gmssl_ctx = NULL;
static SSL_SESSION *reuse_session = NULL;

static int load_pkcs12(BIO *in, EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca, char *password)
{
	char tpass[PEM_BUFSIZE] = {0,};
	int ret = 0;
	PKCS12 *p12;
	if (password) {
		snprintf(tpass, sizeof(tpass), "%s", password);
	}
	p12 = d2i_PKCS12_bio(in, NULL);
	if (p12 == NULL) {
		printf("Error loading PKCS12 file \n");
		goto die;
	}
	/* See if an empty password will do */
	if (!PKCS12_verify_mac(p12, tpass, strlen(tpass))) {
		printf("Mac verify error (wrong password?) in PKCS12 file \n");
		goto die;
	}
	ret = PKCS12_parse(p12, tpass, pkey, cert, ca);
die:
	PKCS12_free(p12);
	return ret;
}

void gmssl_init(int gmssl) {
	const SSL_METHOD *method;
	SSLeay_add_ssl_algorithms();
	SSL_load_error_strings();
	if (gmssl) {
		method = CNTLS_client_method();
	} else {
		method = TLS_client_method();
	}
	gmssl_ctx = SSL_CTX_new(method);
	if (!gmssl_ctx) {
		printf("gm ctx init failed\n");
	}
}

void gmssl_set_cert2(char *cert_S_file, char *cert_E_file, char *ca_file, char *password) {
	if (!gmssl_ctx) {
		printf("no gm ctx\n");
		return;
	}

	if (!cert_S_file || !cert_E_file || !ca_file) {
		return;
	}
	SSL_CTX_load_verify_locations(gmssl_ctx, ca_file, NULL);
	X509 *x = NULL;
	EVP_PKEY *pkey = NULL;
	BIO *cert;
	int ret;
	cert = BIO_new_file(cert_S_file, "rb");
	ret = load_pkcs12(cert, &pkey, &x, NULL, password);
	printf("load file %s %p ret %d\n", cert_S_file, x, ret);
	BIO_free(cert);
	if (x) {
		SSL_CTX_use_certificate(gmssl_ctx, x);
	}
	if (pkey) {
		SSL_CTX_use_PrivateKey(gmssl_ctx, pkey);
	}

	cert = BIO_new_file(cert_E_file, "rb");
	ret = load_pkcs12(cert, &pkey, &x, NULL, password);
	printf("load file %s %p ret %d\n", cert_E_file, x, ret);
	BIO_free(cert);
	if (x) {
		SSL_CTX_use_enc_certificate(gmssl_ctx, x);
	}
	if (pkey) {
		SSL_CTX_use_enc_PrivateKey(gmssl_ctx, pkey);
	}

	if (reuse_session) {
		SSL_SESSION_free(reuse_session);
		reuse_session = NULL;
	}
	return;
}

void * gmssl_ssl_connect(int fd) {
	int ret;
	SSL *ssl;
	ssl = SSL_new(gmssl_ctx);
	if (ssl == NULL) {
		printf("ssl new failed\n");
		close(fd);
		return 0;
	}
	//SSL_set_cipher_list(ssl, "SM2DHE-WITH-SMS4-SM3");
	SSL_set_fd(ssl, fd);
	if (reuse_session) {
		SSL_set_session(ssl, reuse_session);
	}	
	ret = SSL_connect(ssl);
	if (ret == -1) {
		printf("ssl connect failed ret %d %s\n", ret, SSL_state_string_long(ssl));
		ERR_print_errors_fp(stderr);
		if (reuse_session) {
			SSL_SESSION_free(reuse_session);
			reuse_session = NULL;
		}
		SSL_shutdown(ssl);
		close(fd);
		SSL_free(ssl);
		return 0;
	}
	if (!reuse_session) {
		reuse_session = SSL_get1_session(ssl);
	}
	return (void *)ssl;
}

int gmssl_read(void *fd, void *buf, int num) {
	SSL *ssl = (SSL *)fd;
	return SSL_read(ssl, buf, num);
}

int gmssl_write(void *fd, void *buf, int num) {
	SSL *ssl = (SSL *)fd;
	return SSL_write(ssl, (const void *)buf, num);
}

void gmssl_close(void *ssl_fd, int socket_fd) {
	SSL *ssl = (SSL *)ssl_fd;
	SSL_shutdown(ssl);
	close(socket_fd);
	SSL_free(ssl);
	return;
}

void gmssl_destroy_ctx(void) {
	SSL_CTX_free(gmssl_ctx);
	gmssl_ctx = NULL;
}

