#ifndef HEADER_SSL_H
#define HEADER_SSL_H

extern void gmssl_init(int gmssl);
extern void gmssl_set_cert2(char *cert_S_file, char *cert_E_file, char *ca_file, char *password);
extern void * gmssl_ssl_connect(int fd);
extern int gmssl_read(void *fd, void *buf, int num);
extern int gmssl_write(void *fd, void *buf, int num);
extern void gmssl_close(void *ssl_fd, int socket_fd);
extern void gmssl_destroy_ctx(void);
#endif
