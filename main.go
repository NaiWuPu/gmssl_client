package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"
)

/*
#include "gmssl.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <fcntl.h>

void go_gmssl_set_cert(void *cert_file, int cert_file_len, void *cert_file_enc, int cert_file_len_enc, void *ca_file, int ca_file_len, void *password, int password_len) {
        char cert_file_str[1024] = {0,};
        char cert_file_str_enc[1024] = {0,};
        char ca_file_str[1024] = {0,};
        char password_str[1024] = {0,};
        memcpy(cert_file_str, cert_file, cert_file_len >= 1024 ? 1023 : cert_file_len);
        memcpy(cert_file_str_enc, cert_file_enc, cert_file_len_enc >= 1024 ? 1023 : cert_file_len_enc);
        memcpy(ca_file_str, ca_file, ca_file_len >= 1024 ? 1023 : ca_file_len);
        memcpy(password_str, password, password_len >= 1024 ? 1023 : password_len);
        gmssl_set_cert2(cert_file_str, cert_file_str_enc, ca_file_str, password_str);
}

int gmssl_socket_connect(void *server, int port) {
	int client_socket;
	struct sockaddr_in addr_server;
	client_socket = socket(AF_INET, SOCK_STREAM, 0);

	memset(&addr_server, 0, sizeof(addr_server));
	addr_server.sin_family = AF_INET;
	addr_server.sin_addr.s_addr = inet_addr((char *)server);
	addr_server.sin_port = htons(port);

	int ret;
	ret = connect(client_socket, (struct sockaddr*) &addr_server, sizeof(addr_server));
	if (ret == -1) {
			printf("connect failed\n");
			close(client_socket);
			return -1;
	}

	return client_socket;
}

void gmssl_socket_set_nonblock(int client_socket) {
	int flags = fcntl(client_socket, F_GETFL, 0);
	fcntl(client_socket, F_SETFL, flags|O_NONBLOCK);
}
*/
// #cgo LDFLAGS: -L. -lgmssl
import "C"

var Mutex sync.Mutex

func main() {
	// CA证书
	caFile := "./ca.crt"
	// 客户端证书
	certFile := "./client.p12"
	// 客户端加密证书
	certFile2 := "./client_enc.p12"
	// 证书加密密码
	XgsCertPassword := "xxxxxx"
	// 访问地址
	url := "http://10.75.2.245:443"

	_, caErr := os.Stat(caFile)
	_, certErr := os.Stat(certFile)
	_, certErr2 := os.Stat(certFile2)

	fmt.Println(caErr)
	fmt.Println(certErr)
	fmt.Println(certErr2)

	SetCert(caFile, certFile, certFile2, XgsCertPassword)
	client := CreateHttp()
	requestBody := bytes.NewReader([]byte(""))
	req, _ := http.NewRequest("POST", url, requestBody)
	req.Header.Set("Content-Type", "application/json")
	response, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	// 返回值
	respBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(respBody))
}

// 构建 https Client
func CreateHttp() *http.Client {
	client := http.Client{
		Transport: &http.Transport{
			Dial:                GmDial,
			MaxIdleConns:        8,
			MaxIdleConnsPerHost: 2,
		},
	}
	return &client
}
type GmsslAddr struct {
	addr string
}
func (sslAddr *GmsslAddr) Network() string {
	return "tcp"
}
func (sslAddr *GmsslAddr) String() string {
	return sslAddr.addr
}

type GmsslConn struct {
	socketFd  C.int
	sslFd     unsafe.Pointer
	addr      string
	connMutex sync.Mutex
	connState int
	deadline  time.Time
	ref       int
}

func (sslConn *GmsslConn) Read(b []byte) (int, error) {
	sslConn.connMutex.Lock()
	if sslConn.connState == 1 {
		sslConn.connMutex.Unlock()
		return 0, errors.New("conn closed")
	}
	sslConn.ref += 1
	sslConn.connMutex.Unlock()
	ret := C.gmssl_read(sslConn.sslFd, unsafe.Pointer(&b[0]), C.int(len(b)))
	sslConn.connMutex.Lock()
	sslConn.ref -= 1
	sslConn.connMutex.Unlock()

	fixTarget := []byte("HTTP/1.1 301")
	if int(ret) >= len(fixTarget) {
		if bytes.Equal(b[0:len(fixTarget)], fixTarget) == true {
			b[len(fixTarget)-1] = byte('7')
		}
	}
	if int(ret) <= 0 {
		return 0, errors.New("ssl read err")
	} else {
		return int(ret), nil
	}
}

func (sslConn *GmsslConn) Write(b []byte) (int, error) {
	sslConn.connMutex.Lock()
	if sslConn.connState == 1 {
		sslConn.connMutex.Unlock()
		return 0, errors.New("conn closed")
	}
	sslConn.ref += 1
	sslConn.connMutex.Unlock()
	ret := int(C.gmssl_write(sslConn.sslFd, unsafe.Pointer(&b[0]), C.int(len(b))))
	sslConn.connMutex.Lock()
	sslConn.ref -= 1
	sslConn.connMutex.Unlock()
	if ret <= 0 {
		return 0, errors.New("ssl write err")
	} else {
		return ret, nil
	}
}

func (sslConn *GmsslConn) Close() error {
	C.gmssl_socket_set_nonblock(sslConn.socketFd)
	sslConn.connMutex.Lock()
	for sslConn.ref != 0 {
		sslConn.connMutex.Unlock()
		time.Sleep(time.Duration(100) * time.Millisecond)
		sslConn.connMutex.Lock()
	}
	sslConn.connState = 1
	if sslConn.sslFd != nil {
		C.gmssl_close(sslConn.sslFd, sslConn.socketFd)
		sslConn.sslFd = nil
	}
	sslConn.connMutex.Unlock()
	return nil
}

func (sslConn *GmsslConn) LocalAddr() net.Addr {
	return nil
}

func (sslConn *GmsslConn) RemoteAddr() net.Addr {
	return &GmsslAddr{sslConn.addr}
}

func (sslConn *GmsslConn) SetDeadline(t time.Time) error {
	sslConn.deadline = t
	return nil
}

func (sslConn *GmsslConn) SetReadDeadline(t time.Time) error {
	sslConn.deadline = t
	return nil
}

func (sslConn *GmsslConn) SetWriteDeadline(t time.Time) error {
	sslConn.deadline = t
	return nil
}

func GmDial(_, addr string) (net.Conn, error) {
	var conn net.Conn
	sslConn := new(GmsslConn)
	sslConn.socketFd = 0
	sslConn.sslFd = nil
	sslConn.addr = addr
	sslConn.connState = 0
	sslConn.connMutex = sync.Mutex{}
	sslConn.ref = 0

	now := time.Now()
	sslConn.deadline = now.Add(time.Hour)

	server := strings.Split(addr, ":")[0]
	port, _ := strconv.Atoi(strings.Split(addr, ":")[1])
	socketFd := C.gmssl_socket_connect(unsafe.Pointer(&[]byte(server)[0]), C.int(port))
	if C.int(socketFd) == -1 {
		return nil, errors.New("socket create failed")
	}
	sslConn.socketFd = socketFd
	Mutex.Lock()
	sslFd := C.gmssl_ssl_connect(socketFd)
	Mutex.Unlock()
	if sslFd == nil {
		return nil, errors.New("ssl create failed")
	}
	sslConn.sslFd = sslFd

	conn = sslConn
	return conn, nil
}

func SetCert(caFile string, certFile string, certFileEnc string, certPassword string) {
	C.go_gmssl_set_cert(unsafe.Pointer(&[]byte(certFile)[0]), C.int(len(certFile)),
		unsafe.Pointer(&[]byte(certFileEnc)[0]), C.int(len(certFileEnc)),
		unsafe.Pointer(&[]byte(caFile)[0]), C.int(len(caFile)),
		unsafe.Pointer(&[]byte(certPassword)[0]), C.int(len(certPassword)))
}
