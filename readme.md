### SM2 国密客户端 拟定
###  libgmssl.c libgmssl.h是为golang提供可以使用ssl, crypto的C接口库；
```bash
gcc libgmssl.c -I./include -L./ -fPIC -shared -o libgmssl.so
go build main.go
```

###-lssl -lcrypto  这两个库是从TASSL-1.1.1b-V_1.4这里编译出来的。
https://github.com/jntass/TASSL-1.1.1b
