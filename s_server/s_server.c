#include <stdio.h>

#include <wolfssl/ssl.h>
#include <wolfssl/options.h>
#include <sys/socket.h>

#define BACKLOG 5
#define BUFSIZE 1024

int main(int argc, char *argv[]){
    int port = 11111;
    char *certFile = argv[1];
    char *privateFile = argv[2];

    int wAddr, cSock;
    struct sockaddr_in aAddr;
    struct sockaddr_in clientAddr;
    socklen_t clientSize;
    
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL *ssl = NULL;

    int ret = 0;
    int finish = 0;
    char buf[BUFSIZE];
    int recvSize;

    wolfSSL_Init();
    if((ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method())) == NULL){
        goto err;
    }
    if(wolfSSL_CTX_use_PrivateKey_file(ctx, privateFile, SSL_FILETYPE_PEM) != 
     WOLFSSL_SUCCESS){
        goto err;
    }
    if(wolfSSL_CTX_use_certificate_file(ctx, certFile, SSL_FILETYPE_PEM)
     != WOLFSSL_SUCCESS){
        goto err;
    }
    wAddr = socket(AF_INET, SOCK_STREAM, 0);
    if(wAddr == -1){
        goto err;
    }

    memset(&aAddr, 0, sizeof(struct sockaddr_in));
    aAddr.sin_family = AF_INET;
    aAddr.sin_port = htons((unsigned short)port);
    aAddr.sin_addr.s_addr = INADDR_ANY;

    if(bind(wAddr, (const struct sockaddr *)&aAddr, sizeof(aAddr)) == -1){
        goto err;
    }
    if(listen(wAddr, BACKLOG) == -1){
        goto err;
    }
    clientSize = sizeof(clientAddr);
    while(!finish){
        if((cSock = accept(wAddr, (struct sockaddr *)&clientAddr, &clientSize)) 
         == -1){
            continue;
        }
        if((ssl = wolfSSL_new(ctx)) == NULL){ //セッション育成
            goto sslerr;
        }
        if(wolfSSL_set_fd(ssl, cSock) != WOLFSSL_SUCCESS){
            goto sslerr;
        }
        printf("before accept\n");
        if((ret = wolfSSL_accept(ssl)) != WOLFSSL_SUCCESS){ //エラー発生
            printf("%d\n",wolfSSL_get_error(ssl,ret)); //-313 : FATAL_ERROR
            goto sslerr;
        }
        printf("after accept\n");

        memset(buf, 0, BUFSIZE);
        if((recvSize = wolfSSL_read(ssl, buf, sizeof(buf)-1))>0){
            printf("Message : %s\n", buf);
            if(wolfSSL_write(ssl, buf, recvSize) != recvSize){
                printf("Failed to send message.\n");
            }
        }
        else{
            printf("Failed to recv message.\n");
        }
        if(strcmp(buf, "finish") == 0){
            finish = 1;
        }
sslerr:
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
        close(cSock);
    }
    goto success;

err:
    ret = -1;

success:
    close(wAddr);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    
    return ret;
}