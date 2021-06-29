#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "net.h"
#include "device.h"
#include "webserver.h"
#include "hashmap.h"
#include "iterator.h"

static int run;
static struct hashmap *devices;
static char devverifypath[256];
static char devsslprefix[256];

struct option opt[] = {
    { "auth",           1, NULL, 'a' },
    { "dev-port",       1, NULL, 'd' },
    { "dev-key",        1, NULL, 'k' },
    { "dev-cert",       1, NULL, 'c' },
    { "dev-verify",     1, NULL, 'v' },
    { "dev-ssl-prefix", 1, NULL, 'V' },
    { "web-port",       1, NULL, 'w' },
    { "web-key",        1, NULL, 'x' },
    { "web-cert",       1, NULL, 'y' },
    { "index-page",     1, NULL, 'i' },
    { "terminal-page",  1, NULL, 't' },
    { "help",           0, NULL, 'h' },
    { NULL,             0, NULL, 0 }
};

void signalCallback(int sig)
{
  printf("signal %d\n", sig);
  if (sig == SIGINT || sig == SIGTERM)
    run = 0;
}

#define DEV_SSL_PREFIX "LEMEL-"
#if ENABLE_SSL

int SSLVerifyCallback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
  X509 *cert;
  SSL *ssl;
  int ret;
  char name[512];
  char path[512];
  char *dev;

  FILE *fp;
  struct hkey hashkey;
  DeviceContext_t *dc;

  cert = X509_STORE_CTX_get_current_cert(x509_ctx);
  if (cert)
  {
    X509_NAME_oneline(X509_get_subject_name(cert), name, 512);
    if (0 == preverify_ok)
    {
      ret = X509_STORE_CTX_get_error(x509_ctx);
      printf("DEV: verify error:num=%d:%s\n", ret, X509_verify_cert_error_string(ret));
      printf("DEV: device %s not registered\n", name);
      dev = strstr(name, devsslprefix);
      if (dev)
      {
        printf("DEV: device %s pending\n", dev);
        strcpy(path, devverifypath);
        strcat(path, dev);
        if (access(path, F_OK) != 0)
        {
          fp = fopen(path, "w");
          if (fp)
          {
            printf("storing %s\n", path);
            PEM_write_X509(fp, cert);
            fclose(fp);
          }
        }
      }
    }
    else
    {
      printf("DEV: device %s OK\n", name);
      ssl = X509_STORE_CTX_get_ex_data(x509_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
      ret = SSL_get_fd(ssl);
      hashkey.length = sizeof(int);
      hashkey.data = &ret;
      dc = (DeviceContext_t *) hashmap_get(devices, &hashkey);
      if (dc) strcpy(dc->name, strstr(name, devsslprefix));
    }
  }
  else
  {
    printf("SSL cert failed\n");
  }

  return preverify_ok;
}
#endif

int main(int argc, char **argv)
{
  int epollFd;
  int deviceSock;
  int wsSock;
  int clientSock;
  int i;
  int ret = 1;
  int sockReady;

  unsigned short port = 4433;
  unsigned short wsport = 8080;
  char basicauth[256] = "YWRtaW46QURNSU4=";
  char index[256] = "./web/index.html";
  char terminal[256] = "./web/terminal.html";
  char devcert[256];
  char devkey[256];
  char webcert[256];
  char webkey[256];
  
	struct epoll_event epollServer;
  struct epoll_event epollInput[1 + MAX_CLIENTS];

  SSL_CTX *deviceSslCtx = NULL;
  SSL_CTX *wsSslCtx = NULL;
  DeviceContext_t *dc;
  WebContext_t *wc;
  struct hashmap *websocks;
  struct hashmap *deviceids;
  struct hashmap *shared[2];
  struct hkey hashkey = {0, sizeof(int)};

  strcpy(devsslprefix, DEV_SSL_PREFIX);

  while((i = getopt_long(argc, argv, "a:d:k:c:v:V:w:x:z:i:t:h", opt, NULL)) != -1)
  {
    switch (i)
    {
      case 'a':
        strncpy(basicauth, optarg, 255);
        break;
      case 'd':
        port = atoi(optarg);
        break;
      case 'k':
        strncpy(devkey, optarg, 255);
        break;
      case 'c':
        strncpy(devcert, optarg, 255);
        break;
      case 'v':
        strncpy(devverifypath, optarg, 255);
        break;
      case 'V':
        strncpy(devsslprefix, optarg, 255);
        break;
      case 'w':
        wsport = atoi(optarg);;
        break;
      case 'x':
        strncpy(webkey, optarg, 255);
        break;
      case 'z':
        strncpy(webcert, optarg, 255);
        break;
      case 'i':
        strncpy(index, optarg, 255);
        break;
      case 't':
        strncpy(terminal, optarg, 255);
        break;
      case 'h':
        ret = 0;
        __attribute__ ((fallthrough));
      default:
        printf("USAGE: %s [options]\nOptions:\n" \
               "\t-h/--help\t\tPrint this help\n" \
               "\t-a/--auth\t\tBasic authorization for web access\n" \
               "\t-d/--dev-port\t\tSet port for device access\n" \
               "\t-k/--dev-key\t\tPath to device SSL key\n" \
               "\t-c/--dev-cert\t\tPath to device SSL cert\n" \
               "\t-v/--dev-verify\t\tPath to device verification cert dir\n" \
               "\t-V/--dev-ssl-prefix\tSet device certificate prefix\n" \
               "\t-w/--web-port\t\tSet port for web access\n" \
               "\t-x/--web-key\t\tPath to web SSL key\n" \
               "\t-z/--web-cert\t\tPath to web SSL cert\n" \
               "\t-i/--index-page\t\tPath to index page\n" \
               "\t-t/--terminal-page\tPath to terminal page\n" \
               , argv[0]);
        exit(ret);
    }
  }

  ret = 0;
  signal(SIGINT, signalCallback);
  signal(SIGTERM, signalCallback);
  signal(SIGPIPE, signalCallback);

  if ((deviceSock = openSocket(port)) == -1)
  {
    return 1;
  }

  if ((wsSock = openSocket(wsport)) == -1)
  {
    close(deviceSock);
    return 2;
  }

#if ENABLE_SSL || ENABLE_WEB_SSL
  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
#endif
#if ENABLE_SSL
  if (devkey[0] != 0 && devcert[0] != 0)
  {
    deviceSslCtx = SSL_CTX_new(TLS_server_method());
    if (!deviceSslCtx)
    {
      fprintf(stderr, "deviceSslCtx failed\n");
      close(deviceSock);
      close(wsSock);
      return 6;
    }
    SSL_CTX_set_options(deviceSslCtx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_CIPHER_SERVER_PREFERENCE);
    if (SSL_CTX_use_certificate_file(deviceSslCtx, devcert, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(deviceSslCtx, devkey, SSL_FILETYPE_PEM) <= 0)
    {
      perror("Unable to load device SSL files");
      SSL_CTX_free(deviceSslCtx);
      close(deviceSock);
      close(wsSock);
      return 7;
    }
  }
  if (devverifypath[0] != 0)
  {
    SSL_CTX_load_verify_locations(deviceSslCtx, NULL, devverifypath);
    SSL_CTX_set_verify(deviceSslCtx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, SSLVerifyCallback);
  }
#endif

#if ENABLE_WEB_SSL
  if (webkey[0] != 0 && webcert[0] != 0)
  {
    wsSslCtx = SSL_CTX_new(TLS_server_method());
    if (!wsSslCtx)
    {
      fprintf(stderr, "webSsl ctx failed\n");
      SSL_CTX_free(deviceSslCtx);
      close(deviceSock);
      close(wsSock);
      return 8;
    }
    SSL_CTX_set_options(wsSslCtx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_CIPHER_SERVER_PREFERENCE);
    if (SSL_CTX_use_certificate_file(wsSslCtx, webcert, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(wsSslCtx, webkey, SSL_FILETYPE_PEM) <= 0)
    {
      perror("Unable to load websocket SSL files");
      SSL_CTX_free(deviceSslCtx);
      SSL_CTX_free(wsSslCtx);
      close(deviceSock);
      close(wsSock);
      return 9;
    }
  }
#endif

  if (initWeb(basicauth, index, terminal) == 0)
  {
    perror("Unable to init webserver");
    SSL_CTX_free(deviceSslCtx);
    SSL_CTX_free(wsSslCtx);
    close(deviceSock);
    close(wsSock);
    return 3;
  }

  memset(&epollServer, 0, sizeof(struct epoll_event));

  epollFd = epoll_create1(0);
  epollServer.data.fd = deviceSock;
  epollServer.events = EPOLLIN;
  epoll_ctl(epollFd, EPOLL_CTL_ADD, deviceSock, &epollServer);

  epollServer.data.fd = wsSock;
  epollServer.events = EPOLLIN;
  epoll_ctl(epollFd, EPOLL_CTL_ADD, wsSock, &epollServer);

  devices = hashmap_create();
  websocks = hashmap_create();
  deviceids = hashmap_create();
  shared[0] = deviceids;
  shared[1] = websocks;
  memset(epollInput, 0, sizeof(epollInput));
  run = 1;
  while (run)
  {
    sockReady = epoll_wait(epollFd, epollInput, MAX_CLIENTS, -1);
    {
      for (i = 0; i < sockReady; i++)
      {
        if (epollInput[i].data.fd == deviceSock || epollInput[i].data.fd == wsSock)
        {
		      clientSock = acceptSocket(epollInput[i].data.fd, epollFd);
          if (clientSock)
          {
            if (epollInput[i].data.fd == deviceSock)
            {
              acceptDevice(clientSock, deviceSslCtx, devices);
            }
            else
            {
              acceptWeb(clientSock, wsSslCtx, websocks);
            }
          }
        }
        else
        {
          hashkey.data = &epollInput[i].data.fd;
          dc = (DeviceContext_t *) hashmap_get(devices, &hashkey);
          if (dc)
          {
            handleDeviceData(dc, devices, shared);
          }
          else
          {
            wc = (WebContext_t *) hashmap_get(websocks, &hashkey);
            if (wc)
            {
              handleWebData(wc, websocks, shared);
            }
            else
            {
              printf("client context not found\n");
            }
          }
        }
      }
    }
  }
  printf("normal exit\n");

  cleanupDevices(devices);
  cleanupWeb(websocks);
  close(deviceSock);
  close(wsSock);
  hashmap_destroy(deviceids);
#if ENABLE_SSL
  SSL_CTX_free(deviceSslCtx);
#endif
#if ENABLE_WEB_SSL
  SSL_CTX_free(wsSslCtx);
#endif

  return ret;
}
