#ifndef WEBSERVER_H
#define WEBSERVER_H

#include <openssl/ssl.h>

#include "hashmap.h"

#define WEB_WRITE_CHUNK       4096

typedef struct
{
  int sock;
  int init;
  int index;
  int session;
#if ENABLE_SSL
  SSL *target;
#else
  int target;
#endif
#if ENABLE_WEB_SSL
  SSL *ssl;
#else
  void *ssl;
#endif
  /* web recv buffer */
  unsigned char *rbuf;
  /* web recv buffer length */
  unsigned int rblen;
  /* web send buffer */
  unsigned char *sbuf;
  /* web send buffer length */
  unsigned int sblen;
  unsigned int sptr;

  /* receiver offset */
  unsigned int ptr;
  /* total processed length */
  unsigned int plen;
  /* processed fragment length */
  unsigned int flen;
  /* total payload length */
  unsigned int tlen;

  unsigned char type;

  /* web proxy payload length */
  int stat;
  char filename[256];
  unsigned char * file;
  int filesize;
  int fileptr;
  unsigned char filehold[3];
} WebContext_t;

int initWeb(char auth, struct hashmap **shared);
void acceptWeb(int clientSock, SSL_CTX *sslCtx, struct hashmap *context);
void disconnectWeb(WebContext_t *wc);
void removeDisconnectWeb(WebContext_t *wc, struct hashmap *context);
void handleWebData(WebContext_t *wc, struct hashmap **shared);
ssize_t writeWebSock(WebContext_t *wc, const void* data, unsigned int len);
ssize_t writeTargetSock(WebContext_t *wc, const void* data, unsigned int len);
void cleanupWeb(struct hashmap *context);

#endif
