#ifndef WEBSOCKET_H
#define WEBSOCKET_H

#include <openssl/ssl.h>

#include "hashmap.h"

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
  /* web buffer */
  unsigned char * buffer;
  /* web buffer length */
  unsigned int blen;

  /* receiver offset */
  unsigned int ptr;
  /* total processed length */
  unsigned int plen;
  /* processed fragment length */
  unsigned int flen;
  /* total payload length */
  unsigned int tlen;

  /* web proxy payload length */
  int stat;
  char filename[256];
  unsigned char * file;
  int filesize;
  int fileptr;
  unsigned char filehold[3];
} WebContext_t;

int initWeb(void);
void acceptWeb(int clientSock, SSL_CTX *sslCtx, struct hashmap *context);
void disconnectWeb(WebContext_t *wc);
void handleWebData(WebContext_t *wc, struct hashmap *context, struct hashmap **shared);
void writeWebSock(WebContext_t *wc, const void* data, int len);
void writeTargetSock(WebContext_t *wc, const void* data, int len);
void createList(struct hashmap **shared);
void cleanupWeb(struct hashmap *context);

#endif
