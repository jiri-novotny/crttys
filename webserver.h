#ifndef WEBSOCKET_H
#define WEBSOCKET_H

#include <openssl/ssl.h>

#include "hashmap.h"

typedef struct
{
  int sock;
  int init;
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
} WebContext_t;

int initWeb(char *basicauth, char *devicelistpath, char *terminalpath);
void acceptWeb(int clientSock, SSL_CTX *sslCtx, struct hashmap *context);
void disconnectWeb(WebContext_t *wc);
void handleWebData(WebContext_t *wc, struct hashmap *context, struct hashmap **shared);
void createList(struct hashmap *context);
void cleanupWeb(struct hashmap *context);

#endif
