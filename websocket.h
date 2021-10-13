#ifndef WEBSOCKET_H
#define WEBSOCKET_H

#include <openssl/ssl.h>

#include "webserver.h"
#include "hashmap.h"

int wsUpgrade(char *data);
int processWsData(WebContext_t *wc, struct hashmap **shared);
void createList(struct hashmap **shared);
unsigned int wsBuildBuffer(unsigned char type, char *response, unsigned int len, unsigned char *buffer);
void wsSendBuffer(WebContext_t *wc, unsigned char type, unsigned char *response, unsigned int len);
ssize_t writeWebSock(WebContext_t *wc, const void* data, unsigned int len);
ssize_t writeTargetSock(WebContext_t *wc, const void* data, unsigned int len);

#endif
