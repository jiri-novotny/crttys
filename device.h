#ifndef DEVICE_H
#define DEVICE_H

#include <stdint.h>
#include <openssl/ssl.h>

#include "hashmap.h"

#define DEVICE_BUFFER_READ 4096
#define DEVICE_BUFFER_HALF DEVICE_BUFFER_READ*4
#define DEVICE_BUFFER_SIZE DEVICE_BUFFER_HALF*2
#define DEVICE_BUFFER_FILE DEVICE_BUFFER_READ*4

enum {
    MSG_TYPE_REGISTER = 0x00,
    MSG_TYPE_LOGIN = 0x01,
    MSG_TYPE_LOGOUT = 0x02,
    MSG_TYPE_TERMDATA = 0x03,
    MSG_TYPE_WINSIZE = 0x04,
    MSG_TYPE_CMD = 0x05,
    MSG_TYPE_HEARTBEAT = 0x06,
    MSG_TYPE_FILE = 0x07,
    MSG_TYPE_WEB = 0x08
};

enum {
    RTTY_FILE_MSG_START_DOWNLOAD,
    RTTY_FILE_MSG_INFO,
    RTTY_FILE_MSG_DATA,
    RTTY_FILE_MSG_DATA_ACK,
    RTTY_FILE_MSG_CANCELED,
    RTTY_FILE_MSG_BUSY,
    RTTY_FILE_MSG_PROGRESS,
    RTTY_FILE_MSG_REQUEST_ACCEPT,
    RTTY_FILE_MSG_NO_SPACE,
    RTTY_FILE_MSG_ERR
};

typedef struct
{
  int sock;
  unsigned char in[DEVICE_BUFFER_SIZE];
  int tlen; /* total length recv */
  int plen; /* processed length */

  uint32_t uptime;
  char name[256];
  char deviceid[256];
  uint8_t deviceidlen;
  char desc[126];
  char webdefault[32];
  int pending;
#if ENABLE_WEB_SSL
  SSL *sessions[5];
#else
  int sessions[5];
#endif
#if ENABLE_SSL
  SSL *ssl;
#else
  void *ssl;
#endif
} DeviceContext_t;

void acceptDevice(int clientSock, SSL_CTX *sslCtx, struct hashmap *context);
void disconnectDevice(DeviceContext_t *dc);
void handleDeviceData(DeviceContext_t *dc, struct hashmap *context, struct hashmap **shared);
ssize_t writeDevSock(DeviceContext_t *wc, const void* data, int len);
void cleanupDevices(struct hashmap *context);

#endif
