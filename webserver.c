#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

#include "webserver.h"
#include "device.h"
#include "log.h"

#define SWITCH_PROTO      "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: "
#define NOT_FOUND         "HTTP/1.1 404 Not found\r\nConnection: close\r\nContent-type: text/html\r\nContent-Length: 93\r\n\r\n<html><head><title>Device proxy - Not found</title></head><body><h2>Device not connected</h2>"
#define UNAUTH            "HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-type: text/html\r\nWWW-Authenticate: Basic realm=\"restricted\"\r\nContent-Length: 95\r\n\r\n<html><head><title>Device proxy - Unauthorized</title></head><body><h2>User not authorized</h2>"

extern char webIndex[];
extern int webIndexLen;
extern char webTerminal[];
extern int webTerminalLen;

typedef struct
{
  char auth[512];
  char devices[2048];
  int deviceslen;
  char referer[256];
} ServerData_t;

static ServerData_t sd;

static void sendDeviceWebRequest(WebContext_t *wc, struct hashmap **shared, char *deviceid, uint16_t port, char *method, char *proto, char *path, char *buffer, int len)
{
  DeviceContext_t *dc;
  struct hkey hashkey = {0, strlen(deviceid)};
  char *response;
  char *tmp;

  hashkey.data = deviceid;
  dc = hashmap_get(shared[0], &hashkey);
  if (dc != NULL)
  {
    response = (char *) calloc(1, len + 28);
    if (response)
    {
      len += 24; /* 18B ctx, 4B address, 2B port */
      response[0] = MSG_TYPE_WEB;
      *(uint16_t *) &response[1] = htons((uint16_t) len);
      *(int *) &response[3] = wc->sock;
      response[15] = (uint8_t) (rand() & 0xff);
      response[16] = (uint8_t) (rand() & 0xff);
      response[17] = 0x7f;
      response[20] = 1;
      response[21] = 0x7f;
      response[24] = 1;
      *(unsigned short *) &response[25] = htons((unsigned short) port);
      tmp = strchr((char *) buffer, '\r');
      sprintf(response + 27, "%s %s %s", method, path, proto);
      strcat(response + 27, tmp);
      len += 3;
#if ENABLE_SSL
      wc->target = dc->ssl;
#else
      wc->target = dc->sock;
#endif
      wc->stat = 0;
      writeTargetSock(wc, response, len);
      free(response);
    }
    // timer when device response fail? or fix rtty conn refused
  }
  else
  {
    writeWebSock(wc, NOT_FOUND, strlen(NOT_FOUND));
  }
}

static void parseWebReqUrl(WebContext_t *wc, struct hashmap **shared, char *buffer, int len)
{
  int i;
  uint16_t port = 0;
  char method[24];
  char deviceid[256];
  char proto[24];
  char path[256] = {0};

  sscanf(buffer, "%s %s %s", method, path, proto);
  i = sscanf(path, "/%[^/]/%hu%s", deviceid, &port, path);
  if (i == 2)
  {
    *(unsigned short *) &path[0] = 0x002f;
  }

  writeLog(LOG_DEBUG, "WEB: %s %d %s (%d)\n", deviceid, port, path, i);
  if (i == 1 && port == 0)
  {
    writeLog(LOG_DEBUG, "WEB: terminal\n");
    writeWebSock(wc, webTerminal, webTerminalLen);
  }
  else if (port != 0)
  {
    writeLog(LOG_DEBUG, "WEB: proxy\n");
    sendDeviceWebRequest(wc, shared, deviceid, port, method, proto, path, (char *) buffer, len);
  }
  else
  {
    writeWebSock(wc, NOT_FOUND, strlen(NOT_FOUND));
  }
}

static void parseWebReqReferer(WebContext_t *wc, struct hashmap **shared, char *buffer, int len)
{
  char *tmp;
  int i;
  uint16_t port = 0;
  char method[24];
  char deviceid[256];
  char proto[24];
  char path[256] = {0};

  i = strlen(sd.referer);
  i -= 2;
  sd.referer[i] = 0;
  tmp = strstr((char *) buffer, sd.referer);
  sd.referer[i] = '\r';
  if (tmp)
  {
    sscanf(buffer, "%s %s %s", method, path, proto);
    tmp += i;
    i = sscanf(tmp, "%[^/]/%hu", deviceid, &port);
    if (i == 2)
    {
      writeLog(LOG_DEBUG, "WEB: proxy native %s to %s %hu %s\n", method, deviceid, port, path);
      sendDeviceWebRequest(wc, shared, deviceid, port, method, proto, path, (char *) buffer, len);
    }
    else if (i == 1 && port == 0)
    {
      writeLog(LOG_DEBUG, "WEB: terminal\n");
      writeWebSock(wc, webTerminal, webTerminalLen);
    }
    else
    {
      writeLog(LOG_DEBUG, "WEB: proxy native, device not detected\n%s", buffer);
      writeWebSock(wc, NOT_FOUND, strlen(NOT_FOUND));
    }
  }
  else
  {
    parseWebReqUrl(wc, shared, (char *) buffer, len);
  }
}

static int wsUpgrade(char *data)
{
  char *tmp;
  char keyIn[128];
  unsigned char keyOut[20];
  unsigned char keyBase[30];
  SHA_CTX ctx;
  int len = -1;

  if (strstr(data, "GET") != NULL)
  {
    tmp = strtok(data, "\n");
    while (tmp != NULL && strlen(tmp) > 1)
    {
      if (strstr(tmp, "Sec-WebSocket-Key:") != NULL)
      {
        strcpy(keyIn, tmp + strlen("Sec-WebSocket-Key: "));
        keyIn[strlen(keyIn) - 1] = 0;
        strcat(keyIn, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
      }
      tmp = strtok(NULL, "\n");
    }
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, (unsigned char *)keyIn, strlen(keyIn));
    SHA1_Final(keyOut, &ctx);
    EVP_EncodeBlock(keyBase, keyOut, SHA_DIGEST_LENGTH);
    len = sprintf((char *) data, "%s%s\r\n\r\n", SWITCH_PROTO, (char *) keyBase);
  }

  return len;
}

int initWeb()
{
  sd.referer[0] = 0;
  /* TODO: dynamic realloc based on device count */
  sprintf(sd.devices, "{\"devices\":[]}");

  return 0;
}

void acceptWeb(int clientSock, SSL_CTX *sslCtx, struct hashmap *context)
{
  WebContext_t *wc;
  struct hkey hashkey = {0, sizeof(int)};

  wc = (WebContext_t *) calloc(1, sizeof(WebContext_t));
  if (wc)
  {
    wc->blen = 4096;
    wc->buffer = (unsigned char *) malloc(wc->blen);
    if (wc->buffer)
    {
      wc->sock = clientSock;
      wc->session = -1;
      if (sslCtx)
      {
        wc->ssl = SSL_new(sslCtx);
        if (wc->ssl)
        {
          SSL_set_fd(wc->ssl, wc->sock);
          SSL_accept(wc->ssl);
        }
      }
      hashkey.data = &wc->sock;
      hashkey.length = sizeof(int);
      hashmap_set(context, &hashkey, wc);
    }
    else
    {
      perror("WEB: buffer alloc");
      close(clientSock);
    }
  }
  else
  {
    perror("WEB: context alloc");
    close(clientSock);
  }
}

void disconnectWeb(WebContext_t *wc)
{
#if ENABLE_WEB_SSL
  if (wc->ssl)
  {
    SSL_shutdown(wc->ssl);
    SSL_free(wc->ssl);
    wc->ssl = NULL;
  }
#endif
  if (wc->file) free(wc->file);
  if (wc->init) writeLog(LOG_INFO, "WS:  fd %d closing\n", wc->sock);
  else writeLog(LOG_INFO, "WEB: fd %d closing\n", wc->sock);
  close(wc->sock);
  free(wc->buffer);
  free(wc);
}

static void removeDisconnectWeb(WebContext_t *wc, struct hashmap *context)
{
  struct hkey hashkey;

  hashkey.data = &wc->sock;
  hashkey.length = sizeof(int);
  hashmap_remove(context, &hashkey);
  disconnectWeb(wc);
}

inline ssize_t writeWebSock(WebContext_t *wc, const void* data, unsigned int len)
{
#if ENABLE_WEB_SSL
    return SSL_write(wc->ssl, data, len);
#else
    return write(wc->sock, data, len);
#endif
}

inline ssize_t writeTargetSock(WebContext_t *wc, const void *data, unsigned int len)
{
#if ENABLE_SSL
  return SSL_write(wc->target, data, len);
#else
  return write(wc->target, data, len);
#endif
}

unsigned int wsBuildBuffer(unsigned char type, char *response, unsigned int len, unsigned char *buffer)
{
  unsigned int keyOffset = 0;

  if (buffer != NULL)
  {
    buffer[0] = 0x80 | type; /* fin */
    if (len >= 65536)
    {
      buffer[1] = 0x7F;
      /* we support only 4B length */
      memset(buffer + 2, 0, 4);
      *(unsigned int *) &buffer[6] = htonl(len);
      keyOffset = 10;
    }
    else if (len >= 126)
    {
      buffer[1] = 0x7E;
      *(unsigned short *) &buffer[2] = htons((unsigned short) len);
      keyOffset = 4;
    }
    else
    {
      buffer[1] = len & 0xFF;
      keyOffset = 2;
    }
    memcpy(buffer + keyOffset, response, len);
    keyOffset += len;
  }
  return keyOffset;
}

void wsSendBuffer(WebContext_t *wc, unsigned char type, unsigned char *response, unsigned int len)
{
  unsigned char buffer[12];
  unsigned int keyOffset = 0;

  buffer[0] = 0x80 | type; /* fin */
  if (len >= 65536)
  {
    buffer[1] = 0x7F;
    /* we support only 4B length */
    memset(buffer + 2, 0, 4);
    *(unsigned int *) &buffer[6] = htonl(len);
    keyOffset = 10;
  }
  else if (len >= 126)
  {
    buffer[1] = 0x7E;
    *(unsigned short *) &buffer[2] = htons((unsigned short) len);
    keyOffset = 4;
  }
  else
  {
    buffer[1] = len & 0xFF;
    keyOffset = 2;
  }
  writeWebSock(wc, buffer, keyOffset);
  const unsigned int S = 4096*16;
  ssize_t a;
  for (unsigned int i = 0; i < len;)
  {
    /* FIXME: block or EPOLLOUT */
    a = writeWebSock(wc, response + i, ((len - i) < S) ? (len - i) : S);
    if (a > 0) i += a;
    else usleep(3000);
  }
}

void wsSendClose(WebContext_t *wc, unsigned short reason)
{
  unsigned char buffer[4] = {0x88, 0x02, 0x00, 0x00};

  *(unsigned short *) &buffer[2] = htons(reason);

  writeWebSock(wc, buffer, 4);
}

int processWsMessage(WebContext_t *wc, struct hashmap *context, struct hashmap **shared)
{
  char *tmp;
  char out[8];
  uint32_t j;
  uint32_t k;
  struct hkey hashkey;
  DeviceContext_t *dc;

  if (0 == memcmp(wc->buffer, "list", 4))
  {
    wc->index = 1;
    wsSendBuffer(wc, 0x01, (unsigned char *) sd.devices, sd.deviceslen);
  }
  else if (0 == memcmp(wc->buffer, "init:", 5))
  {
    hashkey.data = wc->buffer + 5;
    hashkey.length = strlen((char *) &wc->buffer[5]);
    dc = hashmap_get(shared[0], &hashkey);
    if (dc != NULL)
    {
      if (dc->pending != -1)
      {
        hashkey.data = &dc->pending;
        hashkey.length = sizeof(int);
        if (hashmap_get(shared[1], &hashkey) == NULL)
        {
          dc->pending = -1;
        }
      }

      if (dc->pending == -1)
      {
        dc->pending = wc->sock;
        writeLog(LOG_NOTICE, "WEB: sent login pending %d (%d)\n", dc->pending, dc->sock);
        memset(out, 0 , 4);
        out[0] = MSG_TYPE_LOGIN;
#if ENABLE_SSL
        wc->target = dc->ssl;
#else
        wc->target = dc->sock;
#endif
        writeTargetSock(wc, out, 3);
      }
      else
      {
        removeDisconnectWeb(wc, context);
      }
    }
    else
    {
      removeDisconnectWeb(wc, context);
    }
  }
  else if (0 == memcmp(wc->buffer, "data:", 5) && wc->session != -1)
  {
    k = strlen((char *) &wc->buffer[5]);
    out[0] = MSG_TYPE_TERMDATA;
    *(unsigned short *) &out[1] = htons((unsigned short) k + 1);
    out[3] = wc->session;
    writeTargetSock(wc, out, 4);
    writeTargetSock(wc, wc->buffer + 5, k);
  }
  else if (0 == memcmp(wc->buffer, "size:", 5) && wc->session != -1)
  {
    sscanf((char *) &wc->buffer[5], "%hdx%hd", (unsigned short *) &j, (unsigned short *) &k);
    out[0] = MSG_TYPE_WINSIZE;
    out[1] = 0;
    out[2] = 5;
    out[3] = wc->session;
    *(unsigned short *) &out[4] = htons((unsigned short) j);
    *(unsigned short *) &out[6] = htons((unsigned short) k);
    writeTargetSock(wc, out, 8);
  }
  else if (0 == memcmp(wc->buffer, "flc", 3) && wc->session != -1)
  {
    writeLog(LOG_NOTICE, "WEB: file cancel ws\n");
    out[0] = MSG_TYPE_FILE;
    out[1] = 0;
    out[2] = 1;
    out[3] = RTTY_FILE_MSG_CANCELED;
    writeTargetSock(wc, out, 4);
    if (wc->file)
    {
      free(wc->file);
      wc->file = NULL;
      wc->filesize = 0;
    }
  }
  else if (0 == memcmp(wc->buffer, "fls:", 4) && wc->session != -1)
  {
    writeLog(LOG_DEBUG, "WEB: file start ack\n");
    out[0] = MSG_TYPE_FILE;
    out[1] = 0;
    out[2] = 1;
    out[3] = RTTY_FILE_MSG_CANCELED;
    sscanf((char *) &wc->buffer[4], "%[^;];%d", wc->filename, (int *) &wc->filesize);
    if (wc->filesize > 0)
    {
      writeLog(LOG_DEBUG, "WS:  file upload: %s (%d)\n", wc->filename, wc->filesize);
      wc->file = (unsigned char *) malloc(wc->filesize + 1);
      if (NULL == wc->file)
      {
        writeLog(LOG_WARN, "WS:  file cancel mem\n");
        writeTargetSock(wc, out, 4);
      }
      else
      {
        // check size!
        tmp = realloc(wc->buffer, wc->filesize * 3);
        if (tmp)
        {
          writeLog(LOG_NOTICE, "WS:  file buffer realloc\n");
          wc->buffer = (unsigned char *) tmp;
          wc->blen = wc->filesize * 3;
          k = strlen(wc->filename);
          *(unsigned short *) &out[1] = htons((unsigned short) 5 + k);
          out[3] = RTTY_FILE_MSG_INFO;
          *(unsigned int *) &out[4] = htonl((uint32_t) wc->filesize);
          wc->fileptr = 0;
          writeTargetSock(wc, out, 8);
          writeTargetSock(wc, wc->filename, k);
        }
        else
        {
          writeLog(LOG_WARN, "WS:  file buffer cancel mem\n");
          writeTargetSock(wc, out, 4);
        }
      }
    }
    else
    {
      writeLog(LOG_WARN, "WS:  file cancel size\n");
      writeTargetSock(wc, out, 4);
    }
  }
  else if (0 == memcmp(wc->buffer, "flu:", 4) && wc)
  {
    writeLog(LOG_DEBUG, "WS:  file upload\n");
    if (wc->file)
    {
      EVP_DecodeBlock(wc->file, (unsigned char *) wc->buffer + 4, wc->tlen - 4);
      out[0] = MSG_TYPE_FILE;
      out[3] = RTTY_FILE_MSG_DATA;
      if (wc->filesize > DEVICE_BUFFER_FILE)
        k = DEVICE_BUFFER_FILE;
      else
        k = wc->filesize;
      *(unsigned short *) &out[1] = htons((unsigned short) k + 1);
      writeTargetSock(wc, out, 4);
      writeTargetSock(wc, wc->file, k);
      wc->filesize -= DEVICE_BUFFER_FILE;
      wc->fileptr += k;
      if (wc->filesize <= 0)
      {
        free(wc->file);
        wc->file = NULL;
      }
    }
    else
    {
      writeLog(LOG_NOTICE, "WEB: file upload failed\n");
      out[0] = MSG_TYPE_FILE;
      out[1] = 0;
      out[2] = 1;
      out[3] = RTTY_FILE_MSG_CANCELED;
      writeTargetSock(wc, out, 4);
    }
  }

  return 0;
}

int processWsData(WebContext_t *wc, struct hashmap *context, struct hashmap **shared)
{
  int ret = 0;
  uint32_t i;
  unsigned char fin;
  unsigned char rsvd;
  unsigned char opcode;
  unsigned char masked;
  uint32_t wsLen;
  int rlen;
  unsigned char mask[4];

  writeLog(LOG_DEBUG, "WS:  packet ptr %d, plen %d\n", wc->ptr, wc->plen);
  while ((wc->ptr - wc->plen) >= 2 && 0 == ret)
  {
    /* backup processed length */
    rlen = wc->plen;
    fin = wc->buffer[wc->plen] & 0x80;
    rsvd = wc->buffer[wc->plen] & 0x70;
    opcode = wc->buffer[wc->plen] & 0x0f;
    wsLen = (wc->buffer[wc->plen + 1] & 0x7f);
    masked = (wc->buffer[wc->plen + 1] & 0x80);
    wc->plen += 2;
    if (wsLen == 126)
    {
      memcpy((void *) &wsLen, wc->buffer + wc->plen, 2);
      wsLen = htons(wsLen);
      wc->plen += 2;
    }
    else if (wsLen == 127)
    {
      memcpy((void *) &wsLen, wc->buffer + wc->plen, 4);
      if (wsLen > 0)
      {
        writeLog(LOG_DEBUG, "WS:  Unsupported length\n");
        wsSendClose(wc, 1009);
        ret = 1;
        continue;
      }
      else
      {
        memcpy((void *) &wsLen, wc->buffer + wc->plen + 4, 4);
        wsLen = htonl(wsLen);
      }
      wc->plen += 8;
    }

    if ((wc->ptr - wc->plen) >= 4 && masked)
    {
      memcpy(mask, &wc->buffer[wc->plen], 4);
      wc->plen += 4;
    }

    if ((wc->ptr - wc->plen) < wsLen)
    {
      writeLog(LOG_DEBUG, "WS:  packet incomplete\n\n");
      wc->plen = rlen;
      break;
    }
    else
    {
      rlen = 0;
    }

    if (rsvd || (opcode >= 0x08 && (wsLen > 125 || 0 == fin)) || (opcode == 0x08 && (wsLen == 1)) || (0 == wc->type && 0 == opcode) || (0 != wc->type && wc->type == opcode))
    {
#if WS_TEST
      writeLog(LOG_WARN, "WS:  invalid packet ");
      if (rsvd) printf("reserved bits\n");
      else if ((opcode >= 0x08 && (wsLen > 125 || 0 == fin))) printf("control length\n");
      else if ((0 == wc->type && 0 == opcode)) printf("uknown type\n");
      else if ((0 != wc->type && wc->type == opcode)) printf("opcode reset\n");
      else printf("unknown\n");
#endif
      wsSendClose(wc, 1002);
      ret = 1;
      continue;
    }

    wc->tlen += wsLen;
    switch (opcode)
    {
      case 0x01:
      case 0x02:
      case 0x09:
        writeLog(LOG_DEBUG, "WS:  new packet\n");
        if (opcode == 0x09)
        {
          opcode = 0x0A;
          if (wc->flen)
          {
            rlen = wc->flen;
          }
          else
          {
            wc->type = opcode;
          }
        }
        else
        {
          wc->type = opcode;
        }
        
        // fallthrough
      case 0x00:
        /* parse ws data */
        if (masked)
        {
          writeLog(LOG_DEBUG, "WS:  masked\n");
          for (i = 0; wc->flen < wc->tlen; i++, wc->flen++, wc->plen++)
          {
            wc->buffer[wc->flen] = (char)(wc->buffer[wc->plen] ^ mask[i & 0x3]);
          }
          wc->buffer[wc->flen] = 0;
        }
        writeLog(LOG_DEBUG, "WS:  data packet ptr %d len %d plen %d flen %d\n", wc->ptr, wsLen, wc->plen, wc->flen);
        if (fin)
        {
          writeLog(LOG_DEBUG, "WS:  fin detected %d\n", wc->tlen);
          if (wc->tlen < 4096) writeLog(LOG_DEBUG, "\nWS:  %s\n\n", wc->buffer);
#if WS_TEST
          if (rlen)
          {
            writeLog(LOG_DEBUG, "WS:  packet response 1\n");
            wsSendBuffer(wc, opcode, wc->buffer + rlen, wc->flen - rlen);
            writeLog(LOG_DEBUG, "WS:  packet response 2\n");
            wc->flen = rlen;
            wc->tlen -= wsLen;
            rlen = 0;
          }
          else
          {
            writeLog(LOG_DEBUG, "WS:  packet response 3\n");
            wsSendBuffer(wc, wc->type, wc->buffer, wc->tlen);
            writeLog(LOG_DEBUG, "WS:  packet response 4\n");
            wc->type = 0;
            wc->tlen = 0;
            wc->flen = 0;
          }
          writeLog(LOG_DEBUG, "WS:  packet processed\n");
#else
          processWsMessage(wc, context, shared);
          wc->tlen = 0;
#endif
        }
        else
        {
          writeLog(LOG_DEBUG, "WS:  fragment\n");
        }
        break;
      case 0x08:
        writeLog(LOG_DEBUG, "WS:  close packet %d\n", wsLen);
        if (wsLen == 0) wsSendClose(wc, 1000);
        else
        {
          wc->buffer[0] = (char)(wc->buffer[wc->plen++] ^ mask[0]);
          wc->buffer[1] = (char)(wc->buffer[wc->plen] ^ mask[1]);
          rlen = (int) ntohs(*(unsigned short *) &wc->buffer[0]);
          if ((rlen >= 1000 && rlen < 1004) || (rlen >= 1007 && rlen < 1012) || (rlen >= 3000 && rlen < 5000))
          {
            wsSendClose(wc, 1000);
          }
          else wsSendClose(wc, 1002);
          rlen = 0;
        }
        ret = 1;
        break;
      case 0x0A:
        writeLog(LOG_DEBUG, "WS:  pong\n");
        wc->tlen = 0;
        wc->plen += wsLen;
        if (0 == fin)
        {
          wsSendClose(wc, 1002);
          ret = 1;
        }
        break;
      default:
        writeLog(LOG_DEBUG, "WS:  unkown packet %d (%d)\n", opcode, wsLen);
        wsSendClose(wc, 1002);
        ret = 1;
        break;
    }
  }

  return ret;
}

void handleWebData(WebContext_t *wc, struct hashmap *context, struct hashmap **shared)
{
  int ret;
  char *tmp;
  char *tmpeol;
  uint32_t j;
  uint32_t k;
  struct hkey hashkey = {0, 0};

  do
  {
#if ENABLE_WEB_SSL
    ret = SSL_read(wc->ssl, wc->buffer + wc->ptr, wc->blen - wc->ptr);
#else
    ret = read(wc->sock, wc->buffer + wc->ptr, wc->blen - wc->ptr);
#endif
    if (ret > 0)
    {
      wc->ptr += ret;
      if (wc->ptr > (wc->blen / 2))
      {
        tmp = realloc(wc->buffer, wc->blen * 2);
        if (tmp)
        {
          writeLog(LOG_DEBUG, "WEB: buffer realloc ok\n");
          wc->buffer = (unsigned char *) tmp;
          wc->blen *= 2;
        }
        else
        {
          writeLog(LOG_DEBUG, "WEB: buffer realloc fail\n");
          removeDisconnectWeb(wc, context);
        }
      }
    }
    else if (ret == 0)
    {
      if (wc->session != -1)
      {
        writeLog(LOG_DEBUG, "WEB: session logout\n");
        wc->buffer[0] = MSG_TYPE_LOGOUT;
        wc->buffer[1] = 0;
        wc->buffer[2] = 1;
        wc->buffer[3] = wc->session;
        writeTargetSock(wc, wc->buffer, 4);
      }
      removeDisconnectWeb(wc, context);
    }
    else
    {
      if ((errno == EAGAIN || errno == EWOULDBLOCK) && wc->ptr > 0)
      {
        if (0 == wc->init)
        {
          wc->buffer[wc->ptr] = 0;

          if (sd.referer[0] == 0)
          {
            /* replace with custom header? eg. X-Device */
            tmp = strstr((char *) wc->buffer, "Referer: ");
            if (tmp)
            {
              tmpeol = strchr(tmp + 18, '/');
              if (tmpeol)
              {
                j = tmpeol - tmp + 1;
                k = tmp[j];
                tmp[j] = 0;
                sprintf(sd.referer, "%s\r\n", tmp);
                tmp[j] = k;
              }
            }
          }
#ifdef WS_TEST
          if (1)
#else
          tmp = strstr((char *) wc->buffer, "Authorization: Basic");
          if (tmp != NULL)
          {
            j = strchr(tmp + 21, '\n') - &tmp[21];
            memcpy(sd.auth, tmp + 21, j);
            if (sd.auth[j - 1] == '\r') j--;
            sd.auth[j] = 0;
            hashkey.length = j;
            hashkey.data = sd.auth;
          }
          if (hashmap_get(shared[2], &hashkey) != NULL)
#endif
          {
            tmp = (char *) wc->buffer;
            if (strstr(tmp, "GET / ") != NULL)
            {
              writeLog(LOG_DEBUG, "WEB: index\n");
              writeWebSock(wc, webIndex, webIndexLen);
            }
            else if (strstr(tmp, "GET /ws ") != NULL)
            {
              writeLog(LOG_DEBUG, "WEB: websocket\n");
              j = wsUpgrade((char *) wc->buffer);
              if (j)
              {
                wc->init = 1;
                writeWebSock(wc, wc->buffer, j);
              }
            }
            else if (strstr(tmp, "GET /favicon.ico ") != NULL)
            {
              writeWebSock(wc, NOT_FOUND, strlen(NOT_FOUND));
            }
            else if (strstr(tmp, sd.referer) == NULL)
            {
              parseWebReqReferer(wc, shared, (char *) wc->buffer, wc->ptr);
            }
            else
            {
              parseWebReqUrl(wc, shared, (char *) wc->buffer, wc->ptr);
            }
          }
          else
          {
            writeLog(LOG_WARN, "WEB: invalid auth %s\n", sd.auth);
            writeWebSock(wc, UNAUTH, strlen(UNAUTH));
          }
          wc->ptr = 0;
        }
        else
        {
          if (processWsData(wc, context, shared))
          {
            writeLog(LOG_DEBUG, "WS:  disconnect requested\n");
            removeDisconnectWeb(wc, context);
          }
        }
      }
      else if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
        writeLog(LOG_DEBUG, "WEB: ssl handshake for %d OK\n", wc->sock);
      }
      else
      {
#if ENABLE_WEB_SSL
        writeLog(LOG_DEBUG, "WEB: ssl err %d\n", SSL_get_error(wc->ssl, ret));
#else
        perror("WEB: read()");
#endif
        removeDisconnectWeb(wc, context);
      }
    }
  } while (ret > 0);
}

void createList(struct hashmap **shared)
{
  struct iterator *entries;
  DeviceContext_t *dc;
  WebContext_t *wc;
  unsigned char *data;
  int len;

  sd.deviceslen = sprintf(sd.devices, "{\"devices\":[");
  entries = hashmap_iterator(shared[0]);
  while (entries->next(entries))
  {
    dc = ((struct hentry *) entries->current)->value;
    sd.deviceslen += sprintf(sd.devices + sd.deviceslen, "[\"%s\",\"%s\",\"%s\"],", dc->deviceid, dc->desc, dc->webdefault);
  }
  if (sd.devices[sd.deviceslen - 1] == ',') {
    sd.deviceslen -= 1;
    sd.devices[sd.deviceslen] = 0;
  }
  strcat(sd.devices, "]}");
  sd.deviceslen += 2;
  entries->destroy(entries);

  data = (unsigned char *) malloc(sd.deviceslen + 12);
  if (data)
  {
    len = wsBuildBuffer(0x01, sd.devices, sd.deviceslen, data);
    entries = hashmap_iterator(shared[1]);
    while (entries->next(entries))
    {
      wc = ((struct hentry *) entries->current)->value;
      if (wc->index)
      {
        writeWebSock(wc, data, len);
      }
    }
    entries->destroy(entries);
    free(data);
  }
}

void cleanupWeb(struct hashmap *context)
{
  struct iterator *entries;
  WebContext_t *wc;

  entries = hashmap_iterator(context);
  while (entries->next(entries))
  {
    wc = ((struct hentry *) entries->current)->value;
    disconnectWeb(wc);
  }
  entries->destroy(entries);
  hashmap_destroy(context);
}
