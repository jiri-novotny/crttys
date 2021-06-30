#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

#include "webserver.h"
#include "device.h"

#define WS_BUFFER_SIZE    65536
#define SWITCH_PROTO      "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: "
#define NOT_FOUND         "HTTP/1.1 404 Not found\r\nConnection: close\r\nContent-type: text/html\r\nContent-Length: 93\r\n\r\n<html><head><title>Device proxy - Not found</title></head><body><h2>Device not connected</h2>"
#define UNAUTH            "HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-type: text/html\r\nWWW-Authenticate: Basic realm=\"restricted\"\r\nContent-Length: 95\r\n\r\n<html><head><title>Device proxy - Unauthorized</title></head><body><h2>User not authorized</h2>"
#define HEADER            "HTTP/1.1 200 OK\r\nWWW-Authenticate: Basic realm=\"restricted\"\r\nContent-Length: "
#define WS_ERR            "{\"code\":500}"

typedef struct
{
  char *devicelist;
  int devicelistlen;
  char *terminal;
  int terminallen;
  char auth[512];
  char devices[2048];
  int deviceslen;
  char referer[128];
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

  printf("WEB: %s %d %s (%d)\n", deviceid, port, path, i);
  if (i == 1 && port == 0)
  {
    printf("WEB: terminal\n");
    writeWebSock(wc, sd.terminal, sd.terminallen);
  }
  else if (port != 0)
  {
    printf("WEB: proxy\n");
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
      printf("WEB: proxy native %s to %s %hu %s\n", method, deviceid, port, path);
      sendDeviceWebRequest(wc, shared, deviceid, port, method, proto, path, (char *) buffer, len);
    }
    else if (i == 1 && port == 0)
    {
      printf("WEB: terminal\n");
      writeWebSock(wc, sd.terminal, sd.terminallen);
    }
    else
    {
      printf("WEB: proxy native, device not detected\n%s", buffer);
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

int initWeb(char *basicauth, char *devicelistpath, char *terminalpath)
{
  FILE *fd = NULL;
  size_t len;
  int ret = 0;

  sd.referer[0] = 0;
  /* TODO: dynamic realloc based on device count */
  sprintf(sd.devices, "{\"devices\":[]}");
  /* TODO: user hashmap */
  sprintf(sd.auth, "Authorization: Basic %s", basicauth);
  fd = fopen(devicelistpath, "r");
  if (fd)
  {
    fseek(fd, 0, SEEK_END);
    len = ftell(fd);
    rewind(fd);
    sd.devicelist = (char *) malloc(len + 96);
    if (sd.devicelist)
    {
      ret = sprintf(sd.devicelist, "%s%lu\r\n\r\n", HEADER, len);
      fread(sd.devicelist + ret, 1, len, fd);
      sd.devicelistlen = ret + len;
      fclose(fd);

      fd = fopen(terminalpath, "r");
      if (fd)
      {
        fseek(fd, 0, SEEK_END);
        len = ftell(fd);
        rewind(fd);
        sd.terminal = (char *) malloc(len + 96);
        if (sd.terminal)
        {
          ret = sprintf(sd.terminal, "%s%lu\r\n\r\n", HEADER, len);
          fread(sd.terminal + ret, 1, len, fd);
          sd.terminallen = ret + len;
          ret = 1;
        }
        fclose(fd);
      }
    }
    else fclose(fd);
  }

  return ret;
}

void acceptWeb(int clientSock, SSL_CTX *sslCtx, struct hashmap *context)
{
  WebContext_t *wc;
  struct hkey hashkey = {0, sizeof(int)};

  wc = (WebContext_t *) calloc(1, sizeof(WebContext_t));
  if (wc)
  {
    wc->sock = clientSock;
    wc->init = 0;
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
  printf("WEB: fd %d closing\n", wc->sock);
  close(wc->sock);
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

inline void writeWebSock(WebContext_t *wc, const void* data, int len)
{
#if ENABLE_WEB_SSL
    SSL_write(wc->ssl, data, len);
#else
    write(wc->sock, data, len);
#endif
}

inline void writeTargetSock(WebContext_t *wc, const void* data, int len)
{
#if ENABLE_SSL
    SSL_write(wc->target, data, len);
#else
    write(wc->target, data, len);
#endif
}

unsigned int wsBuildBuffer(char *response, unsigned int len, unsigned char *buffer)
{
  unsigned int keyOffset = 0;

  if (buffer != NULL)
  {
    buffer[0] = 0x81; /* fin + text frame */
    if (len >= 65535)
    {
      buffer[1] = 0x7F;
      /* we support only 4B length */
      memset(buffer + 2, 0, 4);
      *(unsigned int *) &buffer[4] = htonl(len);
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

void handleWebData(WebContext_t *wc, struct hashmap *context, struct hashmap **shared)
{
  int ret;
  unsigned char buffer[WS_BUFFER_SIZE];
  char *tmp;
  char *tmpeol;
  int len = 0;
  uint32_t j;
  uint32_t k;
  uint32_t wsLen;
  unsigned keyOffset;
  unsigned char mask[4];
  struct hkey hashkey;
  DeviceContext_t *dc;

  do
  {
#if ENABLE_WEB_SSL
    ret = SSL_read(wc->ssl, buffer + len, WS_BUFFER_SIZE);
#else
    ret = read(wc->sock, buffer + len, WS_BUFFER_SIZE);
#endif
    if (ret > 0)
    {
      len += ret;
    }
    else if (ret == 0)
    {
      if (wc->session != -1)
      {
        printf("WEB: session logout\n");
        buffer[0] = MSG_TYPE_LOGOUT;
        buffer[1] = 0;
        buffer[2] = 1;
        buffer[3] = wc->session;
        writeTargetSock(wc, buffer, 4);
      }
      removeDisconnectWeb(wc, context);
    }
    else
    {
      if ((errno == EAGAIN || errno == EWOULDBLOCK) && len > 0)
      {
        if (0 == wc->init)
        {
          buffer[len] = 0;

          if (sd.referer[0] == 0)
          {
            tmp = strstr((char *) buffer, "Referer: ");
            if (tmp)
            {
              tmpeol = strchr(tmp + 18, '/');
              j = tmpeol - tmp + 1;
              k = tmp[j];
              tmp[j] = 0;
              sprintf(sd.referer, "%s\r\n", tmp);
              tmp[j] = k;
            }
          }

          tmp = (char *) buffer;
          /* TODO: replace with multiuser auth hashmap */
          if (strstr(tmp, sd.auth) != NULL)
          {
            if (strstr(tmp, "GET / ") != NULL)
            {
              printf("WEB: index\n");
              tmp = sd.devicelist;
              len = sd.devicelistlen;
            }
            else if (strstr(tmp, "GET /ws ") != NULL)
            {
              printf("WEB: websocket\n");
              tmp = (char *) buffer;
              len = wsUpgrade(tmp);
              if (len) wc->init = 1;
            }
            else if (strstr(tmp, "GET /favicon.ico ") != NULL)
            {
              writeWebSock(wc, NOT_FOUND, strlen(NOT_FOUND));
              len = 0;
            }
            else if (strstr(tmp, sd.referer) == NULL)
            {
              parseWebReqReferer(wc, shared, (char *) buffer, len);
              len = 0;
            }
            else
            {
              parseWebReqUrl(wc, shared, (char *) buffer, len);
              len = 0;
            }
          }
          else
          {
            writeWebSock(wc, UNAUTH, strlen(UNAUTH));
            len = 0;
          }
        }
        else
        {
          if ((buffer[0] & 0x0f) == 0x08)
          {
            buffer[0] = 0x88;
            buffer[1] = 0x00;
            len = 2;
          }
          else if ((buffer[0] & 0x0f) == 0x09)
          {
            /* set pong */
            buffer[0] &= 0xF0;
            buffer[0] |= 0x0A;
            len = 2;
          }
          else if (buffer[1] > 0x80)
          {
            /* parse ws data */
            keyOffset = 2;
            wsLen = (buffer[1] - 0x80);

            if (wsLen == 126)
            {
              memcpy((void *) &wsLen, buffer + 2, 2);
              wsLen = htons(wsLen);
              keyOffset = 4;
            }
            else if (wsLen == 127)
            {
              memcpy((void *) &wsLen, buffer + 2, 4);
              if (wsLen > 0)
              {
                printf("WEB: Unsupported length\n");
                wsLen = 0;
              }
              else
              {
                memcpy((void *) &wsLen, buffer + 6, 4);
                wsLen = htonl(wsLen);
                keyOffset = 10;
              }
            }

            memcpy((void *) &mask, buffer + keyOffset, 4);
            for (j = 0, k = keyOffset + 4; j < wsLen; j++, k++)
            {
              buffer[j] = (char)(buffer[k] ^ mask[j & 0x3]);
            }
            buffer[j] = 0;

            printf("WEB: %s\n", buffer);
            /* FIXME: websock data are here */
            /* parse json */
            tmp = strstr((char *) buffer, "list");
            if (tmp)
            {
              len = wsBuildBuffer(sd.devices, sd.deviceslen, buffer);
              writeWebSock(wc, buffer, len);
              len = 0;
            }
            tmp = strstr((char *) buffer, "init:");
            if (tmp)
            {
              hashkey.data = tmp + 5;
              hashkey.length = strlen(tmp + 5);
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
                  printf("WEB: sent login pending %d (%d)\n", dc->pending, dc->sock);
                  memset(buffer, 0 , 4);
                  buffer[0] = MSG_TYPE_LOGIN;
                  len = 3;
#if ENABLE_SSL
                  wc->target = dc->ssl;
#else
                  wc->target = dc->sock;
#endif
                  writeTargetSock(wc, buffer, len);
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
              len = 0;
            }
            tmp = strstr((char *) buffer, "data:");
            if (tmp && wc->session != -1)
            {
              len = strlen(tmp + 5) + 1; /* includes session */
              tmp[1] = MSG_TYPE_TERMDATA;
              tmp[2] = 0;
              tmp[3] = len;
              tmp[4] = wc->session;
              writeTargetSock(wc, tmp + 1, len + 3);
              len = 0;
            }
            tmp = strstr((char *) buffer, "size:");
            if (tmp && wc->session != -1)
            {
              sscanf(tmp + 5, "%hdx%hd", (unsigned short *) &j, (unsigned short *) &k);
              len = 5;
              tmp[0] = MSG_TYPE_WINSIZE;
              tmp[1] = 0;
              tmp[2] = len;
              tmp[3] = wc->session;
              *(unsigned short *) &tmp[4] = htons((unsigned short) j);
              *(unsigned short *) &tmp[6] = htons((unsigned short) k);
              len += 3;
              writeTargetSock(wc, tmp, len);
              len = 0;
            }

            if (len > 0)
            {
              len = wsBuildBuffer(WS_ERR, strlen(WS_ERR), buffer);
            }
          }
          tmp = (char *) buffer;
        }
        
        if (len > 0)
        {
          writeWebSock(wc, tmp, len);
        }
      }
      else if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
        printf("WEB: ssl handshake for %d OK\n", wc->sock);
      }
      else
      {
#if ENABLE_WEB_SSL
        printf("WEB: ssl err %d\n", SSL_get_error(wc->ssl, ret));
#endif
        perror("WEB: read()");
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
  sd.deviceslen -= 1;
  if (sd.devices[sd.deviceslen] == ',') sd.devices[sd.deviceslen] = 0;
  strcat(sd.devices, "]}");
  sd.deviceslen += 2;
  entries->destroy(entries);

  data = (unsigned char *) malloc(sd.deviceslen + 14);
  if (data)
  {
    len = wsBuildBuffer(sd.devices, sd.deviceslen, data);
    entries = hashmap_iterator(shared[1]);
    while (entries->next(entries))
    {
      wc = ((struct hentry *) entries->current)->value;
      if (wc->init)
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

  if (sd.devicelist) free(sd.devicelist);
  if (sd.terminal) free(sd.terminal);
}
