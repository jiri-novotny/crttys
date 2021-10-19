#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

#include "webserver.h"
#include "websocket.h"
#include "device.h"
#include "log.h"

#define NOT_FOUND         "HTTP/1.1 404 Not found\r\nConnection: close\r\nContent-type: text/html\r\nContent-Length: 93\r\n\r\n<html><head><title>Device proxy - Not found</title></head><body><h2>Device not connected</h2>"
#define UNAUTH            "HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-type: text/html\r\nWWW-Authenticate: Basic realm=\"restricted\"\r\nContent-Length: 95\r\n\r\n<html><head><title>Device proxy - Unauthorized</title></head><body><h2>User not authorized</h2>"

extern char webIndex[];
extern int webIndexLen;
extern char webTerminal[];
extern int webTerminalLen;

typedef struct
{
  char requireAuth;
  char auth[512];
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

int initWeb(char auth, struct hashmap **shared)
{
  sd.requireAuth = auth;
  sd.referer[0] = 0;
  createList(shared);

  return 0;
}

void acceptWeb(int clientSock, SSL_CTX *sslCtx, struct hashmap *context)
{
  WebContext_t *wc;
  struct hkey hashkey = {0, sizeof(int)};

  wc = (WebContext_t *) calloc(1, sizeof(WebContext_t));
  if (wc)
  {
    wc->rblen = 4096;
    wc->rbuf = (unsigned char *) malloc(wc->rblen);
    if (wc->rbuf)
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
  free(wc->rbuf);
  free(wc);
}

void removeDisconnectWeb(WebContext_t *wc, struct hashmap *context)
{
  struct hkey hashkey;

  hashkey.data = &wc->sock;
  hashkey.length = sizeof(int);
  hashmap_remove(context, &hashkey);
  disconnectWeb(wc);
}

void handleWebData(WebContext_t *wc, struct hashmap **shared)
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
    ret = SSL_read(wc->ssl, wc->rbuf + wc->ptr, wc->rblen - wc->ptr);
#else
    ret = read(wc->sock, wc->rbuf + wc->ptr, wc->rblen - wc->ptr);
#endif
    if (ret > 0)
    {
      wc->ptr += ret;
      if (wc->ptr > (wc->rblen / 2))
      {
        tmp = realloc(wc->rbuf, wc->rblen * 2);
        if (tmp)
        {
          writeLog(LOG_DEBUG, "WEB: buffer realloc ok\n");
          wc->rbuf = (unsigned char *) tmp;
          wc->rblen *= 2;
        }
        else
        {
          writeLog(LOG_DEBUG, "WEB: buffer realloc fail\n");
          removeDisconnectWeb(wc, shared[1]);
        }
      }
    }
    else if (ret == 0)
    {
      if (wc->session != -1)
      {
        writeLog(LOG_DEBUG, "WEB: session logout\n");
        wc->rbuf[0] = MSG_TYPE_LOGOUT;
        wc->rbuf[1] = 0;
        wc->rbuf[2] = 1;
        wc->rbuf[3] = wc->session;
        writeTargetSock(wc, wc->rbuf, 4);
      }
      removeDisconnectWeb(wc, shared[1]);
    }
    else
    {
      if ((errno == EAGAIN || errno == EWOULDBLOCK) && wc->ptr > 0)
      {
        if (0 == wc->init)
        {
          wc->rbuf[wc->ptr] = 0;

          if (sd.referer[0] == 0)
          {
            /* replace with custom header? eg. X-Device */
            tmp = strstr((char *) wc->rbuf, "Referer: ");
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
          if (sd.requireAuth)
          {
            tmp = strstr((char *) wc->rbuf, "Authorization: Basic");
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
            {
              memset(sd.auth, 0, 512);
              k = 1;
            }
            else
            {
              k = 0;
            }
          }
          else k = 1;

          if (k)
          {
            tmp = (char *) wc->rbuf;
            if (strstr(tmp, "GET / ") != NULL)
            {
              writeLog(LOG_DEBUG, "WEB: index\n");
              writeWebSock(wc, webIndex, webIndexLen);
            }
            else if (strstr(tmp, "GET /ws ") != NULL)
            {
              writeLog(LOG_DEBUG, "WEB: websocket\n");
              j = wsUpgrade((char *) wc->rbuf);
              if (j)
              {
                wc->init = 1;
                writeWebSock(wc, wc->rbuf, j);
              }
            }
            else if (strstr(tmp, "GET /favicon.ico ") != NULL)
            {
              writeWebSock(wc, NOT_FOUND, strlen(NOT_FOUND));
            }
            else if (strstr(tmp, sd.referer) == NULL)
            {
              parseWebReqReferer(wc, shared, (char *) wc->rbuf, wc->ptr);
            }
            else
            {
              parseWebReqUrl(wc, shared, (char *) wc->rbuf, wc->ptr);
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
          if (processWsData(wc, shared))
          {
            writeLog(LOG_DEBUG, "WS:  disconnect requested\n");
            removeDisconnectWeb(wc, shared[1]);
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
        removeDisconnectWeb(wc, shared[1]);
      }
    }
  } while (ret > 0);
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
