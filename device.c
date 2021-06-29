#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

#include "device.h"
#include "webserver.h"

extern unsigned int wsBuildBuffer(char *response, unsigned int len, unsigned char *buffer);

static void processMessage(DeviceContext_t *dc, struct hashmap **shared)
{
  int ret;
  struct hkey hashkey;
  unsigned char out[DEVICE_BUFFER_SIZE];
  unsigned char *tmp;
  int len = 0;
  int rlen = 0;
  int session;
  WebContext_t *wc;

  ret = dc->tlen - dc->plen;
  while (ret > 3)
  {
    tmp = dc->in + dc->plen;
    len = ntohs(*((short unsigned int *) &tmp[1]));
    if (len <= ret)
    {
      switch (tmp[0])
      {
      case MSG_TYPE_REGISTER:
        strncpy(dc->deviceid, (char *) &tmp[3], 255);
        hashkey.data = dc->deviceid;
        dc->deviceidlen = strlen(dc->deviceid);
        hashkey.length = dc->deviceidlen;
        if (hashmap_get(shared[0], &hashkey) == NULL)
        {
          strncpy(dc->desc, (char *) &tmp[4 + dc->deviceidlen], 125);
          strncpy(dc->webdefault, (char *) &tmp[5 + dc->deviceidlen + strlen(dc->desc)], 31);
          if (dc->webdefault[0] == 0) strcpy(dc->webdefault, "80");
          memset(out, 0, 4);
          rlen = 4;
          printf("DEV: %s - %s (%d)\n", dc->deviceid, dc->desc, dc->sock);
          hashmap_set(shared[0], &hashkey, dc);
          if (errno != 0)
          {
            printf("DEV: id insert fail\n");
          }
          else
          {
            createList(shared[0]);
          }
        }
        else
        {
          strcpy((char *) &out[3], "XError non-unique ID");
          out[2] = strlen((char *) &out[3]);
          rlen = out[2];
        }
        break;

      case MSG_TYPE_LOGIN:
        session = tmp[4] & 3;
        hashkey.data = &dc->pending;
        hashkey.length = sizeof(int);
        wc = (WebContext_t *) hashmap_get(shared[1], &hashkey);
        if (wc)
        {
          wc->session = session;
#if ENABLE_WEB_SSL
          dc->sessions[session] = wc->ssl;
#else
          dc->sessions[session] = wc->sock;
#endif
        }
        dc->pending = -1;
        rlen = 0;
        break;

      case MSG_TYPE_LOGOUT:
#if ENABLE_WEB_SSL
        rlen = SSL_get_fd(dc->sessions[tmp[3] & 3]);
        dc->sessions[tmp[3] & 3] = NULL;
#else
        rlen = dc->sessions[tmp[3] & 3];
        dc->sessions[tmp[3] & 3] = -1;
#endif
        printf("DEV: session closed %d\n", rlen);
        hashkey.data = &rlen;
        hashkey.length = sizeof(int);
        wc = (WebContext_t *) hashmap_get(shared[1], &hashkey);
        if (wc)
        {
          hashmap_remove(shared[1], &hashkey);
          disconnectWeb(wc);
        }
        rlen = 0;
        break;

      case MSG_TYPE_TERMDATA:
        session = tmp[3] & 3;
        if (session >= 0)
        {
          rlen = wsBuildBuffer((char *) &tmp[4], len - 1, out);
#if ENABLE_WEB_SSL
          SSL_write(dc->sessions[session], out, rlen);
#else
          write(dc->sessions[session], out, rlen);
#endif
        }
        rlen = 0;
        break;

      case MSG_TYPE_WINSIZE:
        rlen = 0;
        break;

      case MSG_TYPE_CMD:
        break;

      case MSG_TYPE_HEARTBEAT:
        printf("DEV: hb\n");
        dc->uptime = ntohl(*((uint32_t *) &tmp[3]));
        out[0] = MSG_TYPE_HEARTBEAT;
        out[1] = 0;
        out[2] = 0;
        rlen = 3;
        break;

      case MSG_TYPE_FILE:
        break;

      case MSG_TYPE_WEB:
        hashkey.data = &tmp[3];
        hashkey.length = sizeof(int);
        wc = (WebContext_t *) hashmap_get(shared[1], &hashkey);
        if (wc)
        {
          printf("DEV: web %d %d\n", wc->sock, len);
#if ENABLE_WEB_SSL
          SSL_write(wc->ssl, tmp + 21, len - 18);
#else
          write(wc->sock, tmp + 21, len - 18);
#endif
        }
        else printf("DEV: not found %d\n", wc->sock);
        rlen = 0;
        break;

      default:
        rlen = 0;
        break;
      }
      if (rlen > 0)
      {
#if ENABLE_SSL
        SSL_write(dc->ssl, out, rlen);
#else
        write(dc->sock, out, rlen);
#endif
      }

      len += 3; /* header */
      ret -= len;
      if (ret == 0)
      {
        dc->tlen = 0;
        dc->plen = 0;
      }
      else
      {
        dc->plen += len;
      }
      if ((dc->plen + DEVICE_BUFFER_HALF) > DEVICE_BUFFER_SIZE)
      {
        dc->tlen -= dc->plen;
        memcpy(dc->in, dc->in + dc->plen, dc->tlen);
        dc->plen = 0;
      }
    }
    else
    {
      ret = 0;
    }
  }
  ret = 0;
}

void acceptDevice(int clientSock, SSL_CTX *sslCtx, struct hashmap *context)
{
  DeviceContext_t *dc;
  struct hkey hashkey = {0, sizeof(int)};
  
  dc = (DeviceContext_t *) calloc(1, sizeof(DeviceContext_t));
  if (dc)
  {
    dc->pending = -1;
    dc->sock = clientSock;
    if (sslCtx)
    {
      dc->ssl = SSL_new(sslCtx);
      if (dc->ssl)
      {
        SSL_set_fd(dc->ssl, dc->sock);
        SSL_accept(dc->ssl);
      }
    }
    hashkey.data = &dc->sock;
    hashmap_set(context, &hashkey, dc);
  }
  else
  {
    perror("DEV: context alloc");
    close(clientSock);
  }
}

void disconnectDevice(DeviceContext_t *dc)
{
#if ENABLE_SSL
  if (dc->ssl)
  {
    SSL_shutdown(dc->ssl);
    SSL_free(dc->ssl);
    dc->ssl = NULL;
  }
#endif
  printf("DEV: fd %d closing\n", dc->sock);
  close(dc->sock);
  free(dc);
}

void removeDisconnectDevice(DeviceContext_t *dc, struct hashmap *context, struct hashmap **shared)
{
  struct hkey hashkey;

  hashkey.data = &dc->sock;
  hashkey.length = sizeof(int);
  hashmap_remove(context, &hashkey);
  hashkey.data = dc->deviceid;
  hashkey.length = dc->deviceidlen;
  hashmap_remove(shared[0], &hashkey);
  createList(shared[0]);
  disconnectDevice(dc);
}

void handleDeviceData(DeviceContext_t *dc, struct hashmap *context, struct hashmap **shared)
{
  int ret;

  do
  {
#if ENABLE_SSL
    ret = SSL_read(dc->ssl, dc->in + dc->tlen, DEVICE_BUFFER_READ);
#else
    ret = read(dc->sock, dc->in + dc->tlen, DEVICE_BUFFER_READ);
#endif
    if (ret > 0)
    {
      dc->tlen += ret;
      if (dc->tlen >= DEVICE_BUFFER_READ)
      {
        processMessage(dc, shared);
      }
    }
    else if (ret == 0)
    {
      removeDisconnectDevice(dc, context, shared);
    }
    else
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK) 
      {
        if (dc->tlen > 0)
        {
          processMessage(dc, shared);
        }
      }
      else
      {
#if ENABLE_SSL
        printf("DEV: ssl err %d\n", SSL_get_error(dc->ssl, ret));
#else
        perror("DEV: read()");
#endif
        removeDisconnectDevice(dc, context, shared);
      }
    }
  } while (ret > 0);
}

void cleanupDevices(struct hashmap *context)
{
  struct iterator *entries;
  DeviceContext_t *dc;

  entries = hashmap_iterator(context);
  while (entries->next(entries))
  {
    dc = ((struct hentry *) entries->current)->value;
    disconnectDevice(dc);
  }
  entries->destroy(entries);
  hashmap_destroy(context);
}
