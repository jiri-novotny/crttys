#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

#include "device.h"
#include "webserver.h"
#include "websocket.h"
#include "log.h"

static void removeDisconnectDevice(DeviceContext_t *dc, struct hashmap *context)
{
  struct hkey hashkey;

  hashkey.data = &dc->sock;
  hashkey.length = sizeof(int);
  hashmap_remove(context, &hashkey);
  disconnectDevice(dc);
}

static void clearDisconnectDevice(DeviceContext_t *dc, struct hashmap *context, struct hashmap **shared)
{
  struct hkey hashkey;
  int i;
  int sesfd;
  WebContext_t *wc;

  hashkey.data = dc->deviceid;
  hashkey.length = dc->deviceidlen;
  hashmap_remove(shared[0], &hashkey);

  hashkey.length = sizeof(int);
  for (i = 0; i < 5; i++)
  {
#if ENABLE_WEB_SSL
    if (dc->sessions[i] != NULL)
    {
      sesfd = SSL_get_fd(dc->sessions[i]);
      dc->sessions[i] = NULL;
#else
    if (dc->sessions[i] != -1)
    {
      sesfd = dc->sessions[i];
      dc->sessions[i] = -1;
#endif
      hashkey.data = &sesfd;
      wc = (WebContext_t *) hashmap_get(shared[1], &hashkey);
      if (wc)
      {
        writeLog(LOG_NOTICE, "DEV: session closed %d\n", sesfd);
        hashmap_remove(shared[1], &hashkey);
        disconnectWeb(wc);
      }
    }
  }

  createList(shared);
  removeDisconnectDevice(dc, context);
}

static int processMessage(DeviceContext_t *dc, struct hashmap **shared)
{
  int ret = 0;
  struct hkey hashkey;
  unsigned char out[DEVICE_BUFFER_SIZE];
  unsigned char *tmp;
  int ptr = 0;
  int len = 0;
  int rlen = 0;
  int session;
  WebContext_t *wc;

  ptr = dc->tlen - dc->plen;
  while (ptr > 3)
  {
    tmp = dc->in + dc->plen;
    len = ntohs(*((short unsigned int *) &tmp[1]));
    if (len <= ptr)
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
          writeLog(LOG_NOTICE, "DEV: %s - %s (%d)\n", dc->deviceid, dc->desc, dc->sock);
          hashmap_set(shared[0], &hashkey, dc);
          if (errno != 0)
          {
            writeLog(LOG_WARN, "DEV: id insert fail\n");
          }
          else
          {
            createList(shared);
          }
        }
        else
        {
          writeLog(LOG_ERR, "DEV: id not unique\n");
          strcpy((char *) &out[3], "XError non-unique ID");
          out[2] = strlen((char *) &out[3]);
          rlen = out[2];
          ret = 1;
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
        writeLog(LOG_NOTICE, "DEV: session closed %d\n", rlen);
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
          memcpy(tmp, "cns:", 4);
          rlen = wsBuildBuffer(0x01, (char *) tmp, len + 3, out);
#if ENABLE_WEB_SSL
          rlen = SSL_write(dc->sessions[session], out, rlen);
#else
          rlen = write(dc->sessions[session], out, rlen);
#endif
          if (rlen < 0)
          {
            writeLog(LOG_WARN, "DEV: writing console failed %s\n", dc->deviceid);
          }
        }
        rlen = 0;
        break;

      case MSG_TYPE_WINSIZE:
        rlen = 0;
        break;

      case MSG_TYPE_CMD:
        writeLog(LOG_WARN, "DEV: CMD not supported\n");
        rlen = 0;
        break;

      case MSG_TYPE_HEARTBEAT:
        dc->uptime = ntohl(*((uint32_t *) &tmp[3]));
        out[0] = MSG_TYPE_HEARTBEAT;
        out[1] = 0;
        out[2] = 0;
        rlen = 3;
        break;

      case MSG_TYPE_FILE:
#if ENABLE_WEB_SSL
        rlen = SSL_get_fd(dc->sessions[tmp[3] & 3]);
#else
        rlen = dc->sessions[tmp[3] & 3];
#endif
        hashkey.data = &rlen;
        hashkey.length = sizeof(int);
        wc = (WebContext_t *) hashmap_get(shared[1], &hashkey);

        switch (tmp[4])
        {
        case RTTY_FILE_MSG_START_DOWNLOAD:
          out[0] = MSG_TYPE_FILE;
          out[1] = 0;
          out[2] = 1;
          if (wc)
          {
            wsSendBuffer(wc, 0x01, (unsigned char *)"flo", 3);
            out[3] = RTTY_FILE_MSG_REQUEST_ACCEPT;
          }
          else
          {
            out[3] = RTTY_FILE_MSG_CANCELED;
          }
          rlen = 4;
          break;
        case RTTY_FILE_MSG_INFO:
          writeLog(LOG_DEBUG, "DEV: RTTY_FILE_MSG_INFO\n");
          if (wc)
          {
            wc->fileptr = 0;
            wc->filesize = 4096 * 6; /* 16KB file + base64 */
            wc->file = (unsigned char *) malloc(wc->filesize);

            memcpy(tmp + 1, "fli:", 4);
            wsSendBuffer(wc, 0x01, tmp + 1, len + 2);
            out[0] = MSG_TYPE_FILE;
            out[1] = 0;
            out[2] = 1;
            out[3] = RTTY_FILE_MSG_DATA_ACK;
            rlen = 4;
          }
          break;
        case RTTY_FILE_MSG_DATA:
          if (wc)
          {
            if (2 == len)
            {
              if (wc->file)
              {
                memcpy(wc->file, "fld:", 4);
                rlen = EVP_EncodeBlock(wc->file + 4, wc->filehold, wc->fileptr);
                wsSendBuffer(wc, 0x01, wc->file, rlen + 4);
                free(wc->file);
                wc->file = NULL;
                wc->filesize = 0;
                wc->fileptr = 0;
              }
            }
            else
            {
              memcpy(wc->file, "flp:", 4);
              memcpy(dc->in + dc->plen + 5 - wc->fileptr, wc->filehold, wc->fileptr);
              out[0] = ((wc->fileptr + (len - 2)) % 3);
              rlen = EVP_EncodeBlock(wc->file + 4, dc->in + dc->plen + 5 - wc->fileptr, len + wc->fileptr - out[0] - 2);
              wc->fileptr = out[0];
              memcpy(wc->filehold, dc->in + dc->plen + 5 + len - wc->fileptr - 2, wc->fileptr);
              wsSendBuffer(wc, 0x01, wc->file, rlen + 4);
            }
          }
          out[0] = MSG_TYPE_FILE;
          out[1] = 0;
          out[2] = 1;
          out[3] = RTTY_FILE_MSG_DATA_ACK;
          rlen = 4;
          break;
        case RTTY_FILE_MSG_DATA_ACK:
          writeLog(LOG_DEBUG, "DEV: RTTY_FILE_MSG_DATA_ACK\n");
          if (wc)
          {
            out[0] = MSG_TYPE_FILE;
            out[3] = RTTY_FILE_MSG_DATA;
            if (wc->filesize > 0)
            {
              if (wc->filesize > DEVICE_BUFFER_FILE)
                rlen = DEVICE_BUFFER_FILE;
              else
                rlen = wc->filesize;
              memcpy(&out[4], wc->file + wc->fileptr, rlen);
              wc->filesize -= DEVICE_BUFFER_FILE;
              wc->fileptr += rlen;
              if (wc->filesize <= 0)
              {
                free(wc->file);
                wc->file = NULL;
                wc->filesize = 0;
                wc->fileptr = 0;
              }
            }
            else
            {
              rlen = 0;
              free(wc->file);
              wc->file = NULL;
              wc->filesize = 0;
              wc->fileptr = 0;
            }
            *(unsigned short *) &out[1] = htons((unsigned short) rlen + 1);
            rlen += 4;
          }
          break;
        case RTTY_FILE_MSG_CANCELED:
          writeLog(LOG_DEBUG, "DEV: RTTY_FILE_MSG_CANCELED\n");
          if (wc && wc->file)
          {
            free(wc->file);
            wc->file = NULL;
            wc->filesize = 0;
            wc->fileptr = 0;
          }
          rlen = 0;
          break;
        default:
          writeLog(LOG_ERR, "DEV: FILE not supported %02x\n", tmp[4]);
          rlen = 0;
          break;
        }
        break;

      case MSG_TYPE_WEB:
        hashkey.data = &tmp[3];
        hashkey.length = sizeof(int);
        wc = (WebContext_t *) hashmap_get(shared[1], &hashkey);
        if (wc)
        {
          wc->stat += len - 18;
          writeLog(LOG_DEBUG, "DEV: web %d %d %d\n", wc->sock, len, wc->stat);
          writeWebSock(wc, tmp + 21, len - 18);
        }
        else writeLog(LOG_NOTICE, "DEV: not found %d\n", wc->sock);
        rlen = 0;
        break;

      default:
        rlen = 0;
        break;
      }
      if (rlen > 0)
      {
        writeDevSock(dc, out, rlen);
      }

      len += 3; /* header */
      ptr -= len;
      if (ptr == 0)
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
      ptr = 0;
    }
  }
  ptr = 0;

  return ret;
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
    writeLog(LOG_ERR, "DEV: context alloc %s\n", strerror(errno));
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
  writeLog(LOG_INFO, "DEV: fd %d closing\n", dc->sock);
  close(dc->sock);
  free(dc);
}

inline ssize_t writeDevSock(DeviceContext_t *dc, const void* data, int len)
{
#if ENABLE_SSL
  return SSL_write(dc->ssl, data, len);
#else
  return write(dc->sock, data, len);
#endif
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
        if (processMessage(dc, shared))
        {
          removeDisconnectDevice(dc, context);
        }
      }
    }
    else if (ret == 0)
    {
      clearDisconnectDevice(dc, context, shared);
    }
    else
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK) 
      {
        if (dc->tlen > 0)
        {
          if (processMessage(dc, shared))
          {
            removeDisconnectDevice(dc, context);
          }
        }
      }
      else
      {
#if ENABLE_SSL
        writeLog(LOG_ERR, "DEV: ssl err %d\n", SSL_get_error(dc->ssl, ret));
#else
        perror("DEV: read()");
#endif
        clearDisconnectDevice(dc, context, shared);
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
