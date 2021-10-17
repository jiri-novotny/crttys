#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

#include "webserver.h"
#include "device.h"
#include "log.h"

#define SWITCH_PROTO      "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: "

extern void modifySock(int sock, int rw);

static char devices[2048];
static int dlen;

int wsUpgrade(char *data)
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
  ssize_t c;

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
  c = writeWebSock(wc, buffer, keyOffset);
  writeLog(LOG_DEBUG, "WS:  write response\n");
  for (wc->sptr = 0, wc->sbuf = response, wc->sblen = len; wc->sptr < len && c > 0;)
  {
    c = writeWebSock(wc, wc->sbuf + wc->sptr, ((wc->sblen - wc->sptr) < WEB_WRITE_CHUNK) ? (wc->sblen - wc->sptr) : WEB_WRITE_CHUNK);
    if (c > 0) wc->sptr += c;
    else if (c == -1 && errno == EWOULDBLOCK)
    {
      writeLog(LOG_DEBUG, "WS:  enable epoll write\n");
      modifySock(wc->sock, 1);
    }
  }
  writeLog(LOG_DEBUG, "WS:  write response done %d\n", c);
}

static void wsSendClose(WebContext_t *wc, unsigned short reason)
{
  unsigned char buffer[4] = {0x88, 0x02, 0x00, 0x00};

  *(unsigned short *) &buffer[2] = htons(reason);

  writeWebSock(wc, buffer, 4);
}

int processWsMessage(WebContext_t *wc, struct hashmap **shared, unsigned char type, unsigned char *input, unsigned int len)
{
  char *tmp;
  char out[8];
  uint32_t j;
  uint32_t k;
  struct hkey hashkey;
  DeviceContext_t *dc;

#if WS_TEST
  wsSendBuffer(wc, type, input, len);
  return 0;
#endif

  if (0 == memcmp(input, "list", 4))
  {
    wc->index = 1;
    wsSendBuffer(wc, type, (unsigned char *) devices, dlen);
  }
  else if (0 == memcmp(input, "init:", 5))
  {
    hashkey.data = input + 5;
    hashkey.length = strlen((char *) &input[5]);
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
        removeDisconnectWeb(wc, shared[1]);
      }
    }
    else
    {
      removeDisconnectWeb(wc, shared[1]);
    }
  }
  else if (0 == memcmp(input, "data:", 5) && wc->session != -1)
  {
    k = strlen((char *) &input[5]);
    out[0] = MSG_TYPE_TERMDATA;
    *(unsigned short *) &out[1] = htons((unsigned short) k + 1);
    out[3] = wc->session;
    writeTargetSock(wc, out, 4);
    writeTargetSock(wc, input + 5, k);
  }
  else if (0 == memcmp(input, "size:", 5) && wc->session != -1)
  {
    sscanf((char *) &input[5], "%hdx%hd", (unsigned short *) &j, (unsigned short *) &k);
    out[0] = MSG_TYPE_WINSIZE;
    out[1] = 0;
    out[2] = 5;
    out[3] = wc->session;
    *(unsigned short *) &out[4] = htons((unsigned short) j);
    *(unsigned short *) &out[6] = htons((unsigned short) k);
    writeTargetSock(wc, out, 8);
  }
  else if (0 == memcmp(input, "flc", 3) && wc->session != -1)
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
  else if (0 == memcmp(input, "fls:", 4) && wc->session != -1)
  {
    writeLog(LOG_DEBUG, "WEB: file start ack\n");
    out[0] = MSG_TYPE_FILE;
    out[1] = 0;
    out[2] = 1;
    out[3] = RTTY_FILE_MSG_CANCELED;
    sscanf((char *) &input[4], "%[^;];%d", wc->filename, (int *) &wc->filesize);
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
        tmp = realloc(input, wc->filesize * 3);
        if (tmp)
        {
          writeLog(LOG_NOTICE, "WS:  file buffer realloc\n");
          input = (unsigned char *) tmp;
          wc->rblen = wc->filesize * 3;
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
  else if (0 == memcmp(input, "flu:", 4) && wc)
  {
    writeLog(LOG_DEBUG, "WS:  file upload\n");
    if (wc->file)
    {
      EVP_DecodeBlock(wc->file, (unsigned char *) input + 4, len - 4);
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
        /* FIXME */
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

int processWsData(WebContext_t *wc, struct hashmap **shared)
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
    fin = wc->rbuf[wc->plen] & 0x80;
    rsvd = wc->rbuf[wc->plen] & 0x70;
    opcode = wc->rbuf[wc->plen] & 0x0f;
    wsLen = (wc->rbuf[wc->plen + 1] & 0x7f);
    masked = (wc->rbuf[wc->plen + 1] & 0x80);
    wc->plen += 2;
    if (wsLen == 126)
    {
      memcpy((void *) &wsLen, wc->rbuf + wc->plen, 2);
      wsLen = htons(wsLen);
      wc->plen += 2;
    }
    else if (wsLen == 127)
    {
      memcpy((void *) &wsLen, wc->rbuf + wc->plen, 4);
      if (wsLen > 0)
      {
        writeLog(LOG_DEBUG, "WS:  Unsupported length\n");
        wsSendClose(wc, 1009);
        ret = 1;
        continue;
      }
      else
      {
        memcpy((void *) &wsLen, wc->rbuf + wc->plen + 4, 4);
        wsLen = htonl(wsLen);
      }
      wc->plen += 8;
    }

    if ((wc->ptr - wc->plen) >= 4 && masked)
    {
      memcpy(mask, &wc->rbuf[wc->plen], 4);
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
            wc->rbuf[wc->flen] = (char)(wc->rbuf[wc->plen] ^ mask[i & 0x3]);
          }
          wc->rbuf[wc->flen] = 0;
        }
        writeLog(LOG_DEBUG, "WS:  data packet ptr %d len %d plen %d flen %d\n", wc->ptr, wsLen, wc->plen, wc->flen);
        if (fin)
        {
          writeLog(LOG_DEBUG, "WS:  fin detected %d\n", wc->tlen);
          if (wc->tlen < 4096) writeLog(LOG_DEBUG, "\nWS:  %s\n\n", wc->rbuf);

          if (rlen)
          {
            processWsMessage(wc, shared, opcode, wc->rbuf + rlen, wc->flen - rlen);
            wc->flen = rlen;
            wc->tlen -= wsLen;
            rlen = 0;
          }
          else
          {
            processWsMessage(wc, shared, wc->type, wc->rbuf, wc->tlen);
            wc->type = 0;
            wc->tlen = 0;
            wc->flen = 0;
            if ((wc->ptr - wc->plen) == 0)
            {
              wc->ptr = wc->plen = 0;
              writeLog(LOG_DEBUG, "WS:  reset buffer\n");
              // FIXME: realloc?
            }
          }
          writeLog(LOG_DEBUG, "WS:  packet processed\n");
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
          wc->rbuf[0] = (char)(wc->rbuf[wc->plen++] ^ mask[0]);
          wc->rbuf[1] = (char)(wc->rbuf[wc->plen] ^ mask[1]);
          rlen = (int) ntohs(*(unsigned short *) &wc->rbuf[0]);
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

void createList(struct hashmap **shared)
{
  struct iterator *entries;
  DeviceContext_t *dc;
  WebContext_t *wc;
  unsigned char *data;
  int len;

  dlen = sprintf(devices, "{\"devices\":[");
  entries = hashmap_iterator(shared[0]);
  while (entries->next(entries))
  {
    dc = ((struct hentry *) entries->current)->value;
    dlen += sprintf(devices + dlen, "[\"%s\",\"%s\",\"%s\"],", dc->deviceid, dc->desc, dc->webdefault);
  }
  if (devices[dlen - 1] == ',') {
    dlen -= 1;
    devices[dlen] = 0;
  }
  strcat(devices, "]}");
  dlen += 2;
  entries->destroy(entries);

  writeLog(LOG_DEBUG, "%s\n", devices);

  data = (unsigned char *) malloc(dlen + 12);
  if (data)
  {
    len = wsBuildBuffer(0x01, devices, dlen, data);
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
