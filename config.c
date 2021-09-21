#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "log.h"
#include "jsmn.h"

typedef struct user {
  char *name;
  char *key;
} User_t;

static int jsoneq(const char *json, jsmntok_t *tok, const char *s)
{
  if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
      strncmp(json + tok->start, s, tok->end - tok->start) == 0)
  {
    return 0;
  }
  return -1;
}

int configParse(char *path, struct hashmap *users)
{
  int i;
  int r;
  size_t len;
  uint16_t version = 0;
  uint8_t inuser = 0;
  FILE *fdConf;
  char *config;
  unsigned char *tmp;
  jsmn_parser jp;
  jsmntok_t tok[128];
  User_t *u;
  struct hkey hashkey;

  fdConf = fopen(path, "r");
  if (fdConf)
  {
    fseek(fdConf, 0, SEEK_END);
    len = ftell(fdConf);
    rewind(fdConf);
    config = (char *) malloc(len);
    if (config)
    {
      fread(config, 1, len, fdConf);
      fclose(fdConf);
    }
    else
    {
      fclose(fdConf);
      return 2;
    }
  }
  else
  {
    return 1;
  }

  jsmn_init(&jp);
  r = jsmn_parse(&jp, config, len, tok, sizeof(tok) / sizeof(tok[0]));
  for (i = 1; i < r; i++)
  {
    if (inuser && (tok[i].type == JSMN_OBJECT || i == (r - 1)))
    {
      inuser--;
      if (inuser) u = (User_t *) calloc(1, sizeof(User_t));
    }

    if (jsoneq(config, &tok[i], "version") == 0)
    {
      i++;
      tmp = (unsigned char *) strndup(config + tok[i].start, tok[i].end - tok[i].start);
      sscanf((char *) tmp, "%hu", &version);
      free(tmp);
    }
    else if (jsoneq(config, &tok[i], "name") == 0)
    {
      i++;
      u->name = strndup(config + tok[i].start, tok[i].end - tok[i].start);
      if (u->key)
      {
        hashkey.data = u->key;
        hashkey.length = strlen(u->key);
        if (hashmap_set(users, &hashkey, u->name) != NULL)
        {
          writeLog(LOG_WARN, "CFG: Adding user %s failed\n", u->name);
          free(u->name);
        }
        free(u->key);
        free(u);
      }
    }
    else if (jsoneq(config, &tok[i], "key") == 0)
    {
      i++;
      u->key = strndup(config + tok[i].start, tok[i].end - tok[i].start);
      if (u->name)
      {
        hashkey.data = u->key;
        hashkey.length = strlen(u->key);
        if (hashmap_set(users, &hashkey, u->name) != NULL)
        {
          writeLog(LOG_WARN, "CFG: Adding user %s failed\n", u->name);
          free(u->name);
        }
        free(u->key);
        free(u);
      }
    }
    else if (jsoneq(config, &tok[i], "users") == 0)
    {
      u = (User_t *) calloc(1, sizeof(User_t));
      /* store size of array */
      inuser = tok[i + 1].size;
      /* jump to first item */
      i += 2;
    }
  }
  free(config);

  if (version != SUPPORTED_VERSION)
  {
    writeLog(LOG_ERR, "CFG: Unsupported config version\n");
    return 1;
  }

  return 0;
}
