#ifndef LOG_H
#define LOG_H

typedef enum {
  LOG_NONE = 0,
  LOG_ERR,
  LOG_NOTICE,
  LOG_INFO,
  LOG_DEBUG,
} LogLevel_t;

void writeLog(LogLevel_t ll, char *logline, ...);

#endif