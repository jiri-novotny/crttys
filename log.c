#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include "log.h"

void writeLog(LogLevel_t ll, char *logline, ...)
{
  va_list args;
  char curtime[128];
  time_t raw;
  struct tm *ti;

  if (LOGLEVEL >= ll)
  {
    struct timeval tsp;
    gettimeofday(&tsp, NULL);
    raw = tsp.tv_sec;
    ti = localtime(&raw);
    strftime(curtime, 128, "%F %X", ti);
    fprintf(stdout, "%s.%06ld: ", curtime, tsp.tv_usec);
    va_start(args, logline);
    vfprintf(stdout, logline, args);
    va_end(args);
    fflush(stdout);
  }
}