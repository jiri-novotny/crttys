#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
  int ret = 1;
  size_t len;
  size_t i;
  FILE *fd;
  char *data;
  char header[85] = "HTTP/1.1 200 OK\r\nWWW-Authenticate: Basic realm=\"restricted\"\r\nContent-Length: ";

  if (argc > 3)
  {
    fd = fopen(argv[1], "rb");
    fseek(fd, 0, SEEK_END);
    len = ftell(fd);
    rewind(fd);
    data = (char *) malloc((len * 5) + 1024);
    if (data)
    {
      data[0] = 0;
      i = sprintf(data, "%s%ld\r\n\r\n", header, len);
      fread(data + i, 1, len, fd);
      fclose(fd);
      len += i;

      fd = fopen(argv[2], "w");
      if (fd)
      {
        fprintf(fd, "const char %s[] = {\n", argv[3]);
        for (i = 0; i < len; i++)
        {
          fprintf(fd, "0x%02x,", data[i]);
          if ((i & 15) == 15)
          {
            fprintf(fd, "\n");
          }
        }
        fprintf(fd, "\n};\n");
        fprintf(fd, "const int %sLen = %ld;\n", argv[3], len);
        fclose(fd);
      }
      free(data);
    }
    else fclose(fd);
    ret = 0;
  }

  return ret;
}
