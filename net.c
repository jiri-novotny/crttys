#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "net.h"

int setSocketFlags(int sock, int f)
{
  int flags = fcntl(sock, F_GETFL, 0);

  if (flags != -1)
  {
    if (fcntl(sock, F_SETFL, flags | f) == -1)
    {
      flags = -1;
    }
    else
    {
      flags = 0;
    }
  }

  return flags;
}

int openSocket(int port)
{
  int sock = -1;
  struct sockaddr_in serverAddr;
  int sockopt = 1;

  sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock == -1)
  {
		fprintf(stderr, "socket() failed\n");
	}
  else
  {
    memset(&serverAddr, 0, sizeof(serverAddr));
  	serverAddr.sin_family = AF_INET;
  	serverAddr.sin_port = htons(port);

    if (0 != setSocketFlags(sock, O_NONBLOCK))
    {
      fprintf(stderr, "setSocketFlags() failed\n");
      close(sock);
      sock = -1;
    }

    if (sock && -1 == setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const void *) &sockopt , sizeof(int)))
    {
      fprintf(stderr, "setsockopt(SO_REUSEADDR) failed\n");
      close(sock);
      sock = -1;
    }

    if (sock && -1 == bind(sock, (struct sockaddr *) &serverAddr, sizeof(serverAddr)))
    {
      fprintf(stderr, "bind() failed\n");
      close(sock);
      sock = -1;
    }

    if (sock && -1 == listen(sock, MAX_CLIENTS))
    {
      fprintf(stderr, "listen() failed\n");
      close(sock);
      sock = -1;
    }
  }

  return sock;
}

int acceptSocket(int remoteSock, int epollFd)
{
  struct sockaddr_in clientAddr;
  socklen_t clientAddrLength;
  int clientSock;
  struct epoll_event epollClient;

  clientAddrLength = sizeof(socklen_t);
  clientSock = accept(remoteSock, (struct sockaddr *) &clientAddr, &clientAddrLength);
  if (clientSock == -1)
  {
    fprintf(stderr, "accept() failed\n");
  }
  else
  {
    memset(&epollClient, 0, sizeof(struct epoll_event));
    if (0 == setSocketFlags(clientSock, O_NONBLOCK))
    {
      epollClient.data.fd = clientSock;
      epollClient.events = EPOLLIN | EPOLLET;
      if (epoll_ctl(epollFd, EPOLL_CTL_ADD, clientSock, &epollClient) < 0)
      {
        perror("epoll_ctl EPOLL_CTL_ADD");
        close(clientSock);
        clientSock = -1;
      }
    }
    else
    { 
      fprintf(stderr, "setSocketFlags() failed\n");
      close(clientSock);
      clientSock = -1;
    }
  }

  return clientSock;
}
