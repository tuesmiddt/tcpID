#ifndef SOCKET_H
#define SOCKET_H
#include <sys/socket.h>
#endif

#ifndef CSTRING
#define CSTRING
#include <cstring>
#endif

#ifndef IOSTREAM
#define IOSTREAM
#include <iostream>
#endif

#ifndef ARPA_INET_H
#define ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifndef CSTDINT
#define CSTDINT
#include <cstdint>
#endif

#ifndef UNISTD_H
#define UNISTD_H
#include <unistd.h>
#endif

#ifndef NETDB_H
#define NETDB_H
#include <netdb.h>
#endif

#ifndef SESSION_H
#define SESSION_H

class TestSession {
	char dstName[MAXHOSTNAMELEN];

	char srcIP[INET_ADDRSTRLEN];
	char dstIP[INET_ADDRSTRLEN];

	int sockfd;

  std::uint32_t src;
  std::uint16_t sport;
  std::uint32_t dst;
  std::uint16_t dport;

public:
	TestSession();

private:
	void setSrcInfo();
}


#endif
