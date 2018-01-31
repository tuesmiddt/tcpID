#include "session.hpp"

struct TestSession * initSession() {
  struct TestSession *session = malloc(sizeof(struct TestSession));
  session->srcIP = getsrcIP();
}

TestSession::TestSession() {
  setSrcInfo();
  setDstInfo();
}

char * setDstInfo(char *target) {
  struct addrinfo hints, *res;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_flags = AI_PASSIVE;
  hints.ai_socktype = SOCK_STREAM;

  if (getaddrinfo(target, NULL, &hints, &res) != 0) {
    std::cerr << "Could not get dst info\n";
    exit(-1);
  }

  memcpy(dstIP, inet_ntoa(res->ai_addr->))


}


void TestSession::setSrcInfo() {
  int sockfd;
  struct sockaddr_in googleAddr;
  struct sockaddr_in myAddr;
  // char *myIPAddr = (char *) malloc(INET_ADDRSTRLEN * sizeof(char));
  socklen_t myAddrSize = sizeof(myAddr);

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    std::cerr << "Could not open socket\n";
    exit(-1);
  }

  memset(&googleAddr, 0, sizeof(googleAddr));
  googleAddr.sin_family = AF_INET;
  inet_aton("8.8.8.8", &googleAddr.sin_addr);
  googleAddr.sin_port = htons(80);

  if (connect(sockfd, (struct sockaddr *) &googleAddr, sizeof(googleAddr)) < 0) {
    std::cerr << "Could not connect to google\n";
    exit(-1);
  }

  if (getsockname(sockfd, (struct sockaddr *) &myAddr, &myAddrSize) < 0) {
    std::cerr << "Could not get local ip_address\n";
    exit(-1);
  }

  close(sockfd);
  memcpy(srcIP, inet_ntoa(myAddr.sin_addr), sizeof(srcIP));
  src = myAddr.sin_addr.s_addr;

  return;
}