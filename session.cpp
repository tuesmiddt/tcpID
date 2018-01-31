#include "session.hpp"

// struct TestSession * initSession() {
//   struct TestSession *session = malloc(sizeof(struct TestSession));
//   session->srcIP = getsrcIP();
// }

TestSession::TestSession() {
  setSrcInfo();
  char target[] = "www.comp.nus.edu.sg";
  setDstInfo(target);
}

void TestSession::setDstInfo(char *target) {
  struct addrinfo hints, *res;
  struct sockaddr_in targetAddr;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_flags = AI_PASSIVE & AI_CANONNAME;
  hints.ai_socktype = SOCK_STREAM;

  if (getaddrinfo(target, NULL, &hints, &res) != 0) {
    std::cerr << "Could not get dst info\n";
    exit(-1);
  }
  std::cout << "hello";
  memcpy(dstIP, inet_ntoa((*(struct sockaddr_in *) (res->ai_addr)).sin_addr), sizeof(dstIP));
  memcpy(dstName, res->ai_canonname, sizeof(dstName));
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