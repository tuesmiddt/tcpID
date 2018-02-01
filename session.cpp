#include "session.hpp"
#include "caai.hpp"

TestSession::TestSession(char* target, int port) {
  setSrcInfo();
  setDstInfo(target, port);
  setIface();
  setOffloadTypes();
  disableOffload();
  blockRSTOut();
  setISS();
  makeEthLayer();
  makeIPLayer();
  test = new CAAITest(this);

  initCapture();
}


void TestSession::initCapture() {
  // std::string filterString = buildFilter();

  dev->setFilter(buildFilter());
  dev->startCapture(CAAITest::testCallBack, test);
  PCAP_SLEEP(2);
  sendSyn();
  PCAP_SLEEP(5);
  dev->stopCapture();
}

std::string TestSession::buildFilter() {
  pcpp::AndFilter f;
  std::string filterString;

  pcpp::PortFilter sportFilter(sport, pcpp::SRC_OR_DST);
  f.addFilter(&sportFilter);
  pcpp::PortFilter dportFilter(dport, pcpp::SRC_OR_DST);
  f.addFilter(&dportFilter);
  pcpp::ProtoFilter tcpFilter(pcpp::TCP);
  f.addFilter(&tcpFilter);
  pcpp::IPFilter srcIPFilter(std::string(srcIP), pcpp::SRC_OR_DST);
  f.addFilter(&srcIPFilter);
  pcpp::IPFilter dstIPFilter(std::string(dstIP), pcpp::SRC_OR_DST);
  f.addFilter(&dstIPFilter);

  f.parseToString(filterString);
  return filterString;
}

void TestSession::sendTcp(pcpp::TcpLayer *tcpLayer) {
  pcpp::Packet* p = new pcpp::Packet(100);
  p->addLayer(ethLayer);
  p->addLayer(ipLayer);
  p->addLayer(tcpLayer);
  p->computeCalculateFields();

  dev->sendPacket(p);
}

void TestSession::sendSyn() {
  pcpp::TcpLayer* tcpLayer = new pcpp::TcpLayer(sport, dport);
  pcpp::tcphdr* header = tcpLayer->getTcpHeader();
  header->sequenceNumber = iss;
  header->synFlag = 1;

  sendTcp(tcpLayer);
}

void TestSession::setIface() {
  pcpp::PcapLiveDevice* pcapDev = pcpp::PcapLiveDeviceList::getInstance()
      .getPcapLiveDeviceByIp(srcIP);
  if (pcapDev == NULL) {
    std::printf("Could not find interface with IPv4 address of %s\n", srcIP);
    exit(-1);
  }

  // before capturing packets let's print some info about this interface
  printf("Interface info:\n");
  // get interface name
  printf("   Interface name:        %s\n", pcapDev->getName());
  // get interface description
  printf("   Interface description: %s\n", pcapDev->getDesc());
  // get interface MAC address
  printf("   MAC address:           %s\n", pcapDev->getMacAddress().toString().c_str());
  // get default gateway for interface
  printf("   Default gateway:       %s\n", pcapDev->getDefaultGateway().toString().c_str());
  // get interface MTU
  printf("   Interface MTU:         %d\n", pcapDev->getMtu());
  // get DNS server if defined for this interface
  if (pcapDev->getDnsServers().size() > 0)
    printf("   DNS server:            %s\n", pcapDev->getDnsServers().at(0).toString().c_str());


  if (!pcapDev->open()) {
    std::printf("Cannot open device\n");
    exit(-1);
  }

  dev = pcapDev;
}

void TestSession::cleanUp() {
  if (dev != NULL) {
    dev->close();
    enableOffload();
  }

  clearFWRules();
}


void TestSession::setDstInfo(char* target, int port) {
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
  std::strcpy(dstIP, inet_ntoa((*(struct sockaddr_in *) (res->ai_addr)).sin_addr));
  dport = (std::uint16_t) port;

  std::strncpy(dstName, target, _SC_HOST_NAME_MAX);
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
  googleAddr.sin_port = htons(443);

  if (connect(sockfd, (struct sockaddr *) &googleAddr, sizeof(googleAddr)) < 0) {
    std::cerr << "Could not connect to google\n";
    exit(-1);
  }

  if (getsockname(sockfd, (struct sockaddr *) &myAddr, &myAddrSize) < 0) {
    std::cerr << "Could not get local ip_address\n";
    exit(-1);
  }

  close(sockfd);
  std::strcpy(srcIP, inet_ntoa(myAddr.sin_addr));
  memcpy(srcIP, inet_ntoa(myAddr.sin_addr), sizeof(srcIP));
  src = myAddr.sin_addr.s_addr;
  sport = htons(myAddr.sin_port);
}

void TestSession::setOffloadTypes() {
  offloadTypes.push_back("gro");
  offloadTypes.push_back("tso");
  offloadTypes.push_back("gso");
}

void TestSession::disableOffload() {
  for(std::string t: offloadTypes) {
    char cmd[200];
    std::sprintf(cmd, "ethtool -K %s %s off", dev->getName(), t.c_str());
    system(cmd);
  }
}

void TestSession::enableOffload() {
  for(std::string t: offloadTypes) {
    char cmd[200];
    std::sprintf(cmd, "ethtool -K %s %s on", dev->getName(), t.c_str());
    system(cmd);
  }
}

void TestSession::blockRSTOut() {
  char rule[300];
  std::sprintf(rule, "iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport %d -d %s --dport %d -j DROP",
      sport, dstIP, dport);

  if (system(rule) == 0) {
    fwRules.push_back(std::string(rule));
  }
  system("iptables -L");
}

void TestSession::clearFWRules() {
  for(std::string rule: fwRules) {
    std::printf("Clearing fw rule: %s\n", rule.c_str());
    std::string orig = "iptables -A";
    rule.replace(rule.find(orig), orig.length(), "iptables -D");
    if (system(rule.c_str()) != 0) {
      std::printf("FAILED\n");
    }
  }
}

void TestSession::setISS() {
  std::mt19937 mt_rand(time(0));
  iss = mt_rand();
}

void TestSession::makeEthLayer() {
  double arpResponseTimeMS;
  pcpp::MacAddress gwMacAddress = pcpp::NetworkUtils::getInstance().getMacAddress(
      dev->getDefaultGateway(),
      dev,
      arpResponseTimeMS);

  ethLayer = new pcpp::EthLayer(dev->getMacAddress(), gwMacAddress);
}

void TestSession::makeIPLayer() {
  ipLayer = new pcpp::IPv4Layer(
      pcpp::IPv4Address(std::string(srcIP)),
      pcpp::IPv4Address(std::string(dstIP))
    );

  ipLayer->getIPv4Header()->timeToLive = 64;
}