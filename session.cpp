#include "session.hpp"
#include "caai.hpp"
#include "pktutil.hpp"

TestSession::TestSession(char* target, bool dumpTCP) {
  setSrcInfo();
  setDstInfo(target);
  setIface();
  setOffloadTypes();
  disableOffload();
  blockRstOut();
  this->dumpTCP = dumpTCP;
  startTcpDump();
  setIss();
  makeEthLayer();
  makeIPLayer();
  test = new CaaiTest(this);
  sendHistory = new History();
  receiveHistory = new History();

  initTest();
}

/**
 * Starts packet capture and inits test. Polls test instance every 5 seonds
 * to check if test is completed.
 */
void TestSession::initTest() {
  dev->setFilter(buildFilter());
  dev->startCapture(TestSession::sessionCallBack, this);
  PCAP_SLEEP(2);
  test->startTest();
  while (true) {
    PCAP_SLEEP(5);
    // if (test->checkRestartTest()) {
    //   test->startTest();
    // }
    if (test->getTestDone()) {
      test->printResults();
      break;
    }
  }

  dev->stopCapture();
}

/**
 * Add packet to history.
 * @param h      history instance
 * @param packet packet to be added to history
 */
void TestSession::addToHistory(History* h, pcpp::Packet* packet) {
  h->push(packet);
}

/**
 * Start tcpdump process on separate thread.
 */
void TestSession::startTcpDump() {
  if (dumpTCP == false) {
    return;
  }
  tcpDumpThread = new std::thread(&TestSession::runTcpDump, this);
}

/**
 * Execute tcpdump command.
 */
void TestSession::runTcpDump() {
  if (dumpTCP == false) {
    return;
  }


  time_t rawtime;
  struct tm* timeinfo;
  char datetime[100];

  time(&rawtime);
  timeinfo = localtime(&rawtime);

  strftime(datetime,sizeof(datetime),"%d-%m-%Y_%I-%M-%S",timeinfo);

  char filter[400];
  std::snprintf(filter, sizeof(filter),
      "tcpdump -s 200 -w %s_%s.pcapng 'tcp and (src port %d or dst port %d) and host %s'",
      dstName.c_str(), datetime, sport, sport, dstIP.c_str());
  std::cout << filter;
  system(filter);
}

/**
 * Stop tcpdump.
 */
void TestSession::stopTcpDump() {
  if (dumpTCP == false) {
    return;
  }
  char cmd[200];
  std::snprintf(cmd, sizeof(cmd),
    "pkill tcpdump"
  );

  system(cmd);
}

/**
 * Callback to be used for each packet captured.
 * @param packet Pointer to raw packet that was captured by pcap device
 * @param dev    Pointer to pcap device
 * @param token  Pointer to current session
 */
void TestSession::sessionCallBack(pcpp::RawPacket* packet,
    pcpp::PcapLiveDevice* dev, void* token) {
  TestSession *curSession = reinterpret_cast<TestSession*>(token);

  pcpp::Packet* parsedPacket = new pcpp::Packet(packet);

  if (parsedPacket->getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress()
      .toString().compare(curSession->dstIP) == 0) {
    curSession->addToHistory(curSession->sendHistory, parsedPacket);

    // MaxAcked is updated in CAAI
    // std::uint32_t pAck = ntohl(parsedPacket
    //     ->getLayerOfType<pcpp::TcpLayer>()->getTcpHeader()->ackNumber);
    // if (pAck > curSession->maxAcked)
    //   curSession->maxAcked = pAck;
  } else if (parsedPacket->getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress()
      .toString().compare(curSession->srcIP) == 0) {
    // packet is incoming
    curSession->addToHistory(curSession->receiveHistory, parsedPacket);

    curSession->test->testCallBack(parsedPacket);
  }
}

/**
 * Update highest seq number seen from target host.
 * @param prev Pointer to tcp layer of received packet.
 */
void TestSession::updateMaxSeen(pcpp::TcpLayer* prev) {
  std::uint32_t rcvSeq = ntohl(prev->getTcpHeader()->sequenceNumber);

  if (rcvSeq > maxSeen) {
    maxSeen = rcvSeq;
    if (irs == 0) {
      irs = rcvSeq;
    }
  }
}

/**
 * Send packet (inject to device) immediately.
 * @param tcpLayer     Pointer to tcp layer. Essentially contains just a
 *                     populated tcp header.
 * @param payloadLayer Pointer to payload layer. This is used here as a wrapper
 *                     around whatever data we want to send.
 */
void TestSession::sendTcp(pcpp::TcpLayer* tcpLayer, pcpp::Layer* payloadLayer) {
  pcpp::Packet* p = new pcpp::Packet(100);
  // Copy constructors used because layers can only be sent once.
  pcpp::EthLayer* curEthLayer = new pcpp::EthLayer(*ethLayer);
  pcpp::IPv4Layer* curIPLayer = new pcpp::IPv4Layer(*ipLayer);
  p->addLayer(curEthLayer);
  p->addLayer(curIPLayer);
  p->addLayer(tcpLayer);
  if (payloadLayer != NULL) {
    p->addLayer(payloadLayer);
  }

  p->computeCalculateFields();
  dev->sendPacket(p);

  // delete payloadLayer;
  // delete tcpLayer;
  // delete curIPLayer;
  // delete curEthLayer;
  // delete p;
}

/**
 * Resend last sent packet immediately.
 */
void TestSession::resendLastPacket() {
  pcpp::Packet* p = sendHistory->getMax();
  dev->sendPacket(p);
}

/**
 * Get last received packet from target host.
 * @return Last received packet, retrievd from history.
 */
pcpp::Packet* TestSession::getLastReceivedPacket() {
  return receiveHistory->getMax();
}

/**
 * Build filter string for packet capture.
 * @return filter string.
 */
std::string TestSession::buildFilter() {
  // AndFilter so all subsequent conditions must be satisfied
  pcpp::AndFilter f;
  std::string filterString;

  // src or dst port == sport
  pcpp::PortFilter sportFilter(sport, pcpp::SRC_OR_DST);
  f.addFilter(&sportFilter);
  // src or dst port == dport
  pcpp::PortFilter dportFilter(dport, pcpp::SRC_OR_DST);
  f.addFilter(&dportFilter);
  // prot == tcp
  pcpp::ProtoFilter tcpFilter(pcpp::TCP);
  f.addFilter(&tcpFilter);
  // src or dst ip == srcIP
  pcpp::IPFilter srcIPFilter(srcIP, pcpp::SRC_OR_DST);
  f.addFilter(&srcIPFilter);
  // src or dst ip == dstIP
  pcpp::IPFilter dstIPFilter(dstIP, pcpp::SRC_OR_DST);
  f.addFilter(&dstIPFilter);

  f.parseToString(filterString);
  return filterString;
}

/**
 * Sets and opens the capture interface. Searches among detected interfaces
 * for one that uses the detected srcIP.
 */
void TestSession::setIface() {
  pcpp::PcapLiveDevice* pcapDev = pcpp::PcapLiveDeviceList::getInstance()
      .getPcapLiveDeviceByIp(srcIP.c_str());
  if (pcapDev == NULL) {
    // This hsould never happen.
    std::printf("Could not find interface with IPv4 address of %s\n",
        srcIP.c_str());
    exit(-1);
  }

  // before capturing packets let's print some info about this interface
  printf("Interface info:\n");
  // get interface name
  printf("   Interface name:        %s\n", pcapDev->getName());
  // get interface description
  printf("   Interface description: %s\n", pcapDev->getDesc());
  // get interface MAC address
  printf("   MAC address:           %s\n",
      pcapDev->getMacAddress().toString().c_str());
  // get default gateway for interface
  printf("   Default gateway:       %s\n",
      pcapDev->getDefaultGateway().toString().c_str());
  // get interface MTU
  printf("   Interface MTU:         %d\n", pcapDev->getMtu());
  // get DNS server if defined for this interface
  if (pcapDev->getDnsServers().size() > 0)
    printf("   DNS server:            %s\n",
        pcapDev->getDnsServers().at(0).toString().c_str());

  if (!pcapDev->open()) {
    std::printf("Cannot open device\n");
    exit(-1);
  }

  dev = pcapDev;
}

/**
 * Cleanup firewall rules and close capture device.
 * Re-enable tcp offloading.
 * Stop tcpdump process.
 */
void TestSession::cleanUp() {
  if (dev != NULL) {
    dev->close();
    enableOffload();
  }
  test->cleanUp();
  stopTcpDump();
  clearFWRules();
}

/**
 * Sets destination information. Populates the following fields:
 * - dstIP xxx.xxx.xxx.xxx
 * - dst as uint32
 * - dport in host byte order
 * - dstName www.hostname.com
 * - dstFile path/to/target
 * @param target Raw target url in the format https://www.hostname.com/path/to/target
 */
void TestSession::setDstInfo(char* target) {
  char* copy = strdup(target);
  char* token;
  char** processed =  new char*[3];
  const char* delim = "/"; // Iterate over strings by '/'
  token = strtok(target, delim);

  for (int i = 0; i < 3; i++) {
    if (token == NULL) {
      break;
    }
    processed[i] = token;
    token = strtok(NULL, delim);
  }

  // Assume only standard http or https ports
  if (strcmp(processed[0], "https:") == 0) {
    dport = 443;
  } else {
    dport = 80;
  }

  dstName = std::string(processed[1]);

  if (processed[2] != NULL) {
    dstFile = std::string(strstr(copy, processed[2]));
  }

  struct addrinfo hints, *res;
  struct sockaddr_in targetAddr;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_flags = AI_PASSIVE & AI_CANONNAME;
  hints.ai_socktype = SOCK_STREAM;

  if (getaddrinfo(dstName.c_str(), NULL, &hints, &res) != 0) {
    std::cerr << "Could not get dst info\n";
    exit(-1);
  }
  targetAddr = *(reinterpret_cast<struct sockaddr_in*>(res->ai_addr));
  dstIP = std::string(inet_ntoa(targetAddr.sin_addr));
  dst = ntohl(targetAddr.sin_addr.s_addr);
}

/**
 * Sets source information by establishing a connection with Google DNS server
 * and checking connection properties. Populates the following fields:
 * - srcIP xxx.xxx.xxx.xxx
 * - src as uint32
 * - sport is random unused port
 */
void TestSession::setSrcInfo() {
  int sockfd;
  struct sockaddr_in googleAddr;
  struct sockaddr_in myAddr;
  socklen_t myAddrSize = sizeof(myAddr);

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    std::cerr << "Could not open socket\n";
    exit(-1);
  }

  memset(&googleAddr, 0, sizeof(googleAddr));
  googleAddr.sin_family = AF_INET;
  inet_aton("8.8.8.8", &googleAddr.sin_addr);
  googleAddr.sin_port = htons(443);

  if (connect(sockfd,
      reinterpret_cast<struct sockaddr*>(&googleAddr),
      sizeof(googleAddr)) < 0) {
    std::cerr << "Could not connect to google\n";
    exit(-1);
  }

  if (getsockname(sockfd,
      reinterpret_cast<struct sockaddr*>(&myAddr),
      &myAddrSize) < 0) {
    std::cerr << "Could not get local ip_address\n";
    exit(-1);
  }

  close(sockfd);
  srcIP = std::string(inet_ntoa(myAddr.sin_addr));
  src = ntohl(myAddr.sin_addr.s_addr);
  sport = ntohs(myAddr.sin_port);
}

/**
 * Populates Vector containg types of offload to disable
 */
void TestSession::setOffloadTypes() {
  offloadTypes.push_back("gro");
  offloadTypes.push_back("tso");
  offloadTypes.push_back("gso");
}

/**
 * Execute command to disable offload types stored in offloadTypes
 */
void TestSession::disableOffload() {
  for (std::string t : offloadTypes) {
    char cmd[200];
    std::snprintf(cmd, sizeof(cmd),
        "ethtool -K %s %s off", dev->getName(), t.c_str());
    system(cmd);
  }
}

/**
 * Execute command to enable offload types
 */
void TestSession::enableOffload() {
  for (std::string t : offloadTypes) {
    char cmd[200];
    std::snprintf(cmd, sizeof(cmd),
        "ethtool -K %s %s on", dev->getName(), t.c_str());
    system(cmd);
  }
}

/**
 * Block RST packets sent by OS in response to experiment packets (since we do
 * not actually open a connection on the source port we use). Stores fw rule.
 */
void TestSession::blockRstOut() {
  char rule[300];
  std::snprintf(rule, sizeof(rule),
      "iptables -A OUTPUT -p tcp --tcp-flags RST RST"
      " --sport %d -d %s --dport %d -j DROP",
      sport, dstIP.c_str(), dport);

  if (system(rule) == 0) {
    fwRules.push_back(std::string(rule));
  }
  system("iptables -L -n");
}

/**
 * Clear fw rules that we have set.
 */
void TestSession::clearFWRules() {
  for (std::string rule : fwRules) {
    std::printf("Clearing fw rule: %s\n", rule.c_str());
    std::string orig = "iptables -A";
    rule.replace(rule.find(orig), orig.length(), "iptables -D");
    if (system(rule.c_str()) != 0) {
      std::printf("FAILED\n");
    }
  }
}

/**
 * Pick a random initial sequence number
 */
void TestSession::setIss() {
  std::mt19937 mt_rand(time(0));
  iss = mt_rand();
  seq = iss;
}

/**
 * Create a populated ethernet layer to the default gateway.
 */
void TestSession::makeEthLayer() {
  double arpResponseTimeMS;
  pcpp::MacAddress gwMacAddress = pcpp::NetworkUtils::getInstance()
      .getMacAddress(
          dev->getDefaultGateway(),
          dev,
          arpResponseTimeMS);

  ethLayer = new pcpp::EthLayer(dev->getMacAddress(), gwMacAddress);
}

/**
 * Create a poulated IP layer to the destination machine.
 */
void TestSession::makeIPLayer() {
  ipLayer = new pcpp::IPv4Layer(
      pcpp::IPv4Address(srcIP),
      pcpp::IPv4Address(dstIP));

  ipLayer->getIPv4Header()->timeToLive = 64;
}
