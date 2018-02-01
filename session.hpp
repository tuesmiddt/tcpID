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

#ifndef PCAP_LIVE_DEVICE_LIST_H
#define PCAP_LIVE_DEVICE_LIST_H
#include "PcapLiveDeviceList.h"
#endif

#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H
#include "NetworkUtils.h"
#endif

#ifndef MAC_ADDRESS_H
#define MAC_ADDRESS_H
#include "MacAddress.h"
#endif

#ifndef IP_ADDRESS_H
#define IP_ADDRESS_H
#include "IpAddress.h"
#endif

#ifndef ETH_LAYER_H
#define ETH_LAYER_H
#include "EthLayer.h"
#endif

#ifndef IPV4_LAYER_H
#define IPV4_LAYER_H
#include "IPv4Layer.h"
#endif

#ifndef TCP_LAYER_H
#define TCP_LAYER_H
#include "TcpLayer.h"
#endif

#ifndef PCAP_FILTER_H
#define PCAP_FILTER_H
#include "PcapFilter.h"
#endif

#ifndef PLATFORM_SPECIFIC_UTILS_H
#define PLATFORM_SPECIFIC_UTILS_H
#include "PlatformSpecificUtils.h"
#endif

#ifndef VECTOR
#define VECTOR
#include <vector>
#endif

#ifndef PACKET_H
#define PACKET_H
#include "Packet.h"
#endif

#ifndef RANDOM
#define RANDOM
#include <random>
#endif

#ifndef SESSION_HPP
#define SESSION_HPP

class CAAITest;
class TestSession {
public:

	char dstName[_SC_HOST_NAME_MAX];

	char srcIP[INET_ADDRSTRLEN];
	char dstIP[INET_ADDRSTRLEN];

	int sockfd;

  std::uint32_t src;
  std::uint16_t sport;
  std::uint32_t dst;
  std::uint16_t dport;

  std::uint32_t iss;
  std::uint32_t irs;

  CAAITest* test;
  std::vector<pcpp::Packet*> history;

  pcpp::PcapLiveDevice* dev;
  pcpp::EthLayer* ethLayer = new pcpp::EthLayer(pcpp::MacAddress::Zero, pcpp::MacAddress::Zero);
  pcpp::IPv4Layer* ipLayer;
  // pcpp::MacAddress macAddress = pcpp::MacAddress::Zero;

	TestSession(char* target, int port);
  void cleanUp();
  void initCapture();
  void addToHistory(pcpp::Packet* packet);

private:
  std::vector<std::string> offloadTypes;
  std::vector<std::string> fwRules;

  std::string buildFilter();
  void sendSyn();
  void sendTcp(pcpp::TcpLayer* tcpLayer);
  void makeEthLayer();
  void makeIPLayer();
  void setISS();
  void blockRSTOut();
  void clearFWRules();
  void setOffloadTypes();
  void disableOffload();
  void enableOffload();
  void setIface();
	void setSrcInfo();
  void setDstInfo(char *target, int port);
};

#endif
