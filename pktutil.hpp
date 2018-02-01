#ifndef IOSTREAM
#define IOSTREAM
#include <iostream>
#endif

#ifndef ARPA_INET_H
#define ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifndef PCAP_LIVE_DEVICE_LIST_H
#define PCAP_LIVE_DEVICE_LIST_H
#include "PcapLiveDeviceList.h"
#endif

#ifndef PACKET_H
#define PACKET_H
#include "Packet.h"
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

#ifndef PKTUTIL_HPP
#define PKTUTIL_HPP

namespace PktUtil {
  void printPktInfo(pcpp::RawPacket* packet);
  std::string printTcpOptionType(pcpp::TcpOption optionType);
  std::string printTcpFlags(pcpp::TcpLayer* tcpLayer);
}

#endif