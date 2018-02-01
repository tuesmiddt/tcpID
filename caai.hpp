#ifndef IOSTREAM
#define IOSTREAM
#include <iostream>
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

#ifndef CAAI_HPP
#define CAAI_HPP

class TestSession;
class CAAITest {
public:
  CAAITest(TestSession *);
  static void testCallBack(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* token);
private:
  TestSession *session;
  static std::string printTcpOptionType(pcpp::TcpOption optionType);
  static std::string printTcpFlags(pcpp::TcpLayer* tcpLayer);
};

#endif