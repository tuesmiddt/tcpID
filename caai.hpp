#ifndef IOSTREAM
#define IOSTREAM
#include <iostream>
#endif

#ifndef CSTDINT
#define CSTDINT
#include <cstdint>
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

#ifndef PAYLOAD_LAYER_H
#define PAYLOAD_LAYER_H
#include "PayloadLayer.h"
#endif

#ifndef CAAI_HPP
#define CAAI_HPP

class TestSession;
class CaaiTest {
 public:
  int testState = 1;

  std::uint16_t tcpOptMss;
  std::uint16_t tcpOptWscale;

  explicit CaaiTest(TestSession *);
  void testCallBack(pcpp::Packet* packet);
  void startTest();
  bool checkRestartTest();
  bool getTestDone();

 private:
  int connectionAttempts = 0;

  TestSession* session;
  static const int ESTABLISH_SESSION = 1;
  static const int SSH_HANDSHAKE = 2;
  static const int PRE_DROP = 3;
  static const int POST_DROP = 4;
  static const int DONE = 0;

  void sendSyn();
  void setInitialOpt(pcpp::TcpLayer* synTcpLayer);
  void sendAck(pcpp::TcpLayer* prev);
  void sendRequest(pcpp::TcpLayer* prev);
  void handleEstablishSession(pcpp::TcpLayer* prev);
  void handleSshHandshake(pcpp::TcpLayer* prev);
  void handlePreDrop(pcpp::TcpLayer* prev);
  void handlePostDrop(pcpp::TcpLayer* prev);
  void handleDone(pcpp::TcpLayer* prev);
};

#endif  // CAAI_HPP_
