#ifndef IOSTREAM
#define IOSTREAM
#include <iostream>
#endif

#ifndef CSTDINT
#define CSTDINT
#include <cstdint>
#endif

#ifndef CTIME
#define CTIME
#include <ctime>
#endif

#ifndef THREAD
#define THREAD
#include <thread>
#endif

#ifndef MUTEX
#define MUTEX
#include <mutex>
#endif

#ifndef QUEUE
#define QUEUE
#include <queue>
#endif

#ifndef CHRONO
#define CHRONO
#include <chrono>
#endif

#ifndef UTILITY
#define UTILITY
#include <utility>
#endif

#ifndef SSTREAM
#define SSTREAM
#include <sstream>
#endif

#ifndef ISTREAM
#define ISTREAM
#include <istream>
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

#ifndef TCP_REASSEMBLY_H
#define TCP_REASSEMBLY_H
#include "TcpReassembly.h"
#endif

#ifndef PAYLOAD_LAYER_H
#define PAYLOAD_LAYER_H
#include "PayloadLayer.h"
#endif

// #ifndef SAFE_QUEUE
// #define SAFE_QUEUE

// #ifndef MUTEX
// #define MUTEX
// #include <mutex>
// #endif

// #ifndef QUEUE
// #define QUEUE
// #include <queue>
// #endif

// #ifndef CONDITION_VARIABLE
// #define CONDITION_VARIABLE
// #include <condition_variable>
// #endif

// template <class T> class SafeQueue {
//  public:
//   SafeQueue(): q(), m(), c() {}

//   void enqueue(T ) {
//     std::unique_lock<std::mutex> lock(m);
//     q.push(t);
//   }

//   void dequeue() {

//   }


//  private:
//   std::queue<T> q;
//   mutable std::mutex m;
//   std::condition_variable c;
// };

// #endif  // SAFE_QUEUE_

#ifndef CAAI_HPP
#define CAAI_HPP

// Include guards work really weirdly with wolfssl for some reason
#include <wolfssl/ssl.h>

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

  // SSL CALLBACKS
  static int sslWriteCallback(WOLFSSL* ssl, char* buf, int sz, void* ctx);
  static int sslReadCallback(WOLFSSL* ssl, char* buf, int sz, void* ctx);

 private:
  int connectionAttempts = 0;
  int sendDelay = 1000;  // send Delay in milliseconds
  int sleepCount = 0;
  int sleepInterval = 100;  // check for changes to send delay every 100 milliseconds
  std::queue<std::pair <pcpp::TcpLayer*, pcpp::Layer*>> sendQueue;
  std::mutex sendMutex;
  std::thread* sendWorker;
  pcpp::TcpReassembly* streamReassembly;
  std::stringstream rcvBuffer;

  TestSession* session;
  static const int ESTABLISH_SESSION = 1;
  static const int SSH_HANDSHAKE = 2;
  static const int PRE_DROP = 3;
  static const int POST_DROP = 4;
  static const int DONE = 0;

  static void reassemblyCallback(
      int side, pcpp::TcpStreamData data, void* cookie);
  // void makeRcvBuffer();
  void sendPacketQueue();
  void startWorker();
  void enqueuePacket(pcpp::TcpLayer* tcpLayer, pcpp::Layer* payloadLayer);
  void sendSyn();
  void setInitialOpt(pcpp::TcpLayer* synTcpLayer);
  void setTSOpt(pcpp::TcpLayer* targetTcpLayer, pcpp::TcpLayer* prevTcpLayer);
  void sendAck(pcpp::TcpLayer* prev);
  void sendData(char* buf, int dataLen);
  void sendRequest(pcpp::TcpLayer* prev);
  void handleEstablishSession(pcpp::TcpLayer* prev);
  void handleSshHandshake(pcpp::TcpLayer* prev);
  void handlePreDrop(pcpp::TcpLayer* prev);
  void handlePostDrop(pcpp::TcpLayer* prev);
  void handleDone(pcpp::TcpLayer* prev);
};

#endif  // CAAI_HPP_
