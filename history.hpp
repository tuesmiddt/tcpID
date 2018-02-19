#ifndef ARPA_INET_H
#define ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifndef MAP
#define MAP
#include <map>
#endif

#ifndef PACKET_H
#define PACKET_H
#include "Packet.h"
#endif

#ifndef TCP_LAYER_H
#define TCP_LAYER_H
#include "TcpLayer.h"
#endif

#ifndef CSTDINT
#define CSTDINT
#include <cstdint>
#endif

#ifndef UTILITY
#define UTILITY
#include <tuple>
#endif

#ifndef CHRONO
#define CHRONO
#include <chrono>
#endif

#ifndef HISTORY_HPP
#define HISTORY_HPP

class History {
 public:
  History();
  int push(pcpp::Packet* packet);
  pcpp::Packet* getMax();

  std::chrono::time_point<std::chrono::high_resolution_clock>
      getTimeBySeq(std::uint32_t key);
  std::chrono::time_point<std::chrono::high_resolution_clock>
      getTimeByAck(std::uint32_t key);
 private:
  std::map<std::uint32_t, std::tuple<pcpp::Packet*,
      std::chrono::time_point<std::chrono::high_resolution_clock>,
      int>> store;
};
#endif  // HISTORY_HPP_
