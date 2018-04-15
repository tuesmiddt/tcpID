#include "pktutil.hpp"

/**
 * Print debug information about a packet
 * @param packet Packet.
 */
void PktUtil::printPktInfo(pcpp::Packet* packet) {
  pcpp::EthLayer* ethernetLayer = packet->getLayerOfType<pcpp::EthLayer>();
  printf("\nSource MAC address: %s\n",
      ethernetLayer->getSourceMac().toString().c_str());
  printf("Destination MAC address: %s\n",
      ethernetLayer->getDestMac().toString().c_str());
  printf("Ether type = 0x%X\n",
      ntohs(ethernetLayer->getEthHeader()->etherType));

  pcpp::IPv4Layer* ipLayer = packet->getLayerOfType<pcpp::IPv4Layer>();
  printf("\nSource IP address: %s\n",
      ipLayer->getSrcIpAddress().toString().c_str());
  printf("Destination IP address: %s\n",
      ipLayer->getDstIpAddress().toString().c_str());
  printf("IP ID: 0x%X\n", ntohs(ipLayer->getIPv4Header()->ipId));
  printf("TTL: %d\n", ipLayer->getIPv4Header()->timeToLive);

  pcpp::TcpLayer* tcpLayer = packet->getLayerOfType<pcpp::TcpLayer>();

  printf("\nSource TCP port: %d\n",
      static_cast<int>(ntohs(tcpLayer->getTcpHeader()->portSrc)));
  printf("Destination TCP port: %d\n",
      static_cast<int>(ntohs(tcpLayer->getTcpHeader()->portDst)));
  printf("Sequence No: %u\n",
      ntohl(tcpLayer->getTcpHeader()->sequenceNumber));
  printf("Window size: %d\n",
      static_cast<int>(ntohs(tcpLayer->getTcpHeader()->windowSize)));
  printf("TCP flags: %s\n", printTcpFlags(tcpLayer).c_str());

  printf("\n");
}

std::string PktUtil::printTcpFlags(pcpp::TcpLayer* tcpLayer) {
  std::string result = "";
  if (tcpLayer->getTcpHeader()->synFlag == 1)
    result += "SYN ";
  if (tcpLayer->getTcpHeader()->ackFlag == 1)
    result += "ACK ";
  if (tcpLayer->getTcpHeader()->pshFlag == 1)
    result += "PSH ";
  if (tcpLayer->getTcpHeader()->cwrFlag == 1)
    result += "CWR ";
  if (tcpLayer->getTcpHeader()->urgFlag == 1)
    result += "URG ";
  if (tcpLayer->getTcpHeader()->eceFlag == 1)
    result += "ECE ";
  if (tcpLayer->getTcpHeader()->rstFlag == 1)
    result += "RST ";
  if (tcpLayer->getTcpHeader()->finFlag == 1)
    result += "FIN ";

  return result;
}
