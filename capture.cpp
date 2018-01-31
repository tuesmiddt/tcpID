// // #include "capture.hpp"


// void testIface(char* srcIP) {
//   pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance()
//       .getPcapLiveDeviceByIp(srcIP);
//   if (dev == NULL) {
//     std::printf("Could not find interface with IPv4 address of %s\n", srcIP);
//     exit(-1);
//   }

//   // before capturing packets let's print some info about this interface
//   printf("Interface info:\n");
//   // get interface name
//   printf("   Interface name:        %s\n", dev->getName());
//   // get interface description
//   printf("   Interface description: %s\n", dev->getDesc());
//   // get interface MAC address
//   printf("   MAC address:           %s\n", dev->getMacAddress().toString().c_str());
//   // get default gateway for interface
//   printf("   Default gateway:       %s\n", dev->getDefaultGateway().toString().c_str());
//   // get interface MTU
//   printf("   Interface MTU:         %d\n", dev->getMtu());
//   // get DNS server if defined for this interface
//   if (dev->getDnsServers().size() > 0)
//     printf("   DNS server:            %s\n", dev->getDnsServers().at(0).toString().c_str());


//   if (!dev->open()) {
//     std::printf("Cannot open device\n");
//     exit(-1);
//   }

// }