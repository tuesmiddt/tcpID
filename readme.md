# PCPP Overview

## Parsing and reading a (captured) packet
When given a `pcpp::RawPacket`, first step is to parse it:

```
pcpp::Packet* parsedPacket = new pcpp::Packet(packet);
```

We can then extract any layer from a `pcpp::Packet`. This is an example for extracting the TCP layer:
```
pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
```

From there, `tcpLayer->getTcpHeader()` returns a pointer to a [`tcphdr`](http://seladb.github.io/PcapPlusPlus-Doc/Documentation/a00177.html) struct that contains the actual raw data. Information is stored in network byte order (as far as I know). For example, to get the sequence number of a packet:
```
std::uint32_t seq = ntohl(tcpLayer->getTcpHeader()->sequenceNumber);
```

There is no direct way to check whether a TCP option is set or not. This can only be done by iterating over the options like so:
```
for (pcpp::TcpOptionData* tcpOption = tcpLayer->getFirstTcpOptionData(); tcpOption != NULL; tcpOption = tcpLayer->getNextTcpOptionData(tcpOption))
{
	printf("%s ", printTcpOptionType(tcpOption->getType()).c_str());
}
```

Detailed documentation for `pcpp::TcpLayer` can be found [here](http://seladb.github.io/PcapPlusPlus-Doc/Documentation/a00178.html).

## Sending a packet

### Crafting a packet

A complete packet is built by creating a packet then adding the various layers in order.

Detailed documentation can be found [here](http://seladb.github.io/PcapPlusPlus-Doc/Documentation/a00105.html).

To create a packet:
```
pcpp::Packet* p = new pcpp::Packet(expectedPktSize);
```

The expected packet size is the initial allocated size and will be automatically increase if necessary (at a performance cost that is inconsequential to us right now).

We then add each layer of the packet:
```
p->addLayer(&myEthernetLayer);
p->addLayer(&myIPLayer);
p->addLayer(&myTCPLayer);
p->addLayer(&myPayloadLayer);
```

Creating ethernet and IP layers is done already in `session.cpp`. Each packet/layer can only be sent once so copy constructors are used to duplicate premade ethernet/IP layers.

Finally, we compute any fields that need to be calculated automatically (checksums and whatnot) like so:
```
p->computeCalculateFields();
```

#### Creating a TCP Layer

This is an overview of the process to create a TCP layer:

```
// Create TCP layer
pcpp::TcpLayer* tcpLayer = new pcpp::TcpLayer(sourcePort, destinationPort);

// Set options
tcpLayer->addTcpOption(pcpp::TCPOPT_MSS, 4, &myOptVal);
// We must manually pad it to fill an octet
// For some reason, we must supply a pointer to the desired value as the third argument for addTcpOption().
std::uint8_t* one = new std::uint8_t(1);
tcpLayer->addTcpOption(pcpp::PCPP_TCPOPT_NOP, 1, one);
tcpLayer->addTcpOption(pcpp::PCPP_TCPOPT_NOP, 1, one);
tcpLayer->addTcpOption(pcpp::PCPP_TCPOPT_NOP, 1, one);
tcpLayer->addTcpOption(pcpp::PCPP_TCPOPT_EOL, 1, 0);

// Set sequence and acknowledgement number
pcpp::tcphdr* header = tcpLayer->getTcpHeader();
header->sequenceNumber = htonl(mySeqNumber);
header->ackNumber = htonl(myAckNumber);

// Set other fields
header->windowSize = htons(myWSize);

// Set any flags
header->pshFlag = 1;
header->ackFlag = 1;
```

### Sending the packet

Packet can be sent from an opened network device as seen in the `TestSession::sendTcp()` method.
```
dev->sendPacket(packetPointer);
```