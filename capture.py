from scapy.all import *
from multiprocessing import Process

netFilter = None

def spawnFilter(sessionParams):
    p = Process(target = startFilter, args=(sessionParams,))
    p.start()

    global netFilter
    netFilter = p


def killFilter():
    netFilter.terminate()


def startFilter(sessionParams):
    filterString = "host %s and host %s and port %d" % (sessionParams["srcIP"],
                                                        sessionParams["dstIP"],
                                                        sessionParams["dport"])
    sniff(filter=filterString, prn=enqueueProcessing(sessionParams["filterQueue"]))


def enqueueProcessing(q):
    def enqueuePacket(packet):
        q.put(packet)
        return packet.summary()

    return enqueuePacket
