from scapy.all import *
from multiprocessing import Process
import history
import pktutil
import time

filterWatcher = None
count = 0

packetSender = None

def spawnFilterWatcher(sessionParams):
    w = Process(target = watchQueue, args=(sessionParams,))
    w.start()

    global filterWatcher
    filterWatcher = w


def killFilterWatcher():
    filterWatcher.terminate()


def watchQueue(sessionParams):
    while True:
        pkt = sessionParams["filterQueue"].get()
        processFilterPkt(pkt, sessionParams)


def processFilterPkt(pkt, sessionParams):
    if (IP in pkt) and (TCP in pkt):
        if pkt[IP].src == sessionParams["srcIP"] and \
                pkt[IP].dst == sessionParams["dstIP"] and \
                pkt[TCP].dport == sessionParams["dport"]:
            processPktOut(pkt, sessionParams)
        elif pkt[IP].src == sessionParams["dstIP"] and \
                pkt[IP].dst == sessionParams["srcIP"] and \
                pkt[TCP].sport == sessionParams["dport"]:
            processPktIn(pkt, sessionParams)


def processPktIn(pkt, sessionParams):
    history.storePkt(pkt, sessionParams)
    print pkt.show()
    print "in"


def processPktOut(pkt, sessionParams):
    history.storePkt(pkt, sessionParams)
    print "out"


def spawnPktSender(sessionParams):
    s = Process(target = sendPktOut, args=(sessionParams,))
    s.start()

    global packetSender
    packetSender = w


def sendPktOut(sessionParams):
    sendQueue = sessionParams["sendQueue"]
    while True:
        time.sleep(sessionParams["testParams"]["sendDelay"])
        numToSend = sendQueue.size
        for _ in range(numToSend):
            pkt = sessionParams["sendQueue"].get()
            send(pkt, verbose = 0)
