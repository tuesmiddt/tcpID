from scapy.all import *
import pktutil

IN = 1
OUT = 2

def makeHistory():
    history = {
        "pkts": {},
        "pktSeq": []
    }

    return history


def storePkt(pkt, sessionParams):
    history = sessionParams["history"]

    key = makeKey(pkt)
    # number represents whether packet has been acked
    history["pkts"][key] = [pkt, 0]
    history["pktSeq"].append(key)

    # mark prev packet as acked
    prev = getPrev(pkt, sessionParams)
    prev[1] = 1


def makeKey(pkt):
    ts = pktutil.getPktTS(pkt)

    seq = pkt[TCP].seq
    datalen = pktutil.getPktDatalen(pkt)
    nextSeq = seq + datalen

    src = pkt[IP].src

    return (nextSeq, ts[0], src)


def getPrev(pkt, sessionParams):
    history = sessionParams["history"]
    prevPktKey = makePrevPktKey(pkt)

    return history["pkts"].get(prevPktKey)


def getPrevPkt(pkt, sessionParams):
    return getPrev(pkt, sessionParams)[0]


def makePrevPktKey(pkt):
    ts = pktutil.getPktTS(pkt)
    ack = pkt[TCP].ack
    dst = pkt[IP].dst

    return (ack, ts[1], dst)


def isRTO(pkt, sessionParams):
    return getPrev(pkt, sessionParams)[1]