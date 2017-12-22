from scapy.all import *
import history
import pktutil

def makeACKPkt(p, sessionParams):
    ackTCP = TCP(
            sport = sessionParams["sport"],
            dport = sessionParams["dport"],
            flags = "A",
            seq = sessionParams["seq"] + 1,
            options = [pktutil.makeTS(p)],
            ack = p.seq + pktutil.getPktDatalen(p)
        )

    ack = sessionParams["ipHdr"]/ackTCP

    return ack


def makeSynPkt(sessionParams):
    initTCPOptions = [pktutil.makeTS()]

    synTCP = TCP(
            sport = sessionParams["sport"],
            dport = sessionParams["dport"],
            flags = "S",
            options = initTCPOptions,
            seq = sessionParams["seq"])

    syn = essionParams["ipHdr"]/synTCP

    return syn


def makePayload(opt, sessionParams):
    if opt == "GET":
        return 'GET / HTTP/1.1\r\nHost: %s\r\n\r\n' % sessionParams["dstHostname"]

    return ""

def isRTO(p, sessionParams):
    return history.isRTO(p, sessionParams)


def calcRTT(p, sessionParams):
    prevPkt = history.getPrevPkt(p, sessionParams)

    return t.time - prevPkt.time

def isValid(p, sessionParams):
    valid = 1

    if (
            # seq < initial responder sequence number
            p[TCP].seq < sessionParams["irs"] or
            # seq > next expected seq + mss * 5
            (sessionParams["rcvNext"] and p[TCP].seq > sessionParams["rcvNext"] + sessionParams["mss"] * 5 )
        ):
        valid = 0

    return valid