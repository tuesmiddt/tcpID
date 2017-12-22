from scapy.all import *
import time

def getPktTS(pkt):
    for opt, val in pkt[TCP].options:
        if opt == "Timestamp":
            return val

    raise Exception("TS NOT FOUND")


def makeTS(pkt = None):
    prev = getPktTS(pkt)[1] if pkt else 0

    return ('Timestamp', (int(time.time()), prev))


def getPktDatalen(pkt):
    return pkt[IP].len - pkt[IP].ihl * 4 - pkt[TCP].dataofs * 4