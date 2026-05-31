from enum import Enum

class Direction(Enum): 
    UNKNOWN = 0
    FORWARD = 1
    BACKWARD = 2

class FlowTerminationReason(Enum):
    UNKNOWN = 0
    FIN = 1
    RST = 2
    ACTIVITY_TIMEOUT = 3
    IDLE_TIMEOUT = 4
    MAX_PACKETS = 5

class Protocol(Enum):
    UNKNOWN = -1
    ICMP = 1
    TCP = 6
    UDP = 17
    IPv6_ICMP = 58
    # For more see https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

class TCPFlag:
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80
