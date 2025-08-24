from utils import *
import time

#Convert an int to a payload parameter
def intToPayload(int: int, sizeN: int) -> str:
    return reverseHex(size(intToHex(int), sizeN))

#Convert a strring to a payload parameter
def strToPayload(str: str, sizeN: int) -> str:
    return reverseHex(size(strToHex(str), sizeN))

#Message class: Used to build the header + payload to send to peer
class Message:
    def __init__(self, command: str, payload: str, magic_bytes="f9beb4d9"):
        self.command = command
        self.payload = payload.upper()
        self.magic_bytes = magic_bytes.upper()
    
    #Pretty print
    def __str__(self):
        build = self.build_message()
        size = build[32:40]
        checksum = build[40:48]
        return f"{self.command}\nmagic_bytes:{self.magic_bytes}\nsize:{int(reverseHex(size), 16)}\nchecksum:{checksum}\npayload:{self.payload}"
    
    def build_message(self):
        magic_bytes = self.magic_bytes
        command = strToHex(self.command)
        sizeOfPayload = reverseHex(size(intToHex(int(len(self.payload) / 2)), 4))
        checksumOfPayload = checksum(self.payload)

        return (magic_bytes + command + sizeOfPayload + checksumOfPayload + self.payload).upper()

    def isValidChecksum(self, check: str):
        return checksum(self.payload) == check.upper()


#Version class: Used to build the payload of a version message wrapped in a Message class
class Version(Message):
    def __init__(self, ipv6: str, magic_bytes="f9beb4d9",port=8333, timestamp=0, version=70015, services=0):
        self.version = version
        self.services = services
        self.time = int(time.time()) if timestamp == 0 else timestamp
        self.remoteIP = ipv6
        self.remotePort = port
        self.localIp = "127.0.0.1"
        self.localPort = port
        self.nonce = 0
        self.lastBlock = 0

        #Build the payload
        payload = intToPayload(self.version, 4)
        payload += intToPayload(services, 8)
        payload += intToPayload(self.time, 8)
        payload += intToPayload(0, 8)
        payload += self.remoteIP.replace(":", "").rjust(32, "0")
        payload += size(intToHex(self.remotePort), 2)
        payload += intToPayload(self.services, 8)
        payload += "00000000000000000000ffff7f000001"
        payload += size(intToHex(self.localPort), 2)
        payload += intToPayload(self.nonce, 8)
        payload += "00"
        payload += intToPayload(0, 4)

        #Wrap it in the Message class
        super().__init__("version", payload, magic_bytes)

#Verack class: Used to build a verack message (no payload)
class Verack(Message):
    def __init__(self, magic_bytes="f9beb4d9"):
        super().__init__("verack", "", magic_bytes)

#Pong class: Used to build a pong message (no payload)
class Pong(Message):
    def __init__(self, payload, magic_bytes="f9beb4d9"):
        super().__init__("pong", payload, magic_bytes)

class GetData(Message):
    def __init__(self, payload, magic_bytes="f9beb4d9"):
        super().__init__("getdata", payload, magic_bytes)