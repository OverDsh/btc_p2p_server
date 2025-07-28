import hashlib

def intToHex(number: int) -> str:
    return hex(number)[2:].upper()

def strToHex(str: str) -> str:
    return str.encode().hex().ljust(24, "0").upper()

#Size hex correctly (little-endian, big-endian, ...)
def size(str: str, size: int) -> str:
    return str.rjust(size*2, "0").upper()

#Reverse hex bytes (03 02 01 -> 01 02 03)
def reverseHex(hex: str) -> str:
    return ''.join(hex[i:i+2] for i in range(0, len(hex), 2)[::-1]).upper()

#Build the checksum of payload (double hash the payload and take the first 4 bytes)
def checksum(payload: str) -> str:
    hash1 = hashlib.sha256(bytes.fromhex(payload)).digest()
    hash2 = hashlib.sha256(hash1).digest()
    return hash2[:4].hex().upper()