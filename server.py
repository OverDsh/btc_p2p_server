import socket
import messages
import traceback
import time

#Convert IPv4 to IPv6-mapped format for payload (i.e., ::ffff:127.0.0.1)
def _ip_to_ipv6(ip: str) -> str:
        hex_ip = ''.join([f"{int(octet):02x}" for octet in ip.split('.')])
        return "00000000000000000000ffff" + hex_ip

#Server class: Used to connect to target peer
class Server():
    def __init__(self, remoteIP: str, network="mainnet", timeout=10):
        self.remoteIP = remoteIP

        #Set correct port and magic bytes depending on what network you are connecting to
        if network.lower() == "mainnet":
            self.port = 8333
            self.magic = "f9beb4d9"
        elif network.lower() == "testnet":
            self.port = 18333
            self.magic = "0b110907"
        else:
            raise Exception(f'Invalid network: expected "mainnet" or "testnet", got {network}')
        
        #Create the TCP socket to connect to peer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(timeout)

        #TCP buffer init
        self.socket_buffer = bytearray()
        self.timeout = timeout
        
    def connect(self):
        #Prepare the TCP socket for data exange
        print(f"[+] Connecting to {self.remoteIP}:{self.port}...")
        self.socket.connect((self.remoteIP, self.port))

        #Begin to exange data
        print("[+] Connected! Initiating handshake...")
        self._handshake()
    
    def receive(self, size: int):
        start = time.time()

        # Fill buffer until expected size reached
        while len(self.socket_buffer) < size:
            if (time.time() - start) > self.timeout:
                raise Exception("Timeout exceeded")
            self.socket_buffer.extend(self.socket.recv(size))
        
        # Return only requested size and clear packet from buffer
        packet = self.socket_buffer[:size]
        self.socket_buffer = self.socket_buffer[size:]
        return packet

    def _handshake(self):
        #Generate a version message and output it to the user
        version_msg = messages.Version(ipv6=_ip_to_ipv6(self.remoteIP), magic_bytes=self.magic, port=self.port)
        print(f"\n[>] Sending version: \n->{version_msg}")
        self.socket.sendall(bytes.fromhex(version_msg.build_message()))

        # Verack should only be sent once
        sent_ack = False

        while True:
            try:
                header = self.receive(24)
                if len(header) < 24:
                    raise Exception("Invalid header received from peer")

                #Extrat the values from header
                magic = header[:4].hex()
                command = header[4:16].rstrip(b"\x00").decode()
                length = int.from_bytes(header[16:20], "little")
                checksum = header[20:24].hex()
                payload = self.receive(length).hex()
                
                #Pretty print
                message_object = messages.Message(command, payload, magic)
                print(f"\n[<] Recieved {command}: \n<-{message_object}")

                #Check data integrity
                if not message_object.isValidChecksum(checksum):
                    raise Exception("Invalid checksum")

                if command == "version" and not sent_ack:
                    #Send Verack message
                    sent_ack = True
                    verack = messages.Verack(self.magic)
                    print(f"\n[>] Sending verack: \n {verack}")
                    self.socket.sendall(bytes.fromhex(verack.build_message()))
                    print("[✓] Handshake complete!")
                elif command == "ping":
                    #Reply with pong message
                    pong = messages.Pong(payload, self.magic)
                    print(f"\n[>] Sending pong: \n-> {pong}")
                    self.socket.sendall(bytes.fromhex(pong.build_message()))
            except socket.timeout:
                print("[-] Socket timeout")
                break
            except Exception as e:
                print(f"[-] Error: {e}")
                traceback.print_exc()
                break
            
                