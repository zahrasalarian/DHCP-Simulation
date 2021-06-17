import socket

IP     = 'localhost'
Port   = 21
bufferSize = 3000

def make_DHCP_message(order, DISCOVER_elements):
    pass

def decode_DHCP_message(message):
    message = message.decode()
    elements = {}
    elements['op'] = message[0]
    elements['htype'] = message[1]
    elements['hlen'] = message[2]
    elements['hops'] = message[3]
    elements['xid'] = message[4:8]
    elements['secs'] = message[8:10]
    elements['flags'] = message[10:12]
    elements['ciaddr'] = message[12:16]
    elements['yiaddr'] = message[16:20]
    elements['siaddr'] = message[20:24]
    elements['giaddr'] = message[24:28]
    elements['chaddr'] = message[28:44]
    elements['sname'] = message[44:108]
    elements['file'] = message[108:236]
    elements['options'] = message[236:]

    return elements

def handle_discover():
    pass
def handle_DHCP_message(p_elements):
    # message type  = discover
    if p_elements['options'][0:6] == '350101':
        handle_discover()

# Create a datagram socket
UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

# Bind to address and ip
UDPServerSocket.bind((IP, Port))
print("UDP server up and listening")

# Listen for incoming datagrams
while(True):
    p = UDPServerSocket.recvfrom(4096)
    print('Packet Received.')
    p_elements = decode_DHCP_message(p[0])
    print(p_elements['options'][0:6])
    # Sending a reply to client