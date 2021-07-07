import json
from os import PathLike
import random
import socket
import binascii

IP     = "localhost"
Port   = 22

def read_configs(file_name):
    with open(file_name) as jsonFile:
        jsonObject = json.load(jsonFile)
        jsonFile.close()
    return jsonObject


def make_DHCP_message(configsObject, order, OFFER_elements):
    ### DHCPDISCOVER
    # Message op code / message type ---> 1 = BOOTREQUEST, 2 = BOOTREPLY
    op = b'1'
    # Hardware address type ---> RFC; e.g., '1' = 10mb ethernet
    htype = b'1'
    # Hardware address length ---> e.g.  '6' for 10mb ethernet
    hlen = b'6'
    # Client sets to zero, optionally used by relay agents when booting via a relay agent.
    hops = b'0'
    # Transaction ID, a random number chosen by the client, used by the client and server to associate messages and responses between a client and a server.
    #xid = bstr(random.randint(1243,2324)) if order == 'DHCPDISCOVER' else OFFER_elements['xid']
    xid = bytes(OFFER_elements['xid'], 'utf-8') if OFFER_elements is not None else  b'48a1'
    # Filled in by client, seconds elapsed since client began address acquisition or renewal process.
    secs = b'00'
    # set broadcast flag
    flags = b'80' 
    ciaddr = b'0000' # Client IP address ---> only filled in if client is in BOUND, RENEW or REBINDING state and can respond to ARP requests.
    if order == 'DHCPREQUEST':
        print(OFFER_elements['yiaddr'])
    yiaddr = b'0000' if order == 'DHCPDISCOVER' else socket.inet_aton(OFFER_elements['yiaddr']) # 'your' (client) IP address.
    siaddr = b'0000' # IP address of next server to use in bootstrap; returned in DHCPOFFER, DHCPACK by server.
    giaddr = b'0000' # Relay agent IP address, used in booting via a relay agent.
    chaddr = b'000000ff7d878c2f' # Client hardware address. ---> Ethernet
    sname = b'0' * 64 # Optional server host name, null terminated string.
    file = b'0' * 128 # Boot file name, null terminated string; "generic" name or null in DHCPDISCOVER, fully qualified directory-path name in DHCPOFFER.
    
    #option 53 : message type  = discover ; code = 35 (53 in decimal), length = 01 = 1 octet (adica 2 litere in hexa) , 01 e valoarea (dhcp discover)
    #optiunea 61 : Client Identifier : mostly the chaddr + alte numere;
    # option 50 : se cere o adresa ip specifica
    #optiunea 55 parameter request = lista de coduri cu optiunile cerute de client, aici spre exemplu e 1,15,3,6,2,28....
    options = ''
    options = b'350101' if order == 'DHCPDISCOVER' else b'350103'
    options += b'3d078125f59fefac54' + b'3204c0a80004' + b'370c010f0306021c1f2179f92b' + b'ff'  #endmark

    message = op + htype + hlen + hops + xid + secs + flags + ciaddr + yiaddr + siaddr + giaddr + chaddr + sname + file + options
    return message

def decode_DHCP_message(message):
    message_p1 = message[:16].decode()
    elements = {}
    elements['op'] = message_p1[0]
    elements['htype'] = message_p1[1]
    elements['hlen'] = message_p1[2]
    elements['hops'] = message_p1[3]
    elements['xid'] = message_p1[4:8]
    elements['secs'] = message_p1[8:10]
    elements['flags'] = message_p1[10:12]
    elements['ciaddr'] = message_p1[12:16]
    elements['yiaddr'] = socket.inet_ntoa(message[16:20])
    message_p2 = message[20:].decode()
    #elements['yiaddr'] = message_p2[16:20]
    elements['siaddr'] = message_p2[0:4]
    elements['giaddr'] = message_p2[4:8]
    elements['chaddr'] = message_p2[8:24]
    elements['sname'] = message_p2[24:88]
    elements['file'] = message_p2[88:216]
    elements['options'] = message_p2[216:]

    return elements

# read configs
configsObject = read_configs('configs.json')
print(configsObject['range'])

# make a connection
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_socket.bind((IP, Port))
print("\nC:About to send a discover message")

# Send DHCPDISCOVER
message = make_DHCP_message(configsObject, 'DHCPDISCOVER', None)
client_socket.sendto(message, ('localhost', 21))
print("\nSent DHCPDISCOVER")


ID = 2324
order = 'DHCPOFFER'
OFFER_elements = ''
xid = random.randint(1243,2324) if order == 'DHCPOFFER' else OFFER_elements['xid']
#print(len("{:01b}".format(1) + "{:015b}".format(0)))

# Receive DHCPOFFER
DHCPOFFER_message = client_socket.recvfrom(4096)
print('Received DHCPOFFER message.')
DHCPOFFER_message_elements = decode_DHCP_message(DHCPOFFER_message[0])

# Send DHCPREQUEST
DHCPREQUEST_message = make_DHCP_message(configsObject, 'DHCPREQUEST', DHCPOFFER_message_elements)
client_socket.sendto(DHCPREQUEST_message, ('localhost', 21))
print("\nSent DHCPREQUEST")

# Receive DHCPACK
DHCPACK_message = client_socket.recvfrom(4096)
print('Received DHCPACK message.')
DHCPACK_message_elements = decode_DHCP_message(DHCPACK_message[0])
print(DHCPACK_message_elements['yiaddr'])

