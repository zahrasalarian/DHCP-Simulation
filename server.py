import socket, json, sys
sys.path.append(".")

IP     = 'localhost'
Port   = 21
bufferSize = 3000

import math, json

class IP_Handler:
    def __init__(self, ip):
        self.ip = ip
        self.mac = ""
        self.free = True
        self.keep = False

    def setMac(self, mac):
        self.mac = mac

    def set_IP_unavailable(self):
        self.free = False

    def keep_IP_address(self):
        # The IP address is set to be retained
        self.keep = True

    def make_IP_available(self):
        self.free = True

    def release_IP_address(self):
        self.keep = False
        self.mac = ""


class IP_Pool:

    def __init__(self, configsObject):
        self.addressIP = [] # here we will store the ip addresses generated following the network address and the mask
        self.reserved_ips = []
        self.black_list = configsObject["black_list"]

        # reserve ips for macs
        self.reserve_ips(configsObject['reservation_list'])

        #pool_mode == subnet
        if configsObject['pool_mode'] == 'subnet':
            self.generate_ips_subnet(configsObject['subnet']['ip_block'], configsObject['subnet']['subnet_mask'])
            #self.create_ips_subnet(configsObject['subnet']['ip_block'], configsObject['subnet']['subnet_mask'])
            
        #pool_mode == range
        else:
            self.generate_ips_range(configsObject['range']['from'], configsObject['range']['to'])

    def reserve_ips(self, reservation_list):
        for mac, ip in reservation_list.items():
            IPAddress = IP_Handler(ip)
            IPAddress.setMac(mac)
            IPAddress.set_IP_unavailable()
            IPAddress.keep_IP_address()
            self.reserved_ips.append(IPAddress)

    def generate_ips_subnet(self, in_ip, mask):
        self.network_address = in_ip
        self.broadcast_address = ""
        self.mask = []

        for val in mask.split('.'):
            self.mask.append(int(val))

        self.total_ips = 0
        nr_zeroes = 0
        for x in range(0, 4):  # 0 1 2 3
            if self.mask[x] == 255:
                continue
            else:
                nr_zeroes_cur = 255 - self.mask[x] + 1  # e.g. 255-252 = 3 + 1 = 4; sqrt (4) = 2 = number of zeros in the current value mask: 11111100 = 252
                nr_zeroes += math.log2(nr_zeroes_cur)

        self.total_ips = 2 ** nr_zeroes  # as formula says : nrOfIPs = 2^x-2, where x is the no of 0's in the subnet mask;
        # this does include the first(gateway) and the last (broadcast) addr

        # Build the address pool
        ip = []
        for x in in_ip.split('.'):
            ip.append(int(x))
        for i in range(1, int(self.total_ips)):
            ip[3] += 1
            if ip[3] > 255:
                ip[3] = 0
                ip[2] += 1
                if ip[2] > 255:
                    ip[2] = 0
                    ip[1] += 1
                    if ip[1] > 255:
                        ip[1] = 0
                        ip[0] += 1
            self.addressIP.append(IP_Handler(str(ip[0]) + '.' + str(ip[1]) + '.' + str(ip[2]) + '.' + str(ip[3])))

        self.broadcast_address = str(ip[0]) + '.' + str(ip[1]) + '.' + str(ip[2]) + '.' + str(ip[3])
        self.server_identifier = str(ip[0]) + '.' + str(ip[1]) + '.' + str(ip[2]) + '.' + str(ip[3] - 1)

        addressIP = self.addressIP.copy()
        for client_ip in addressIP:
            if client_ip.ip == self.server_identifier or client_ip.ip == self.broadcast_address:  # we remove the address for server_identifier, the broadcast address
                self.addressIP.remove(client_ip)

    def generate_ips_range(self, start, end):
        import socket, struct
        start = struct.unpack('>I', socket.inet_aton(start))[0]
        end = struct.unpack('>I', socket.inet_aton(end))[0]
        self.addressIP = [IP_Handler(socket.inet_ntoa(struct.pack('>I', i))) for i in range(start, end+1)]

    def getFreeAddress(self, _mac):
        ip = None
        for _ip in self.addressIP:
            if _ip.free is True and _ip.keep is False:
                #_ip.setMac(_mac)
                #_ip.set_IP_unavailable()
                ip = _ip
                break
        return ip.ip
    
    def assign_IPAddress(self, _ip, _mac):
        IPObj = self.findIPObjByIPAddr(_ip)
        if IPObj.free is True and IPObj.keep is False:
            IPObj.setMac(_mac)
            IPObj.set_IP_unavailable()
            print('YAay')
            return _ip
        return None 

    def getIPAddress(self, _mac):
        """
        Function that returns an IPAddress object and takes into account the following:
        1)We first check if the machine requesting an IP address is among those that have statically assigned an IP address and that is always up to them.
        2)If the machine requesting an IP address is in the black list and we can't assign an IP to it.
        3)If none of the above returns an IP to the machine, it means that we can assign any IP from our address pool.
        """
        return_ip =""
        # if the same ip is assigned to a car (static binding)
        staticIp = self.findIPByMac(_mac)
        if len(staticIp) != 0:
            staticIp = staticIp.pop()
            if staticIp in self.reserved_ips:
            #staticIp.set_IP_unavailable()
            #staticIp.keep_IP_address()
                return_ip = staticIp.ip

        # if mac address is in the black list
        if _mac in self.black_list:
            return None
            
        # we assign a random address
        if return_ip == "":
            return_ip= self.getFreeAddress(_mac)
            print('OOOOOOOO {}'.format(return_ip))
        return return_ip

    def findIPObjByIPAddr(self, _ip):
        return_ip = ""
        for ip in self.addressIP:
            if ip.ip == _ip:
                return ip
        return None

    def findIPByMac(self, _mac):
        return [ip for ip in self.addressIP if ip.mac == _mac]
# if __name__ == '__main__':
#     ap = AddressPool("192.168.1.0", "255.255.255.0")

def read_configs(file_name):
    with open(file_name) as jsonFile:
        jsonObject = json.load(jsonFile)
        jsonFile.close()
    return jsonObject

def make_DHCPOFFER_message(order, DISCOVER_elements):
    #macid = DISCOVER_elements['chaddr']
    #if macid in black_list:
    #    print('You are blocked')
    #    return

    #create message
    op = b'2'
    htype = b'1'
    hlen = b'6'
    hops = b'0'
    #xid = bstr(random.randint(1243,2324)) if order == 'DHCPDISCOVER' else OFFER_elements['xid']
    xid = bytes(DISCOVER_elements['xid'], 'utf-8')
    secs = b'00'
    flags = bytes(DISCOVER_elements['flags'], 'utf-8') 
    ciaddr = b'0000' # Client IP address ---> only filled in if client is in BOUND, RENEW or REBINDING state and can respond to ARP requests.
    yiaddr = ''
    if order == 'OFFER':
        ip = IPP.getIPAddress(DISCOVER_elements['ciaddr'])
        #yiaddr = bytes(map(int,IPP.getFreeAddress(12).split('.')))
        yiaddr = socket.inet_aton(ip) if ip is not None else b'0000'
        print(ip)
    elif order == 'ACK':
        ip = IPP.assign_IPAddress(DISCOVER_elements['yiaddr'], DISCOVER_elements['ciaddr'])
        yiaddr = socket.inet_aton(ip) if ip is not None else b'0000'
        print(ip)

    #yiaddr = bytes(IPP.getFreeAddress(12), 'utf-8')
    siaddr = b'0000' # IP address of next server to use in bootstrap; returned in DHCPOFFER, DHCPACK by server.
    giaddr = bytes(DISCOVER_elements['giaddr'], 'utf-8')
    chaddr = bytes(DISCOVER_elements['chaddr'], 'utf-8')
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

def handle_discover():
    pass
def handle_DHCP_message(p_elements):
    # message type  = discover
    if p_elements['options'][0:6] == '350101':
        handle_discover()

# read configs
configsObject = read_configs('configs.json')
black_list = configsObject['black_list']

# make initial ips
IPP = IP_Pool(configsObject)

# Create a datagram socket
UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

# Bind to address and ip
UDPServerSocket.bind((IP, Port))
print("UDP server up and listening")

# Listen for incoming datagrams
while(True):
    # Receive DHCPDISCOVER message from client
    DISCOVER_message = UDPServerSocket.recvfrom(4096)
    print('Received DISCOVER message.')
    DISCOVER_message_elements = decode_DHCP_message(DISCOVER_message[0])
    print(DISCOVER_message_elements['options'][0:6])

    # Send a DHCPOFFER message to client
    DHCPOffer_message = make_DHCPOFFER_message('OFFER',DISCOVER_message_elements)
    UDPServerSocket.sendto(DHCPOffer_message, ('localhost', 22))
    print('Sent DHCPOFFER message.')

    # Receive DHCPREQUEST message from client
    DHCPREQUEST_message = UDPServerSocket.recvfrom(4096)
    print('Received DHCPREQUEST message.')
    DHCPREQUEST_message_elements = decode_DHCP_message(DHCPREQUEST_message[0])

    # Send a DHCPACK message to client
    DHCPAck_message = make_DHCPOFFER_message('ACK', DHCPREQUEST_message_elements)
    UDPServerSocket.sendto(DHCPAck_message, ('localhost', 22))
    print('Sent DHCPACK message.')


