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

    def generate_ips_subnet(self, ip, mask):
        self.network_address = ip
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
        for x in ip.split('.'):
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
                _ip.setMac(_mac)
                _ip.set_IP_unavailable()
                ip = _ip
                break
        return ip.ip

    def getIPAddress(self, option50, _mac):
        """
        Function that returns an IPAddress object and takes into account the following:
        1)We first check if the machine requesting an IP address is among those that have statically assigned an IP address and that is always up to them.
        2)We check the car's preference by analyzing option 50, if it exists
        3)If none of the above returns an IP to the machine, it means that we can assign any IP from our address pool.
        """
        return_ip =""
        # if the same ip is assigned to a car (static binding)
        staticIp = self.findIPByMac(_mac)
        if len(staticIp) != 0:
            staticIp = staticIp.pop()
            staticIp.set_IP_unavailable()
            staticIp.keep_IP_address()
            return_ip = staticIp.ip

        # it's not about static binding, so we try to satisfy the customer's request
        elif 50 in option50 :
            requested = self.findIPObjByIPAddr(option50[50])
            if requested != None:
                if requested.free == True and requested.keep == False:
                    requested.setMac(_mac)
                    requested.set_IP_unavailable()
                    return_ip = requested.ip

        # we assign a random address
        if return_ip == "":
            return_ip= self.getFreeAddress(_mac)

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
# read configs
configsObject = read_configs('configs.json')
black_list = configsObject['black_list']

def make_DHCPOFFER_message(order, DISCOVER_elements):
    #macid = DISCOVER_elements['chaddr']
    #if macid in black_list:
    #    print('You are blocked')
    #    return
    o = IP_Pool(configsObject)
    print('hi')
    for i in o.addressIP:
        print(i.ip)
    
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

make_DHCPOFFER_message('','')

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

