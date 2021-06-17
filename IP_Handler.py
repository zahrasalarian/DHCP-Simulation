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