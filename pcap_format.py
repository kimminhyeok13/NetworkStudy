import pcap_open as po


class Pcap_Parser:
    ''' PCAP FILE FORMAT PARSER '''



    def __init__(self):
        self.pcap_data = po.main()[0:40]
        self.actual_packet = po.main()[40:]

        self.global_header = {
            'magic_number': self.pcap_data[0:4],
            'version_major': self.pcap_data[4:6],
            'version_minor': self.pcap_data[6:8],
            'thiszone': self.pcap_data[8:12],
            'sigfigs': self.pcap_data[12:16],
            'snaplen': self.pcap_data[16:20],
            'network': self.pcap_data[20:24],
        }
        self.packet_header = {
            'ts_sec': self.pcap_data[24:28],
            'ts_usec': self.pcap_data[28:32],
            'incl_len': self.pcap_data[32:36],
            'orig_len': self.pcap_data[36:40]
        }


    def print_GH(self):
        print("--------------GLOBAL HEADER-------------")
        for key, value in self.global_header.items():
            print("{0} : {1} ".format(key, value))


    def print_PH(self):
        print("--------------PACKET HEADER-------------")
        for key, value in self.packet_header.items():
            print("{0} : {1}".format(key, value))

    # def calc_values(self,key,value):






p=Pcap_Parser()
p.print_GH()
p.print_PH()

