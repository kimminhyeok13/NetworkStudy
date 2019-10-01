class PacketList:
    def __init__(self):
        self.packet_list = []

    def append_packet(self,packet):
        self.packet_list.append(packet)


class Packet_Data:
    def __init__(self,pcap_data):
        self.packet_header = {
            'ts_sec': pcap_data[0:4],
            'ts_usec': pcap_data[4:8],
            'incl_len': pcap_data[8:12],
            'orig_len': pcap_data[12:16]
        }



class Packet_Parser:

    def file_open(self):
        filename = input("input filename : ")
        #fp = open(filename,"rb")
        fp = open("test.pcap","rb")
        self.pcap_data = fp.read()
        self.hex_data = ['{:02x}'.format(i) for i in self.pcap_data]
        #print(hex_data)
        return self.hex_data


#main()

# int('16진수 문자열',16) => 16진수 값을 10진수로 변환해줌


class Pcap_Parser:
    ''' PCAP FILE FORMAT PARSER '''

    def __init__(self):
        self.packet_in_pcap = []
        self.pcap = Packet_Parser()
        self.data = self.pcap.file_open()
        self.pcap_data = self.data[0:40]


        self.global_header = {
            'magic_number': self.pcap_data[0:4],
            'version_major': self.pcap_data[4:6],
            'version_minor': self.pcap_data[6:8],
            'thiszone': self.pcap_data[8:12],
            'sigfigs': self.pcap_data[12:16],
            'snaplen': self.pcap_data[16:20],
            'network': self.pcap_data[20:24],
        }
        # self.packet_header = {
        #     'ts_sec': self.pcap_data[24:28],
        #     'ts_usec': self.pcap_data[28:32],
        #     'incl_len': self.pcap_data[32:36],
        #     'orig_len': self.pcap_data[36:40]
        # }

    def print_GH(self):
        print("--------------GLOBAL HEADER-------------")
        for key, value in self.global_header.items():
            print("{0} : {1} ".format(key, value))

    # def print_PH(self):
    #     print("--------------PACKET HEADER-------------")
    #     for key, value in self.packet_header.items():
    #         print("{0} : {1}".format(key, value))

    def calc_little_endian(self,arg1):
        self.little_endian = ''
        for i in reversed(arg1):
            self.little_endian += i

        return int(self.little_endian,16)




pl  = PacketList()
p=Pcap_Parser()
p.print_GH()
p.print_PH()
print(p.calc_little_endian(p.global_header['snaplen']))




