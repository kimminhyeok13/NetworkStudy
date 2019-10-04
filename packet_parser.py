
packet_list = []

ether_type = {'0806':'ARP','0835':'RARP','0800':'IP'}


class Pcap_Parser:
    ''' PCAP FILE FORMAT PARSER '''

    def __init__(self):
        self.data = file_open()
        self.data_size = len(self.data)
        self.packet_data = self.data[24:]


        self.global_header = {
            'magic_number': self.data[0:4],
            'version_major': self.data[4:6],
            'version_minor': self.data[6:8],
            'thiszone': self.data[8:12],
            'sigfigs': self.data[12:16],
            'snaplen': self.data[16:20],
            'network': self.data[20:24],
        }


    def print_GH(self):
        print("--------------GLOBAL HEADER-------------")
        for key, value in self.global_header.items():
            print("{0} : {1} ".format(key, value))



class Packet_Parser:

    def __init__(self, pcap_data):
        self.packet_header = {
            'ts_sec': pcap_data[0:4],
            'ts_usec': pcap_data[4:8],
            'incl_len': pcap_data[8:12],
            'orig_len': pcap_data[12:16]
        }
        self.packet_size = little_endian(self.packet_header['orig_len'])
        self.next_header = pcap_data[16+self.packet_size:]
        self.packet_buff = pcap_data[16:16 + self.packet_size]

        self.ether_frame = {
            'dst_mac': ':'.join(self.packet_buff[:6]),
            'src_mac': ':'.join(self.packet_buff[6:12]),
            'ether_type': self.packet_buff[12]+self.packet_buff[13]

        }
        self.check_etherType()

    def print_PH(self):
        print("--------------PACKET HEADER-------------")
        for key, value in self.packet_header.items():
            print("{0} : {1} ".format(key, value))

    def print_ETH(self):
        print("--------------ETHER FRAME-------------")
        for key, value in self.ether_frame.items():
            print("{0} : {1} ".format(key, value))

    def check_etherType(self):
        protocol = ether_type[self.ether_frame['ether_type']]
        if protocol == 'ARP':
            self.ether_frame['ether_type'] = ARP(self.packet_buff[14:])
        elif protocol == 'RARP':
            self.ether_frame['ether_type'] = ARP(self.packet_buff[14:])
        elif protocol =='IP':
            # self.ether_frame['ether_type'] = IP(self.packet_buff)
            print("----------IP Header---------------")
            self.ether_frame['ether_type'] = IP(self.packet_buff[14:])


    # def print_mac(self):
    #     self.dst = ':'.join(self.ether_frame['dst_mac'])
    #     self.src = ':'.join(self.ether_frame['src_mac'])
    #     print("dst_mac: ",self.dst)
    #     print("src_mac: ",self.src)


class IP:
    def __init__(self,packet_buff):
        self.ip_header = {
            'Version and IHL' : packet_buff[:1],
            'Type of Service' : packet_buff[1:2],
            'Total length' : packet_buff[2:4],
            'Identification' : packet_buff[4:6],
            'Flags and Fragment offset' : packet_buff[6:8],
            'TTL' : packet_buff[8:9],
            'Protocol' : packet_buff[9:10],
            'Header Checksum' : packet_buff[10:12],
            # 'Src IP' : packet_buff[12:16],
            # 'Dst IP' : packet_buff[16:20],
            'Src IP' : '.'.join([str(int(i,16)) for i in packet_buff[12:16]]),
            'Dst IP': '.'.join([str(int(i, 16)) for i in packet_buff[16:20]]),
            'OPtion and Data' : packet_buff[20:]

        }
        print(self.ip_header['Src IP'], self.ip_header['Dst IP'])




class ARP:
    def __init__(self,packet_buff):
        self.arp={
            'Hardware Type' : packet_buff[:4],
            'Protocol Type' : packet_buff[4:8],
            'Hardware Length' : packet_buff[8:10],
            'Protocol Length' : packet_buff[10:12],
            'Operation' : packet_buff[12:16],
            'Sender Hardware Address' : packet_buff[16:24],
            'Sender IP Address' : packet_buff[24:32],
            'Target Hardware Address':packet_buff[32:40],
            'Target IP Address' : packet_buff[40:48]

        }


def little_endian(value_list):
    tmp = ''
    for i in reversed(value_list):
        tmp += i

    return int(tmp, 16)


def file_open():

    filename = input("input filename : ")
    fp = open(filename,"rb")
    #fp = open(filename, "rb")
    pcap_data = fp.read()
    hex_data = ['{:02x}'.format(i) for i in pcap_data]
    # print(hex_data)
    return hex_data



def pcap2packet():

    pcap = Pcap_Parser()                # Pcap 파일 내부의 패킷 파싱
    pcap.print_GH()                     # pcap의 글로벌 헤더 출력
    total_len = pcap.data_size - 24     # 글로벌 헤더 제외한 패킷들의 총 길이
    packet_len = 0                      # total_len과 비교하기위한 패킷 길이
    data = pcap.packet_data             # 글로벌 헤더 제외한 실제 패킷들의 데이터(패킷헤더 포함)

    while total_len > packet_len:       # 반복문을 돌려 패킷헤더 + 패킷데이터로 구분지어 packet_list에 저장
        packet = Packet_Parser(data)
        packet.print_PH()
        packet.print_ETH()
        # packet.print_mac()
        packet_list.append(packet)
        data = packet.next_header
        packet_len += (packet.packet_size+16)





pcap2packet()
print(len(packet_list))