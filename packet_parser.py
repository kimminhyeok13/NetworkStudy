
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
            'dst_mac': self.packet_buff[:6],
            'src_mac': self.packet_buff[6:12],
            'ether_type': self.packet_buff[12:14]

        }

    def print_PH(self):
        print("--------------PACKET HEADER-------------")
        for key, value in self.packet_header.items():
            print("{0} : {1} ".format(key, value))

    def print_ETH(self):
        print("--------------ETHER FRAME-------------")
        for key, value in self.ether_frame.items():
            print("{0} : {1} ".format(key, value))






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
        packet_list.append(packet)
        data = packet.next_header
        packet_len += (packet.packet_size+16)




pcap2packet()
print(len(packet_list))