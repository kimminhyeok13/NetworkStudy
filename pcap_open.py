
class Packet_Parser:

    packet_list = []
    def file_open(self):
        filename = input("input filename : ")
        #fp = open(filename,"rb")
        fp = open("test.pcap","rb")
        pcap_data = fp.read()
        hex_data = ['0x'+'{:02x}'.format(i) for i in pcap_data]
        #print(hex_data)
        return hex_data


#main()

# int('16진수 문자열',16) => 16진수 값을 10진수로 변환해줌