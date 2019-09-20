
def main():
    fp = open("test.pcap","rb")
    pcap_data = fp.read()
    hex_data = [hex(i) for i in pcap_data]
    #print(hex_data)
    return hex_data


#main()