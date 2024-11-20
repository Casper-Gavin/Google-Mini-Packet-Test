import matplotlib.pyplot as plt
import pyshark

# dst = destination, src = source, addr = either
def filter_packets_total(pcap_file, ip_address, filterType):
    packets = []
    capture = pyshark.FileCapture(pcap_file, display_filter=f"ip.{filterType} == {ip_address}")
    for packet in capture:
        packets.append(packet)
    return packets

def plot_packet_count(packets1, packets2, ip_address, filterType):
    count1 = len(packets1)
    count2 = len(packets2)
    
    plt.bar([' Mini On', ' Mini Off'], [count1, count2])
    plt.xlabel('Files')
    plt.ylabel('Packet Count')
    if filterType == "addr":
        plt.title(f'Total Packet Count for Google Home Mini')
    if filterType == "src":
        plt.title(f'Packet Count with Source of Google Home Mini')
    if filterType == "dst":
        plt.title(f'Packet Count with Desination of Google Home Mini')
    plt.show()

# comment out and uncomment for each packet type and switch type to plot
def main():
    offMini = 'Google_Home_Mini_Off.pcapng'
    onMini = 'Google_Home_Mini_On.pcapng'
    ipAddress = '192.168.8.232'  # IP address of my Google Home Mini

    # onPackets = filter_packets_total(offMini, ipAddress, "addr")
    # offPackets = filter_packets_total(onMini, ipAddress, "addr")

    # onPackets = filter_packets_total(offMini, ipAddress, "src")
    # offPackets = filter_packets_total(onMini, ipAddress, "src")

    onPackets = filter_packets_total(onMini, ipAddress, "dst")
    offPackets = filter_packets_total(offMini, ipAddress, "dst")

    plot_packet_count(onPackets, offPackets, ipAddress, "dst")

if __name__ == "__main__":
    main()