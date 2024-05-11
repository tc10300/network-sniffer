import struct
from scapy.all import *
import tkinter as tk
import netifaces as nt

protocol_names = {
    6: "TCP",
    17: "UDP",
    1: "ICMP",
    2: "IGMP",
    47: "GRE",
}
ether_type_names = {
    0x0001: "ISO 8802-3 CSMA/CD",
    0x0002: "ISO 8802-2 LLC",
    0x0003: "ISO 8802-2 LLC",
    0x0004: "ISO 8802-3 CSMA/CD",
    0x0005: "ISO 8802-3 CSMA/CD",
    0x0006: "ISO 8802-3 CSMA/CD",
    0x0007: "ISO 8473 OSI Network Layer over IPX",
    0x0008: "ISO 8802-3 CSMA/CD",
    0x0009: "ISO 8802-3 CSMA/CD",
    0x000B: "NBS Internet Exchange Protocol",
    0x000C: "Ethernet CSMA/CD",
    0x000D: "Ethernet CSMA/CD",
    0x000E: "Ethernet CSMA/CD",
    0x000F: "Ethernet CSMA/CD",
    0x0010: "ISO 8802-3 CSMA/CD",
    0x0014: "X.25 Frame Relay",
    0x0017: "QNX Qnet",
    0x0018: "IEEE 802.1Q VLAN Tagging",
    0x0019: "VLAN doubled-tagged frames",
    0x001B: "Multi-Link Frame Relay (FRF.15)",
    0x001C: "IEEE 802.1Q VLAN Double-Tagging",
    0x001D: "Inter-Switch Link (ISL) between devices",
    0x001E: "VLAN doubled-tagged frames",
    0x0020: "IEEE 802.3",
    0x0021: "ISO 8802-3",
    0x0022: "ISO 8802-3",
    0x002F: "Cisco Discovery Protocol",
    0x0030: "IEEE 802.3x Flow Control",
    0x0040: "IEEE 802.3",
    0x0041: "IEEE 802.3",
    0x0042: "IEEE 802.3",
    0x0043: "IEEE 802.3",
    0x0050: "ISO 8802-2 LLC",
    0x0051: "ISO 8802-2 LLC",
    0x0052: "ISO 8802-3 CSMA/CD",
    0x0060: "IEEE 802.3",
    0x0071: "Nortel QIC SONET Annex D",
    0x0080: "Xerox PUP",
    0x0081: "Xerox PUP Address Translation",
    0x0088: "IEEE 802.1Q",
    0x0099: "Nortel QIC SONET",
    0x009A: "Nortel QIC SONET",
    0x00A0: "BRIDGE TUNNEL",
    0x00A1: "IBM SNA Services over Ethernet",
    0x00A2: "IBM SNA Services over Ethernet",
    0x00A3: "IBM SNA Services over Ethernet",
    0x00C0: "DEC MOP Duplicate",
    0x00C1: "DEC MOP Duplicate",
    0x00C2: "DEC MOP Remote Console",
    0x00C3: "DEC MOP Remote Console",
    0x00C4: "DEC Ethernet CSMA/CD",
    0x00C5: "DEC Ethernet CSMA/CD",
    0x00C6: "DEC MOP Protocol",
    0x00C7: "DEC Ethernet CSMA/CD",
    0x00C8: "DEC MOP Extension",
    0x00C9: "DEC MOP Extension",
    0x00CC: "DEC Unextended LAN",
    0x00CD: "DEC Unextended LAN",
    0x0100: "ISO 8802-3 CSMA/CD",
    0x0200: "IBM Channel-to-Channel Protocol",
    0x0201: "IBM Channel-to-Channel Protocol",
    0x0231: "OSI Network Layer over CLNP",
    0x0232: "OSI Network Layer over CLNP",
    0x0233: "OSI Transport Layer over CLNP",
    0x0234: "OSI Session Layer over CLNP",
    0x0280: "IBM SNA Services over Ethernet",
    0x02FF: "IBM SNA Services over Ethernet",
    0x0300: "APOLLO Domain",
    0x0400: "Xerox NS IDP",
    0x0401: "Xerox NS IDP",
    0x0800: "IPv4",
    0x0801: "Xerox PUP",
    0x0802: "Xerox PUP Address Translation",
    0x0803: "XNS (Xerox Network Systems)",
    0x0804: "ISO 8072",
    0x0805: "ISO 8878",
    0x0608: "ARP",
    0x0806: "ARP",
    0x0807: "AppleTalk Protocol",
    0x0808: "Banyan VINES",
    0x0809: "IBM NetBIOS Frames",
    0x080A: "IBM NetBIOS Frames",
    0x080B: "Cabletron",
    0x080C: "3Com Bridge",
    0x080D: "3Com Bridge",
    0x080E: "DEC LAN Traffic",
    0x080F: "DEC Local Area Transport",
    0x0810: "DEC Diagnostic",
    0x0811: "DEC Unassigned",
    0x0812: "DEC Unassigned",
    0x0813: "DEC MOP Remote Console",
    0x0814: "DEC DECNET Phase IV",
    0x0815: "DEC DECNET Phase IV",
    0x0816: "DEC LAT",
    0x0817: "DEC Diagnostic",
    0x0818: "VAXELN",
    0x0819: "VAXELN",
    0x081A: "FRF.16.1",
    0x081B: "FRF.16.1",
    0x081C: "DEC Unassigned",
    0x081D: "DEC MOP Protocol",
    0x0822: "LMI Management",
    0x0823: "DEC Unassigned",
    0x0824: "DEC Unassigned",
    0x0825: "DEC Unassigned",
    0x0826: "DEC Unassigned",
    0x0827: "DEC DECnet Phase IV",
    0x0828: "DEC Diagnostic",
    0x0829: "DEC Diagnostic",
    0x082A: "DEC Unassigned",
    0x082B: "DEC Unassigned",
    0x082C: "DEC Unassigned",
    0x082D: "DEC DECnet Phase IV",
    0x082E: "DEC Unassigned",
    0x082F: "DEC Unassigned",
    0x0830: "DEC Private",
    0x0831: "DEC Private",
    0x0832: "DEC Private",
    0x0833: "DEC Private",
    0x0834: "DEC Private",
    0x0835: "DEC Private",
    0x0836: "DEC Private",
    0x0837: "DEC Private",
    0x0838: "DEC Private",
    0x0839: "DEC Private",
    0x083A: "DEC Private",
    0x083B: "DEC Private",
    0x083C: "DEC Private",
    0x083D: "DEC Private",
    0x083E: "DEC Private",
    0x083F: "DEC Private",
    0x0840: "NBS Internet Exchange Protocol",
    0x0842: "AARP (AppleTalk)",
    0x0843: "AARP (AppleTalk)",
    0x0844: "AARP (AppleTalk)",
    0x0845: "AARP (AppleTalk)",
    0x0846: "AARP (AppleTalk)",
    0x0847: "AARP (AppleTalk)",
    0x0848: "AARP (AppleTalk)",
    0x0849: "AARP (AppleTalk)",
    0x084A: "AARP (AppleTalk)",
    0x084B: "AARP (AppleTalk)",
    0x084C: "AARP (AppleTalk)",
    0x084D: "AARP (AppleTalk)",
    0x084E: "AARP (AppleTalk)",
    0x084F: "AARP (AppleTalk)",
    0x0850: "TRAIL",
    0x0851: "TRILL",
    0x0852: "DEC LANBridge",
    0x0853: "DEC LANBridge",
    0x0854: "DEC LANBridge",
    0x0855: "DEC LANBridge",
}

class ListShow:
    process=None
    def __init__(self,root,iface):
        self.interface_Name = iface
        self.root=root
        self.detect=Detect(self.interface_Name)
        self.canvas=tk.Canvas(root)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollBar = tk.Scrollbar(self.root,command=self.canvas.yview)
        self.scrollBar.pack(side=tk.RIGHT, fill=tk.Y)
        self.canvas.configure(yscrollcommand=self.scrollBar.set)
        self.frame = tk.Frame(self.canvas)
        self.frame.pack(anchor=tk.CENTER,fill=tk.BOTH,expand=True) 
        self.canvas.create_window((0,0), window=self.frame, anchor="nw")

    def PacketSniff(self,packet):
        button=tk.Button(self.frame,text=packet.summary(),anchor='w',command=lambda p=packet:self.detect.detail(p))
        button.pack(side=tk.TOP,fill=tk.X)
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        self.canvas.yview_moveto(1)
    
    def Sniff_count(self):
        self.process=AsyncSniffer(prn=self.PacketSniff,iface=self.interface_Name,count=20)
        self.process.start()
        
    def Sniff_all(self):
        self.process=AsyncSniffer(prn=self.PacketSniff,iface=self.interface_Name)
        self.process.start()
        
    def terminate(self):
        self.process.stop()
        
    def clear(self):
        self.scrollBar.pack_forget()
        self.canvas.pack_forget()
        
class Detect: 

    def __init__(self, name):
        self.interface_name = name
        
    def detail(self,packet):
        win=tk.Tk()
        win.title(packet.summary())
        win.geometry('500x500')
        text=tk.Text(win)
        text.pack(fill="both",expand=True)
        self.transportLayer(packet,text)
        self.analyze_ip_packet(packet,text)
        self.analyze_ether(packet,text)
        win.mainloop()
        
    def transportLayer(self,packet,text):
        def udp_segment():
            try:
                packet_bytes = bytes(packet[UDP])
                src_port,des_port,length,checksum= struct.unpack("!HHHH", packet_bytes[:8])
                text.insert(tk.END, "UDP segment:\n")
                text.insert(tk.END, f"Source Port: {src_port}\n")
                text.insert(tk.END, f"Destination Port: {des_port}\n")
                text.insert(tk.END, f"UDP length: {length}\n")
                text.insert(tk.END, f"Checksum: {checksum}\n")
                text.insert(tk.END,"----------------------------------\n")
            except IndexError:
                text.insert(tk.END, "No UDP layer found in the packet.\n")
                text.insert(tk.END,"----------------------------------\n")   
        def tcp_segment():
            try:
                packet_bytes = bytes(packet[TCP])
                src_port,des_port,seq,ack,offset,flags,windows,checksum,urgent = struct.unpack("!HHIIBBHHH", packet_bytes[:20])
                length=(offset>>4)*4
                urg=(flags&32)>>5
                ack=(flags&16)>>4
                psh=(flags&8)>>3
                rst=(flags&4)>>2
                stn=(flags&2)>>1
                fin=(flags&1)
                text.insert(tk.END, "TCP segment:\n")
                text.insert(tk.END, f"Source Port: {src_port}\n")
                text.insert(tk.END, f"Destination Port: {des_port}\n")
                text.insert(tk.END, f"Sequence Number: {seq}\n")
                text.insert(tk.END, f"Acknowledgment Number: {ack}\n")
                text.insert(tk.END, f"Segment Length: {length}\n")
                text.insert(tk.END, f"Window Size: {windows}\n")
                text.insert(tk.END, f"Checksum: {checksum}\n")
                text.insert(tk.END, f"Urgent Pointer: {urgent}\n")
                text.insert(tk.END, f"URG: {urg}\n")
                text.insert(tk.END, f"ACK: {ack}\n")
                text.insert(tk.END, f"PSH: {psh}\n")
                text.insert(tk.END, f"RST: {rst}\n")
                text.insert(tk.END, f"STN: {stn}\n")
                text.insert(tk.END, f"FIN: {fin}\n")
                text.insert(tk.END,"----------------------------------\n")
            except IndexError:
                text.insert(tk.END, "No TCP layer found in the packet.\n")
                text.insert(tk.END,"----------------------------------\n")                                       
        if TCP in packet:
            tcp_segment()
        elif UDP in packet:
            udp_segment()
        else:
            text.insert(tk.END, "No transport layer found in the packet.\n")
            text.insert(tk.END,"----------------------------------\n") 
            
    def analyze_ip_packet(self,packet,text):
        def analyze_ipv4_packet():
            try:
                packet_bytes=bytes(packet[IP])
                version_and_IHL,ToS,total_length,identification,flags_and_offset,ttl,protocol,checkSum,src_ip,dst_ip= struct.unpack("!BBHHHBBH4s4s", packet_bytes[:20])
                version = version_and_IHL>>4
                header_length=version_and_IHL & 0b00001111 
                flag=flags_and_offset >>13
                offset=flags_and_offset & 0b0001111111111111
                protocol_num=protocol
                protocol_name = protocol_names.get(protocol_num, "Unknown Protocol")
                text.insert(tk.END, f"IPv4 Packet:\n")
                text.insert(tk.END, f"Version: {version}\n")
                text.insert(tk.END, f"Header Length: {header_length*4} bytes\n")
                text.insert(tk.END, f"DSCP:{ToS>>2}\n")
                text.insert(tk.END, f"ECN:{ToS & 0b00000011}\n")
                text.insert(tk.END, f"Total length: {total_length}\n")
                text.insert(tk.END, f"Identification: {identification}\n")
                text.insert(tk.END, f"Flag:{flag}\n")
                text.insert(tk.END, f"Offset: {offset}\n")
                text.insert(tk.END, f"TTL: {ttl}\n")
                text.insert(tk.END, f"Protocol: {protocol_name}\n")
                text.insert(tk.END, f"Checksum: {checkSum}\n")
                text.insert(tk.END, f"Source IP: {'.'.join(map(str, src_ip))}\n")
                text.insert(tk.END, f"Destination IP: {'.'.join(map(str, dst_ip))}\n") 
                text.insert(tk.END,"----------------------------------\n") 
            except IndexError:
                text.insert(tk.END, "No IP layer found in the packet.\n")
                text.insert(tk.END,"----------------------------------\n")  
        def analyze_ipv6_packet():
            try:
                ipv6=packet[IP]
                ipv6_bytes = bytes(ipv6)
                version_tc_flow, payload_length, next_header, hop_limit = struct.unpack('!IHBB', ipv6_bytes[:8])
                version = version_tc_flow >> 28
                tc = (version_tc_flow >> 20) & 0x000000FF
                flow = version_tc_flow & 0x000FFFFF
                src_ip = str(ipv6.src)
                dst_ip = str(ipv6.dst)
                text.insert(tk.END, f"IPv6 Packet:\n")
                text.insert(tk.END, f"version: {version}\n")
                text.insert(tk.END, f"traffic class: {tc}\n")
                text.insert(tk.END, f"flow: {flow}\n")
                text.insert(tk.END, f"payload length: {payload_length}\n")
                text.insert(tk.END, f"next header: {next_header}\n")
                text.insert(tk.END, f"hop limit: {hop_limit}\n")
                text.insert(tk.END, f"source ip: {src_ip}\n")
                text.insert(tk.END, f"destination ip: {dst_ip}\n")
                text.insert(tk.END, "----------------------------------\n")
            except IndexError:
                text.insert(tk.END, "No IP layer found in the packet.\n")
                text.insert(tk.END,"----------------------------------\n")  
        if "IPv6" in packet:
            analyze_ipv6_packet()
        else:
            analyze_ipv4_packet()
            
    def analyze_ether(self,packet,text):
        ether_bytes=bytes(packet[Ether])
        dst_addr, src_addr,ether_type= struct.unpack('6s6sH', ether_bytes[:14])
        dst_addr_str = ':'.join(f'{byte:02x}' for byte in dst_addr)
        src_addr_str = ':'.join(f'{byte:02x}' for byte in src_addr)
        ether_type_16= f'{ether_type:04x}'
        ether_type_name=ether_type_names.get(ether_type, "Unknown")
        text.insert(tk.END, f"Source MAC: {src_addr_str}\n")
        text.insert(tk.END, f"Destination MAC: {dst_addr_str}\n")
        text.insert(tk.END, f"Ether type :0x{ether_type_16}:{ether_type_name}\n")
        text.insert(tk.END,"----------------------------------\n")
        
class ctl:
    def __init__(self,root):
        self.root=root
        self.button_frame=None
        self.card_frame=None
        
    def card_choose(self):
        self.button_frame=tk.Frame(self.root)
        self.button_frame.pack(side=tk.BOTTOM)
        self.card_frame=tk.Frame(self.root)
        self.card_frame.pack(side=tk.TOP)
        label=tk.Label(self.card_frame,text="请选择网卡")
        label.pack(anchor=tk.CENTER,side=tk.TOP)
        for iface in nt.interfaces():
            button=tk.Button(self.card_frame,text=iface,command=lambda iface=iface,card_frame=self.card_frame,button_frame=self.button_frame:self.create(iface))
            button.pack(anchor=tk.CENTER,side=tk.TOP)
            
    def create(self,iface):
        self.card_frame.pack_forget()
        myShow = ListShow(self.root,iface)
        Return=tk.Button(self.button_frame, text="返回", command=lambda :(self.button_frame.pack_forget(),myShow.clear(),self.card_choose()))
        Return.pack(side=tk.LEFT,anchor=tk.CENTER)
        start_1 = tk.Button(self.button_frame, text="批量抓包", command=lambda :myShow.Sniff_count())
        start_1.pack(side=tk.LEFT,anchor=tk.CENTER)
        start_2 = tk.Button(self.button_frame, text="动态抓包", command=lambda :myShow.Sniff_all())
        start_2.pack(side=tk.LEFT,anchor=tk.CENTER)
        stop = tk.Button(self.button_frame, text="停止抓包", comma=lambda :myShow.terminate())
        stop.pack(side=tk.LEFT,anchor=tk.CENTER)

if __name__ == "__main__":
    root = tk.Tk()
    root.title('抓包神器')
    root.geometry('600x600')
    myCtl=ctl(root)
    myCtl.card_choose()
    root.mainloop()