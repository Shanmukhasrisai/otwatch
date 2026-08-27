"""Packet capture engine - passive OT traffic monitor."""
from scapy.all import sniff, IP, TCP, Raw
from otwatch.protocols.modbus import parse_modbus
from otwatch.inventory import Inventory
from otwatch.alerts import AlertEngine

class OTSniffer:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.inventory = Inventory()
        self.alerts = AlertEngine()

    def process_packet(self, pkt):
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        payload = bytes(pkt[Raw].load)

        # Modbus TCP runs on port 502
        if 502 in (sport, dport):
            event = parse_modbus(src_ip, dst_ip, sport, dport, payload)
            if event:
                self.inventory.register(src_ip, role="client", protocol="modbus")
                self.inventory.register(dst_ip, role="server", protocol="modbus")
                self.inventory.log_event(event)
                self.alerts.check(event)

    def start(self, filter_bpf="tcp port 502"):
        print(f"[*] OTWatch listening on {self.interface}... Press Ctrl+C to stop.")
        sniff(iface=self.interface, filter=filter_bpf,
              prn=self.process_packet, store=False)

if __name__ == "__main__":
    import sys
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    OTSniffer(interface=iface).start()
