"""Packet capture engine - passive OT traffic monitor."""
from scapy.all import sniff, IP, TCP, Raw
from otwatch.protocols.registry import get_parser_for_port
from otwatch.inventory import Inventory
from otwatch.alerts import AlertEngine
import time

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

        # Try to find a parser for either source or destination port
        parser = get_parser_for_port(sport) or get_parser_for_port(dport)
        if parser is None:
            return

        # parser.parse returns list[OTEvent]
        events = parser.parse(src_ip, dst_ip, sport, dport, payload, timestamp=time.time())
        for event in events:
            # keep registering assets and logging events as before
            self.inventory.register(event.source, role="client", protocol=event.protocol)
            self.inventory.register(event.destination, role="server", protocol=event.protocol)
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
