from scapy.all import sniff, get_if_list
from scapy.layers.inet import IP, TCP, UDP
import datetime
from collections import defaultdict

# Simulated transaction history (mock example)
transaction_history = defaultdict(lambda: {"deposits": 0, "withdrawals": 0})

def analyze_transaction(packet):
    # Mock detection of deposits and withdrawals based on packet contents
    if b"deposit" in bytes(packet):
        account = "account1"  # This would be derived from packet content in a real scenario
        transaction_history[account]["deposits"] += 1
        print(f"Deposit detected for {account}. Total deposits: {transaction_history[account]['deposits']}")
    elif b"withdrawal" in bytes(packet):
        account = "account1"
        transaction_history[account]["withdrawals"] += 1
        print(f"Withdrawal detected for {account}. Total withdrawals: {transaction_history[account]['withdrawals']}")

def packet_capture(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol_name = "TCP"
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol_name = "UDP"
        else:
            src_port = None
            dst_port = None
            protocol_name = "Other"

        print(f"[{datetime.datetime.now()}] IP src: {ip_src} -> IP dst: {ip_dst}, Protocol: {protocol_name}, Src Port: {src_port}, Dst Port: {dst_port}")

        # Analyze transactions if applicable
        analyze_transaction(packet)

# Function to start sniffing packets on a specified network interface
def start_sniffing(interface):
    print(f"Sniffing on {interface}... Press Ctrl+C to stop.")
    sniff(iface=interface, prn=packet_capture, store=False)

# Main program execution
if __name__ == "__main__":
    # List all available interfaces and prompt the user to select one
    print("Available interfaces:", get_if_list())
    interface = input("Enter the interface you want to sniff on (e.g., 'Wi-Fi', 'Ethernet'): ")

    # Start sniffing on the selected interface
    start_sniffing(interface)
