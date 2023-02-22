from collections import Counter
from ipwhois import IPWhois
from scapy.all import IP
from scapy.all import *
import tkinter as tk
from graph import *

from file_manager import *


# Resolve IP addresses using socket and WHOIS.
# Check if addresses are private.


class ReaderWindow(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.pack()

        self.packet_read_frame = tk.Frame(self)
        self.packet_read_frame.pack()

        self.packet_field = tk.Text(self.packet_read_frame, height=17, width=125, font=(
            "consolas", 10), pady=10)  # WIDTH and HEIGHT set here
        self.packet_field.pack(side=tk.LEFT)

        self.scrollbar = tk.Scrollbar(
            self.packet_read_frame, command=self.packet_field.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.packet_field.config(yscrollcommand=self.scrollbar.set)

        self.stop_button = tk.Button(
            self, text="Stop Reading", command="", width=20, bg="red", font=("Calibri", 11))
        self.stop_button.pack(pady=10)


def is_private_ip(ip_address):
    try:
        # Split the IP address into its octets
        octets = ip_address.split(".")

        # Check if the IP address is in the private IP range
        if (octets[0] == "10") or \
           (octets[0] == "172" and int(octets[1]) >= 16 and int(octets[1]) <= 31) or \
           (octets[0] == "192" and octets[1] == "168"):
            return True
        else:
            return False
    except:
        print("Invalid IP address format.")
        return False


def search(ip_address):
    # Translates public IP addresses to their respective services.
    try:
        if not is_private_ip(ip_address):
            ipwhois = IPWhois(ip_address)
            results = ipwhois.lookup_rdap()

            print(f"Organization: {results['network']['name']}")
            print(f"Country: {results['network']['country']}")
    except:
        print("Not found")
        pass


def search_org(ip_address):
    try:
        # Private addresses cannot be resolved using whois.
        if not is_private_ip(ip_address):
            ipwhois = IPWhois(ip_address)
            results = ipwhois.lookup_rdap()
            return (f"{results['network']['name']}")
        else:
            # If passed in address is private, return private address
            # Without this return, search_org returns the address as "None"
            return ip_address
    except:
        return ip_address


def display_pcap_composition():
    try:
        # Prompts for pcap file
        # Performs analysis

        selected_file = open_pcap()
        rd_file = rdpcap(selected_file)

        # Create a Counter object to store the IP addresses and their occurence count
        ip_address_counter = Counter()
        for packet in rd_file:
            if 'IP' in packet:
                source_ip = packet['IP'].src
                ip_address_counter[source_ip] += 1

        counter_sum = sum(ip_address_counter.values())

        # Counter contains ip addresses and their occurences
        # This list will contain tuples with ip addresses and their percentages.
        ips_with_percentages = []

        for address, occurences in ip_address_counter.items():
            percentage = 100 * occurences / counter_sum  # Get percentage
            ips_with_percentages.append(
                (address, percentage))  # Build a list of tuples

        sorted_percentages = sorted(
            ips_with_percentages, key=lambda x: x[1], reverse=True)

        # Lists which can be used for generating graphs.
        ips_from_counter = []
        percentages_from_counter = []

        # Iterate list of tuples
        for entry in sorted_percentages:
            address, percentage = entry
            address = search_org(address)

            # Building lists that can be used to generate graphs.
            ips_from_counter.append(address)
            percentages_from_counter.append(percentage)

            print("{}: {:.2f}%".format(address, percentage))

        # Public to private address percentage
        public_private_composition(selected_file)

        # Display graphs
        build_bc(ips_from_counter, percentages_from_counter)
        build_pc(ips_from_counter, percentages_from_counter)

    except:
        print("Error, could not analyse .pcap composition.")
        pass


def public_private_composition(pcap_file):
    # Prompts for pcap file
    # Performs analysis

    # pcap_file = open_pcap()

    try:
        # Read the PCAP file using rdpcap()
        packets = rdpcap(pcap_file)

        # Create a list to store the IP addresses
        ip_addresses = []

        # Extract the IP addresses from the packets
        for packet in packets:
            if IP in packet:
                ip_addresses.append(packet[IP].src)
                ip_addresses.append(packet[IP].dst)

        # Create a set to store unique IP addresses
        unique_ips = set(ip_addresses)

        # Create variables to keep track of public and private IP addresses
        public_ip = 0
        private_ip = 0

        # Check the type of each IP address and increment the appropriate counter
        for ip in unique_ips:
            if ip.startswith("10.") or ip.startswith("172.") or ip.startswith("192.168."):
                private_ip += 1
            else:
                public_ip += 1

        # Calculate the percentage of public and private IP addresses
        total_ips = public_ip + private_ip
        public_percent = (public_ip / total_ips) * 100
        private_percent = (private_ip / total_ips) * 100

        print(
            f"Public IP addresses: {'{:.2f}'.format(public_percent)}%\nPrivate IP addresses: {'{:.2f}'.format(private_percent)}%")

    except FileNotFoundError:
        print(f"Error: Could not find file {pcap_file}")
    except Exception as e:
        print(f"An error occurred: {e}")


# GLOBAL VARIABLES for "socket_translator"
translated_ips = {}  # stores {ip: hostname}
unknown_ips = set()  # stores ips that could not be resolved


def socket_translator(packet):
    # Resolve IP addresses from a packet to their respective hostnames.

    # Extract relevant data from packet
    src = packet.sprintf("%IP.src%")
    dst = packet.sprintf("%IP.dst%")

    # set for case where src or dst IS in unkown_ips
    src_attempted_resolve = src
    dst_attempted_resolve = dst

    # Try to translate source to an ip address
    if src not in unknown_ips:
        if src not in translated_ips:
            try:
                src_attempted_resolve = socket.gethostbyaddr(
                    src)[0]  # attempt resolve
                translated_ips[src] = src_attempted_resolve
            except socket.error:
                unknown_ips.add(src)
        else:
            src_attempted_resolve = translated_ips[src]

    # Try to translate destination to an ip address
    if dst not in unknown_ips:
        if dst not in translated_ips:
            try:
                dst_attempted_resolve = socket.gethostbyaddr(
                    dst)[0]  # attempt resolve
                translated_ips[dst] = dst_attempted_resolve
            except socket.error:
                unknown_ips.add(dst)
        else:
            dst_attempted_resolve = translated_ips[dst]

    if src != "??" or dst != "??":
        print(src_attempted_resolve, "->", dst_attempted_resolve)
