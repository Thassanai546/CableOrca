from collections import Counter
from ipwhois import IPWhois
from scapy.all import IP
from scapy.all import *
import tkinter as tk
from graph import *
import threading

from file_manager import *

# Globals
pcap_file_name = None
pcap_file_list = None


class ReaderWindow(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.pack()

        pcap_reading_window_font = "Calibri"

        # Heading
        self.heading = tk.Label(
            self, text="Please select a PCAP file to read.", font=(pcap_reading_window_font, 14))
        self.heading.pack()

        # Button frame
        self.button_frame = tk.Frame(self)
        self.button_frame.pack()

        # Select file button
        self.select_file_btn = tk.Button(self.button_frame, text="Select File", width=15,
                                         command=self.select_file_clicked, font=(pcap_reading_window_font, 12), bg="#58d68d")
        self.select_file_btn.pack(side=tk.LEFT, pady=5, padx=5)

        # Tiered buttons instructions:
        # Command = self.specified_command
        # A specified_command should follow the "clicked button"
        # Guidelines specified below.
        # For each button, enable it once a file has been selected
        # This is done in select_file_clicked()

        # Tier 1
        self.tier_one = tk.Button(self.button_frame, text="Tier 1", width=15,
                                  command=self.tier_one_clicked, font=(pcap_reading_window_font, 12))
        self.tier_one.pack(side=tk.LEFT, pady=5, padx=5)
        self.tier_one.config(state=tk.DISABLED)

        # Tier 2
        self.tier_two = tk.Button(self.button_frame, text="Tier 2", width=15,
                                  command=self.tier_two_clicked, font=(pcap_reading_window_font, 12))
        self.tier_two.pack(side=tk.LEFT, pady=5, padx=5)
        self.tier_two.config(state=tk.DISABLED)

        # Tier 3
        self.tier_three = tk.Button(self.button_frame, text="Tier 3", width=15,
                                    command=self.tier_three_clicked, font=(pcap_reading_window_font, 12))
        self.tier_three.pack(side=tk.LEFT, pady=5, padx=5)
        self.tier_three.config(state=tk.DISABLED)

        # Packet view frame
        self.packet_read_frame = tk.Frame(self)
        self.packet_read_frame.pack()

        # Packet view text area
        self.packet_field = tk.Text(self.packet_read_frame, height=13, width=130, font=(
            "consolas", 10), pady=10)  # WIDTH and HEIGHT set here
        self.packet_field.pack(side=tk.LEFT)

        self.scrollbar = tk.Scrollbar(
            self.packet_read_frame, command=self.packet_field.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.packet_field.config(yscrollcommand=self.scrollbar.set)

        # Stop reading button, disabled by default
        self.stop_button = tk.Button(
            self, text="Stop Reading", command=self.stop_reading_thread, width=20, bg="red", font=(pcap_reading_window_font, 11))
        self.stop_button.pack(pady=10)

        self.stop_button.config(state=tk.DISABLED)

    def select_file_clicked(self):
        # Select file button clicked.
        # Try, as user may not always select a file
        try:
            global pcap_file_name
            global pcap_file_list
            # read_pcap uses rdpcap(file) and returns a list of packets.
            pcap_file_name, pcap_file_list = read_pcap()

            # Change heading to file selected
            # Strip path, display only filename.
            pcap_file_name_stripped = os.path.basename(pcap_file_name)
            read_info = "Selected File: " + pcap_file_name_stripped
            self.heading.config(text=read_info)

            # Enable analysis buttons now that a file has been selected.
            self.tier_one.config(state=tk.NORMAL)
            self.tier_two.config(state=tk.NORMAL)
            self.tier_three.config(state=tk.NORMAL)
        except:
            read_info = "No File Selected."
            self.heading.config(text=read_info)

    # Writing button clicked events:
    # Define global packet list var
    # Clear existing packet field
    # Enable the stop button
    # Call thread primer with specified thread name.

    def tier_one_clicked(self):
        global pcap_file_list
        self.clear_packet_field()
        self.stop_button.config(state=tk.NORMAL)
        self.thread_primer(pcap_file_list, "raw_read_thread")

    def tier_two_clicked(self):
        global pcap_file_list
        self.clear_packet_field()
        self.stop_button.config(state=tk.NORMAL)
        self.thread_primer(pcap_file_list, "composition_read_thread")

    def tier_three_clicked(self):
        global pcap_file_list
        self.clear_packet_field()
        self.stop_button.config(state=tk.NORMAL)
        self.thread_primer(pcap_file_list, "socket_read")

    # THREAD PRIMER takes a READ THREAD
    def thread_primer(self, packet_list, target_func_name):
        self.packet_field.delete("1.0", tk.END)
        self.thread_stop = threading.Event()
        target_func = getattr(self, target_func_name)

        # Note args=(), from the thread constructor expects a tuple of arguments.
        # (packet_list,) = tuple with one element
        # (packet_list) = single argument
        # This is why ',' is needed.
        read_thread = threading.Thread(
            target=target_func, args=(packet_list,))
        read_thread.start()

    # READ THREADS - These are passed in to thread_primer for .pcap analysis.

    def raw_read_thread(self, packet_list):
        # THREAD A
        # Raw read, no analysis
        for pkt in packet_list:
            # Stop thread if stop button has been clicked
            if self.thread_stop.is_set():
                self.stop_button.config(state=tk.DISABLED)
                break

            # Stop button not clicked, print to packet field
            self.packet_field.insert(tk.END, str(pkt))
            self.packet_field.insert(tk.END, '\n')
            self.packet_field.see(tk.END)

        # Once read is finished, disable "stop button"
        # Alert user
        self.stop_button.config(state=tk.DISABLED)
        self.heading.config(text="File Reading Complete!")

    def composition_read_thread(self, packet_list):
        # THREAD B
        self.stop_button.config(state=tk.DISABLED)
        global pcap_file_name

        ip_address_counter = Counter()

        for pkt in packet_list:
            if 'IP' in pkt:
                source_ip = pkt['IP'].src
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

        initial_output = "Below are the percentages representing the composition of:\n" + \
            pcap_file_name + '\n'
        self.packet_field.insert(tk.END, initial_output)
        self.packet_field.see(tk.END)

        # Iterate list of tuples
        for entry in sorted_percentages:
            address, percentage = entry
            address = search_org(address)
            current_output = ("{}: {:.2f}%\n".format(address, percentage))
            # print(current_output)
            self.packet_field.insert(tk.END, str(current_output))
            self.packet_field.see(tk.END)

        composition = public_private_composition(pcap_file_name)
        self.packet_field.insert(tk.END, '\n')
        self.packet_field.insert(tk.END, str(composition))
        self.packet_field.see(tk.END)
        self.heading.config(text="File Reading Complete!")

    def socket_read(self, packet_list):
        # THREAD C
        global pcap_file_name

        for pkt in packet_list:
            if self.thread_stop.is_set():
                self.stop_button.config(state=tk.DISABLED)
                break

            result = socket_translator(pkt)
            if result:
                # Only attempt insert if a result is given.
                self.packet_field.insert(tk.END, result + '\n')
                self.packet_field.see(tk.END)

        composition = public_private_composition(pcap_file_name)
        self.packet_field.insert(tk.END, '\n')
        self.packet_field.insert(tk.END, str(composition))
        self.packet_field.see(tk.END)
        self.heading.config(text="[!] Socket Translate Concluded.")
        self.stop_button.config(state=tk.DISABLED)

    # Thread and packet_field management.
    def stop_reading_thread(self):
        # Called by "Stop Reading" button
        self.thread_stop.set()

    def clear_packet_field(self):
        self.packet_field.delete("1.0", tk.END)
        print("Text field wiped.")


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

        return (f"This pcap file is {'{:.2f}'.format(public_percent)}% public addresses\n"
                f"This pcap file is {'{:.2f}'.format(private_percent)}% private addresses.")

    except FileNotFoundError:
        return (f"Error: Could not find file {pcap_file}")
    except Exception as e:
        return (f"An error occurred: {e}")


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
        return f"{src_attempted_resolve} -> {dst_attempted_resolve}"
