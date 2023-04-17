import threading

import ipaddress
from ipwhois import IPWhois
import socket
import tkinter as tk
from collections import Counter
from scapy.all import TCP, UDP, ICMP, IP, IPv6
from scapy.all import *

from file_manager import *


class GlobalParsingVars:
    def __init__(self):
        # These vars change for each new .pcap file selected.
        self.pcap_file_name = None
        self.pcap_file_list = None

        # Socket Translator Vars, these are persistent for CableOrca's runtime.
        self.translated_ips = {}  # stores {ip: hostname}
        self.unknown_ips = set()  # stores ips that could not be resolved

        # Initialize PCAP file protocol counters
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0

    def print_protocol_counters(self):
        print("Protocol counters:")
        print(f"TCP: {self.tcp_count}")
        print(f"UDP: {self.udp_count}")
        print(f"ICMP: {self.icmp_count}")

    def reset(self):
        self.pcap_file_name = None
        self.pcap_file_list = None
        self.translated_ips = {}
        self.unknown_ips = set()
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        print("GlobalParsingVars has been reset.")


global_parse_vars = GlobalParsingVars()


class ReaderWindow(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.pack()

        pcap_reading_window_font = "Calibri"

        # Heading
        self.heading = tk.Label(
            self, text="Welcome! Please select a PCAP file to read.", font=(pcap_reading_window_font, 18))
        self.heading.pack(pady=5)

        # Button frame
        self.button_frame = tk.Frame(self)
        self.button_frame.pack()

        # Select file button
        self.select_file_btn = tk.Button(self.button_frame, text="Select File", width=15,
                                         command=self.select_file_clicked, font=(pcap_reading_window_font, 12), bg="#58d68d")
        self.select_file_btn.pack(side=tk.LEFT, pady=5, padx=5)

        '''
        Tiered buttons instructions:
        Command = self.specified_command
        A specified_command should follow the "clicked button"
        Guidelines specified below.
        For each button, enable it once a file has been selected
        This is done in select_file_clicked()
        '''

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

        # Packet reading text area
        self.packet_field = tk.Text(self.packet_read_frame, wrap="word", height=18,
                                    width=100, font=("calibri", 14), pady=12, padx=12)  # WIDTH and HEIGHT set here
        self.packet_field.pack(side=tk.LEFT, pady=5)

        msg = "A .pcap file is a file format that stores network traffic data captured by packet sniffers. It contains a record of every packet that was captured by the sniffer, along with details like the source and destination IP addresses, the protocol used, and the time the packet was sent and received."
        self.packet_field.insert(tk.END, msg)
        self.packet_field.insert(tk.END, '\n')
        self.packet_field.see(tk.END)

        self.scrollbar = tk.Scrollbar(
            self.packet_read_frame, command=self.packet_field.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.packet_field.config(yscrollcommand=self.scrollbar.set)

        # Stop reading button, disabled by default
        self.stop_button = tk.Button(
            self, text="Stop Reading", command=self.stop_reading_thread, width=20, bg="red", font=(pcap_reading_window_font, 11))
        self.stop_button.pack(pady=10)

        # No need to stop, if nothing is currently running
        self.stop_button.config(state=tk.DISABLED)

        # Disable packet field
        self.packet_field.config(state=tk.DISABLED)

        # Explanation labels
        tk.Label(self, text="Tier 1 = Raw Read", font=(
            pcap_reading_window_font, 16)).pack()
        tk.Label(self, text="Tier 2 = Traffic Percentage Analysis",
                 font=(pcap_reading_window_font, 16)).pack()
        tk.Label(self, text="Tier 3 = Attempt to Translate Each IP Address", font=(
            pcap_reading_window_font, 16)).pack()

    def select_file_clicked(self):
        # Select file button clicked.
        # Try, as user may not always select a file
        try:
            self.heading.config(text="Please select a PCAP file to read.")

            # read_pcap uses rdpcap(file) and returns a list of packets.
            global_parse_vars.pcap_file_name, global_parse_vars.pcap_file_list = read_pcap()
            print(".PCAP File Ready to Read!")

            # Change heading to file selected
            # Strip path, display only filename.
            pcap_file_name_stripped = os.path.basename(
                global_parse_vars.pcap_file_name)
            read_info = "Selected File: " + pcap_file_name_stripped
            self.heading.config(text=read_info)

            # Enable analysis buttons now that a file has been selected.
            self.tier_one.config(state=tk.NORMAL)
            self.tier_two.config(state=tk.NORMAL)
            self.tier_three.config(state=tk.NORMAL)

        except FileNotFoundError:
            # Handle the case where the user did not select a file.
            read_info = "No File Selected."
            self.heading.config(text=read_info)
        except Exception as ex:
            # Handle other exceptions that may be thrown by read_pcap.
            print(ex)
            read_info = "No File Selected."
            self.heading.config(text=read_info)

    '''
    Writing button clicked events:
    Define global packet list var
    Clear existing packet field
    Enable the stop button
    Call thread primer with specified thread name.
    '''

    def tier_one_clicked(self):
        self.stop_button.config(state=tk.NORMAL)
        self.thread_primer(global_parse_vars.pcap_file_list, "raw_read_thread")

    def tier_two_clicked(self):
        self.stop_button.config(state=tk.NORMAL)
        self.thread_primer(global_parse_vars.pcap_file_list,
                           "composition_read_thread")

    def tier_three_clicked(self):
        self.stop_button.config(state=tk.NORMAL)
        self.thread_primer(global_parse_vars.pcap_file_list, "socket_read")

    # THREAD PRIMER takes a READ THREAD
    def thread_primer(self, packet_list, target_func_name):
        # Disable tier buttons
        self.disable_buttons()

        # Enable packet view text field
        self.packet_field.config(state=tk.NORMAL)
        self.packet_field.delete("1.0", tk.END)

        self.thread_stop = threading.Event()
        target_func = getattr(self, target_func_name)

        """
        Note args=(), from the thread constructor expects a tuple of arguments.
        (packet_list,) = tuple with one element
        (packet_list) = single argument
        This is why ',' is needed.
        """
        read_thread = threading.Thread(
            target=target_func, args=(packet_list,))
        read_thread.start()

    # READ THREADS - These are passed in to thread_primer for .pcap analysis.

    def raw_read_thread(self, packet_list):
        self.heading.config(text="Reading...")

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

        self.enable_buttons()

    def composition_read_thread(self, packet_list):
        self.heading.config(text="Reading...")

        # THREAD B
        self.stop_button.config(state=tk.DISABLED)

        ip_address_counter = Counter()

        # Testing IPV6 support. Composition requires changing "is_private_ip()"
        for pkt in packet_list:
            if 'IPv6' in pkt:
                source_ip = pkt['IPv6'].src
                ip_address_counter[source_ip] += 1
            elif 'IP' in pkt:
                source_ip = pkt['IP'].src
                ip_address_counter[source_ip] += 1

        counter_sum = sum(ip_address_counter.values())

        # Counter contains ip addresses and their occurrences
        # This list will contain tuples with ip addresses and their percentages.
        ips_with_percentages = []

        for address, occurrences in ip_address_counter.items():
            percentage = 100 * occurrences / counter_sum  # Get percentage
            ips_with_percentages.append(
                (address, percentage))  # Build a list of tuples

        sorted_percentages = sorted(
            ips_with_percentages, key=lambda x: x[1], reverse=True)

        initial_output = "Below are the percentages representing the composition of:\n" + \
            global_parse_vars.pcap_file_name + '\n\n'
        self.packet_field.insert(tk.END, initial_output)
        self.packet_field.see(tk.END)

        # Iterate list of tuples
        for entry in sorted_percentages:
            address, percentage = entry

            # Attempt to translate current IP address.
            try:
                address = search_org(address)
            except:
                print("Error translating:", address, "skipping.")
                pass

            current_output = ("{}: {:.2f}%\n".format(address, percentage))
            self.packet_field.insert(tk.END, str(current_output))
            self.packet_field.see(tk.END)

        composition = public_private_composition(
            global_parse_vars.pcap_file_name)

        self.packet_field.insert(tk.END, '\n')
        self.packet_field.insert(tk.END, str(composition))
        self.packet_field.see(tk.END)
        self.heading.config(text="File Reading Complete!")

        self.enable_buttons()

    def socket_read(self, packet_list):
        # THREAD C
        self.heading.config(text="Reading...")

        initial_output = "The speed at which CableOrca translates your IP addresses depends on how fast your computer can process the information.\n" + \
            global_parse_vars.pcap_file_name + '\n'
        self.packet_field.insert(tk.END, initial_output)
        self.packet_field.see(tk.END)

        for pkt in packet_list:
            if self.thread_stop.is_set():
                self.stop_button.config(state=tk.DISABLED)
                break

            result = socket_translator(pkt)
            if result:
                # Only attempt insert if a result is given.
                self.packet_field.insert(tk.END, result + '\n')
                self.packet_field.see(tk.END)

        composition = public_private_composition(
            global_parse_vars.pcap_file_name)

        self.packet_field.insert(tk.END, '\n')
        self.packet_field.insert(tk.END, str(composition))
        self.packet_field.see(tk.END)
        self.heading.config(text="[!] Socket Translation Concluded.")
        self.stop_button.config(state=tk.DISABLED)

        self.enable_buttons()

    # Thread and packet_field management.
    def stop_reading_thread(self):
        # Called by "Stop Reading" button
        self.thread_stop.set()

    # Button configuration functions
    def disable_buttons(self):
        # Disable tier buttons
        self.select_file_btn.config(state=tk.DISABLED)
        self.tier_one.config(state=tk.DISABLED)
        self.tier_two.config(state=tk.DISABLED)
        self.tier_three.config(state=tk.DISABLED)

    def enable_buttons(self):
        # Disable tier buttons
        self.select_file_btn.config(state=tk.NORMAL)
        self.tier_one.config(state=tk.NORMAL)
        self.tier_two.config(state=tk.NORMAL)
        self.tier_three.config(state=tk.NORMAL)


def is_private_ip(ip):
    # Utilized in public_private_composition()
    try:
        ip_addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    if ip_addr.is_private:
        return True
    else:
        return False


def search_org(ip_address):
    try:
        # Parse the input IP address and determine its type
        ip = ipaddress.ip_address(ip_address)
        is_private = ip.is_private

        # Private addresses cannot be resolved using WHOIS
        if not is_private:
            # Use the IPWhois library to perform a WHOIS lookup and extract the network name
            ipwhois = IPWhois(ip_address)
            results = ipwhois.lookup_rdap()
            return results['network']['name']
        else:
            # If the input IP address is private, return it without performing a lookup
            return str(ip)
    except ValueError:
        # If the input is not a valid IP address, raise an error
        print(f"Invalid IP address: {ip_address}")
        return str(ip)
    except Exception as e:
        # If any other error occurs, raise a more informative error message
        print(f"Error looking up network name for {ip_address}: {e}")
        return str(ip)


def public_private_composition(pcap_file):
    # Please pass in the name of the .pcap file to get composition of.
    try:

        # Performance + prevent file handle leaks.
        with open(pcap_file, "rb") as pcap:
            packets = rdpcap(pcap)

        # Extract the IP addresses from the packets
        ip_addresses = []
        for packet in packets:
            if IP in packet:
                ip_addresses.append(packet[IP].src)
                ip_addresses.append(packet[IP].dst)

        # Check if all IP addresses are private or public
        unique_ips = set(ip_addresses)
        all_private = all(is_private_ip(ip) for ip in unique_ips)
        all_public = all(not is_private_ip(ip) for ip in unique_ips)

        if all_private:
            return "This pcap file is 100% private IP addresses.\nPlease note that if you are analyzing an IPv6 pcap file and notice that all the addresses are labeled as 'private', it is likely that they are actually unique local addresses (ULA). Unlike IPv4, IPv6 does not have private addresses in the same way. "
        elif all_public:
            return "This pcap file is 100% public IP addresses."
        else:
            # Create variables to keep track of public and private IP addresses
            public_ip = 0
            private_ip = 0

            # Check the type of each IP address and increment the appropriate counter
            for ip in unique_ips:
                if is_private_ip(ip):
                    private_ip += 1
                else:
                    public_ip += 1

            # Calculate the percentage of public and private IP addresses
            total_ips = public_ip + private_ip
            if total_ips > 0:
                public_percent = (public_ip / total_ips) * 100
                private_percent = (private_ip / total_ips) * 100
            else:
                public_percent = 0
                private_percent = 0

            return f"This pcap file is {public_percent:.2f}% public addresses\nThis pcap file is {private_percent:.2f}% private addresses."

    except FileNotFoundError:
        return f"Error: Could not find file {pcap_file}"
    except Exception as e:
        return f"An error occurred: {e}"


def socket_translator(packet):
    # Resolve IP addresses from a packet to their respective host names.

    # Extract relevant data from packet
    if IP in packet:
        src = packet.sprintf("%IP.src%")
        dst = packet.sprintf("%IP.dst%")
    elif IPv6 in packet:
        src = packet.sprintf("%IPv6.src%")
        dst = packet.sprintf("%IPv6.dst%")
    else:
        # Packet does not contain IP or IPv6 headers
        return ""

    # Resolve source and destination IP addresses
    src_attempted_resolve = resolve_ip(src)
    dst_attempted_resolve = resolve_ip(dst)

    if src != "??" or dst != "??":
        return f"{src_attempted_resolve}   -->   {dst_attempted_resolve}"


def resolve_ip(ip_address):
    if ip_address in global_parse_vars.unknown_ips:
        # IP address is already known to be unresolved
        return ip_address
    elif ip_address in global_parse_vars.translated_ips:
        # IP address has already been resolved
        return global_parse_vars.translated_ips[ip_address]
    else:
        # Attempt to resolve IP address to hostname
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            # Hostname resolved, add to global dict.
            global_parse_vars.translated_ips[ip_address] = hostname
            return hostname

        # IP address could not be resolved. Add it to global set.
        except socket.error:
            global_parse_vars.unknown_ips.add(ip_address)
            return ip_address


def protocol_analysis(packet_list):

    protocol_counter = Counter()
    result = ""

    if packet_list:
        # Loop through each packet in the list
        for packet in packet_list:
            try:
                # Check the protocol of the packet
                if packet.haslayer(scapy.layers.http.HTTP):
                    protocol_counter['HTTP'] += 1
                elif packet.haslayer(scapy.layers.dns.DNS):
                    protocol_counter['DNS'] += 1
                elif packet.haslayer(scapy.layers.inet.TCP):
                    protocol_counter['TCP'] += 1
                elif packet.haslayer(scapy.layers.inet.UDP):
                    protocol_counter['UDP'] += 1
            except:
                # Ignore any packets that cannot be checked for layers
                continue

        # Build the result string
        for protocol, count in protocol_counter.items():
            result += f"\nFound {count} [{protocol}] occurrences"

        # Check if any of the four protocols exist in the Counter
        if 'HTTP' in protocol_counter:
            result += ("\n\nHTTP is the protocol that allows communication between web servers and web browsers.")
        if 'DNS' in protocol_counter:
            result += ("\n\nDNS is like a phone book for the internet. When you type a website address into your browser, such as 'www.google.com,' your computer needs to know the IP address (a unique numerical identifier) of the server that hosts that website")
        if 'TCP' in protocol_counter:
            result += ("\n\nTCP is responsible for making sure those packets are delivered in the correct order, without errors, and without being lost or duplicated.")
        if 'UDP' in protocol_counter:
            result += ("\n\nUDP is often used for applications that require real-time, low-latency communication, such as video streaming or online gaming.")
    else:
        result = "Protocol_analysis() packet list was empty."

    return result
