from net_interfaces import *
from file_manager import *
from scapy.all import *
from scapy.all import IP
import tkinter as tk

# Start packet analysis
# Packet output formats


class SnifferWindow(tk.Frame):
    def __init__(self, parent, duration, interface):
        super().__init__(parent)
        self.pack()

        # Packet view frame allows a "save" button
        # to be placed underneath the packet view window.
        # Without a frame the button would get placed beside it.
        self.packet_view_frame = tk.Frame(self)
        self.packet_view_frame.pack()

        # Building a text field with a vertical scrollbar.
        self.packet_field = tk.Text(self.packet_view_frame, height=14, width=115, font=(
            "consolas", 10), pady=10)  # WIDTH and HEIGHT set here
        self.packet_field.pack(side=tk.LEFT)

        self.scrollbar = tk.Scrollbar(
            self.packet_view_frame, command=self.packet_field.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.packet_field.config(yscrollcommand=self.scrollbar.set)

        # Add a "Stop" button to the GUI
        self.stop_button = tk.Button(self, text="Stop Analysis", command=self.stop_sniffing, width=20, bg="red", font=("Calibri",11))
        self.stop_button.pack(pady=10)

        # Duration and interface from "def init"
        self.duration = duration
        self.interface = interface

        # All Interfaces = "None" as an interface for scapy sniff() function.
        if (self.interface == "All Interfaces."):
            self.interface = interface = None  # None sniffs all interfaces in scapy sniff()

        # Starting a new thread as scapy sniff() blocks execution until
        # sniff() is finished.
        # Live output of packets requires the use of a thread
        # so that GUI remains active.
        self.stop_sniff = threading.Event()
        self.sniff_thread = threading.Thread(target=self.initiate_sniffer )
        self.sniff_thread.start()
        # Note Python will clean up once thread process is complete.

    def stop_sniffing(self):
        self.stop_sniff.set()

    def initiate_sniffer (self):
        # This def defines "display_packet", which appends output to a field on the gui
        # and call the sniff fucntion with "display_packet" as prn.
        # in the sniff function, prn is done for every packet captured.
        # in this case, every packet captured goes to the packet_field on the gui.
        def display_packet(packet):
            self.packet_field.insert(tk.END, packet.summary() + "\n")
            self.packet_field.update_idletasks()
            self.packet_field.see('end')

        try:
            #pkts = sniff(iface=self.interface, prn=display_packet, store=True, timeout=self.duration)

            # iface = interface, prn = processing done for each packet, timeout = duration of analysis,
            # store = true grants ability to save capture to a .pcap file
            # stop_filter = stop thread that is running sniff function. Stopping sniff jumps to "create_pcap_saver_frame".
            pkts = sniff(iface=self.interface, prn=display_packet, store=True, timeout=self.duration, stop_filter=lambda p: self.stop_sniff.is_set())
            self.packet_field.config(state="disabled") # Prevent the user from accidently typing in to the packet output field.
            self.stop_button.config(state="disabled", bg="grey")
            print("Sniffing complete")

            # call file_manager saving functions:
            create_pcap_saver_frame(self, pkts) # file_manager.py
        except Exception as ex:
            self.packet_field.insert(tk.END, ex)
            self.packet_field.update_idletasks()
            self.packet_field.see('end')


def configure_sniff():
    # Lists all interfaces
    # Asks for interface ID
    # Asks for analysis duration in seconds.
    # Let's user configure .pcap file for data captured.

    # display interfaces to console
    print_interfaces()

    # user options
    option = int(input("Enter interface ID:"))

    try:
        duration = int(
            input("Enter the duration of the network scan (in seconds):"))
    except:
        duration = 10

    # Start network analysis
    if option in interfaces_to_index_list():
        if option == 0:
            print("sniffing on all...")
            # note to thass: store=True allowed me to SAVE AND READ pcap files made by this program.
            # iface = list of all available interfaces.
            pkts = sniff(iface=interfaces_to_name_list(),
                         prn=clean, store=True, timeout=duration)
        else:
            # Interface index is translated to device name, eg "Ethernet"
            pkts = sniff(iface=dev_from_index(option),
                         prn=clean, store=True, timeout=duration)
    else:
        print("Invalid interface, choose an ID from the list above")

    # PCAP file management
    filename = create_pcap()
    append(filename, pkts)


def sniff_with(function):
    # Lists all interfaces
    # Asks for interface ID
    # Asks for analysis duration in seconds.
    # Let's user configure .pcap file for data captured.

    # display interfaces to console
    print_interfaces()

    # user options
    option = int(input("Enter interface ID:"))

    try:
        duration = int(
            input("Enter the duration of the network scan (in seconds):"))
    except:
        duration = 10

    # Start network analysis
    if option in interfaces_to_index_list():
        if option == 0:
            print("sniffing on all...")
            # note to thass: store=True allowed me to SAVE AND READ pcap files made by this program.
            # iface = list of all available interfaces.
            pkts = sniff(iface=interfaces_to_name_list(),
                         prn=function, store=True, timeout=duration)
        else:
            # Interface index is translated to device name, eg "Ethernet"
            pkts = sniff(iface=dev_from_index(option),
                         prn=function, store=True, timeout=duration)
    else:
        print("Invalid interface, choose an ID from the list above")


def handler(packet):
    # Packet summary for each captured packet.
    return (packet.summary())


def clean(packet):
    # Nicely formatted output for packet capture.
    try:
        src_mac = packet.src
        dst_mac = packet.dst
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        return (f'Time: {packet.time}\nSource MAC: {src_mac}\nDestination MAC: {dst_mac}\nSource IP: {src_ip}\nDestination IP: {dst_ip}\nProtocol: {protocol}\n')
    except:
        pass
