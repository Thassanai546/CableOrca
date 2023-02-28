from scapy.all import *
from scapy.all import IP
import tkinter as tk

from net_interfaces import *
from file_manager import *


class SnifferWindow(tk.Frame):
    def __init__(self, parent, duration, interface):
        super().__init__(parent)
        self.pack()

        # Packet view frame contains a live packet analysis window
        # and a "Save Results" button.
        self.packet_view_frame = tk.Frame(self)
        self.packet_view_frame.pack()

        # Building the live packet output display
        # It uses consolas font. Note that changing font affects width and height
        # values of the live packet output field.
        self.packet_field = tk.Text(self.packet_view_frame, height=17, width=125, font=(
            "consolas", 10), pady=10)  # WIDTH and HEIGHT set here
        self.packet_field.pack(side=tk.LEFT)

        self.scrollbar = tk.Scrollbar(
            self.packet_view_frame, command=self.packet_field.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.packet_field.config(yscrollcommand=self.scrollbar.set)

        # Add a "Stop" button to the GUI, to stop network analysis.
        self.stop_button = tk.Button(
            self, text="Stop Analysis", command=self.stop_sniffing, width=20, bg="red", font=("Calibri", 11))
        self.stop_button.pack(pady=10)

        # Duration and interface from "def init"
        self.duration = duration
        self.interface = interface

        # All Interfaces = "None" as an interface for scapy sniff() function.
        if self.interface == "All Interfaces.":
            self.interface = interface = None  # None sniffs all interfaces in scapy sniff()

        # Starting a new thread as scapy sniff() blocks execution until
        # sniff() is finished.
        # Live output of packets requires the use of a thread
        # so that GUI remains active.
        self.stop_sniff = threading.Event()
        self.sniff_thread = threading.Thread(target=self.initiate_sniffer)
        self.sniff_thread.start()
        # Note Python will clean up once thread process is complete.

    def stop_sniffing(self):
        # Used to terminate sniffing thread
        self.stop_sniff.set()

    def initiate_sniffer(self):
        # Initiate sniffer calls Scapy's sniff() function. Sniff() takes "display_packet" function
        # as an argument. This function is called on each packet that Scapy captures.

        def display_packet(packet):
            # Take a packet and append it to the text field on the GUI.
            self.packet_field.insert(tk.END, packet.summary() + "\n")
            self.packet_field.update_idletasks()
            self.packet_field.see('end')

        try:
            def call_pcap_saver():
                # called by "save_button"
                save_result = ""
                if save_to_pcap(captured_packets):  # Call file_manager.py function
                    save_result = ".PCAP File Saved"
                else:
                    save_result = ".PCAP Not File Saved"

                message.config(text=save_result)

            # iface = interface, prn = processing done for each packet, timeout = duration of analysis,
            # store = true grants ability to save capture to a .pcap file
            # stop_filter = stop thread that is running sniff function. Stopping sniff jumps to "create_pcap_saver_frame".
            captured_packets = sniff(iface=self.interface, prn=display_packet, store=True,
                         timeout=self.duration, stop_filter=lambda p: self.stop_sniff.is_set())

            # Prevent the user from accidently typing inisde the packet output field.
            self.packet_field.config(state="disabled")

            self.stop_button.config(state="disabled", bg="grey")

            # Packet sniffing has ended, display message and save button.
            message = tk.Label(self, text="Packet Sniffing Complete.",
                               font=("Calibri", 13), pady=5)
            message.pack()

            # save_to_pcap function from file_manager.py used.
            save_button = tk.Button(self, text="Click here to save file",
                                    command=call_pcap_saver, width=20, font=("Calibri", 11), bg="white")
            save_button.pack(pady=10)

        # Errors are displayed on the GUI inside the packet_field text area.
        except OSError as ex:
            # Network interface error
            error_message = f"Error: {ex.strerror}"
            self.packet_field.insert(tk.END, error_message)
            self.packet_field.update_idletasks()
            self.packet_field.see('end')

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


# Packet parsing and output formats.

def handler(packet):
    # Packet summary for each captured packet.
    return packet.summary()


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
        # If we fail to parse a packet, don't attempt to display that packet.
        return ("")
