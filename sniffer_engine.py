from pcap_parser import is_private_ip
from scapy.all import *
from scapy.all import IP, TCP, UDP
import tkinter as tk

from net_interfaces import *
from file_manager import *


class SnifferWindow(tk.Frame):
    def __init__(self, parent, duration, interface, view_bool):
        super().__init__(parent)
        self.pack()

        # SnifferWindow takes a duration and an interface as arguments
        self.duration = duration
        self.interface = interface
        self.view_bool = view_bool
        self.device_ip = get_if_addr('default')

        # Packet view frame contains a live packet analysis window
        self.packet_view_frame = tk.Frame(self)
        self.packet_view_frame.pack()

        # Building the live packet output display with a vertical scrollbar
        self.packet_field = tk.Text(self.packet_view_frame, height=17,
                                    width=110, font=12, pady=10, padx=10)  # WIDTH and HEIGHT set here
        self.packet_field.pack(side=tk.LEFT)

        self.scrollbar = tk.Scrollbar(
            self.packet_view_frame, command=self.packet_field.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.packet_field.config(yscrollcommand=self.scrollbar.set)

        # Analysis stop button
        self.stop_button = tk.Button(
            self, text="Stop Analysis", command=self.stop_sniffing, width=20, bg="red", font=("Calibri", 12))
        self.stop_button.pack(pady=10)

        """
        All Interfaces = "None" as an interface for scapy sniff() function.
        Defined in "net_interfaces.py" -> interfaces_to_name_list()
        """
        if self.interface == "ALL INTERFACES":
            self.interface = interface = None  # None sniffs all interfaces in scapy sniff()

        """
        Starting a new thread as scapy sniff() blocks execution until sniff() is finished.
        Live output of packets on to GUI requires the use of a thread so that GUI remains active.
        """
        self.stop_sniff = threading.Event()
        self.sniff_thread = threading.Thread(target=self.initiate_sniffer)
        self.sniff_thread.start()
        # Note Python will clean up once thread process is complete.

    def stop_sniffing(self):
        # Used to terminate sniffing thread
        self.stop_sniff.set()

    def initiate_sniffer(self):
        """
        Initiate_sniffer is run in it's own thread.
        This thread is controlled by "stop_sniffing"
        """

        # Default packet display option
        def display_packet(packet):
            # Take a packet and append it to the text field on the GUI.
            self.packet_field.insert(tk.END, packet.summary() + "\n")
            self.packet_field.update_idletasks()
            self.packet_field.see('end')

        # Alternate method of displaying live packets
        # This is set by the checkbox on CableOrca.py's frame
        def display_compact_packet(packet):
            # Take a packet and append it to the text field on the GUI.
            self.packet_field.insert(tk.END, clean(packet) + "\n")
            self.packet_field.update_idletasks()
            self.packet_field.see('end')

        def post_sniff():

            def call_pcap_saver():
                # called by "save_button"
                save_result = ""
                if save_to_pcap(captured_packets):  # Call file_manager.py function
                    save_result = "Capture File Saved!"
                else:
                    save_result = "Capture File Not Saved"

                # Display save result and clear message about packet capture file saving
                msg1.config(text=save_result)
                msg2.config(text="")

            # After sniff() commences, save button is spawned
            # "file_manager" file save function is called
            self.save_button = tk.Button(self, text="Save",
                                         command=call_pcap_saver, width=20, font=("Calibri", 12), bg="white")

            if len(captured_packets) == 0:
                msg_text = "Packet Sniffing Complete. No packets were captured on this interface."
                packet_field_text = "CableOrca did not detect any network activity on this interface."

                self.packet_field.config(state=tk.NORMAL)
                self.packet_field.insert(tk.END, packet_field_text)
                self.packet_field.update_idletasks()
                self.packet_field.see('end')
                self.packet_field.config(state=tk.DISABLED)

                self.save_button.config(
                    text="No Packets To Save", state=tk.DISABLED)
            else:
                msg_text = "Packet Sniffing Complete."

            # Prevent the user from accidentally typing inside the packet output field.
            self.packet_field.config(state="disabled")
            self.stop_button.config(state="disabled", bg="grey")

            msg1 = tk.Label(self, text=msg_text,
                            font=("Calibri", 16), pady=5)
            msg1.pack()

            msg2 = tk.Label(self, text="You can save a file called a 'Packet Capture File' which records network traffic.\nThis file can then be looked at more closely using CableOrca, or another program that you prefer.\nThis will give you a better understanding of what is happening with your internet connection.",
                            font=("Calibri", 16), pady=5, justify="left")
            msg2.pack()

            self.save_button.pack(pady=10)

        try:
            """
            Initiate Sniffer

            PRN = function run for each packet detected
            store = allow packet capture file saving
            stop_filter = anonymous function that checks if "self.stop_sniff" is set
            """
            if not self.view_bool:
                captured_packets = sniff(iface=self.interface, prn=display_packet, store=True,
                                         timeout=self.duration, stop_filter=lambda p: self.stop_sniff.is_set())
            else:
                captured_packets = sniff(iface=self.interface, prn=display_compact_packet, store=True,
                                         timeout=self.duration, stop_filter=lambda p: self.stop_sniff.is_set())

            # After Scapy "sniff()" has ended
            post_sniff()

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

# Packet parsing and output formats.


def clean(packet):
    """
    Takes a packet and returns a user-friendly summary of that packet as a string,
    including whether the packet is from the Internet or from the local network.
    """
    pkt_summary = ""

    # Check if the packet is an IP packet
    if IP in packet:
        # Check if the source IP is in the local network range
        if is_private_ip(IP):
            pkt_summary += "Packet is from the local network.\n"
        else:
            pkt_summary += "Packet is from the Internet.\n"

        pkt_summary += "Source IP: " + str(packet[IP].src) + "\n"
        pkt_summary += "Destination IP: " + str(packet[IP].dst) + "\n"
        proto_num = packet[IP].proto

        # Map the protocol number to its name
        # https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
        if proto_num == 6:
            proto_name = "TCP"
        elif proto_num == 17:
            proto_name = "UDP"
        else:
            proto_name = str(proto_num)

        pkt_summary += "Protocol: " + proto_name + "\n"
    else:
        pkt_summary += "Packet is not an IP packet.\n"

    # Check if the packet is a TCP or UDP packet
    if TCP in packet:
        pkt_summary += "Source Port: " + str(packet[TCP].sport) + "\n"
        pkt_summary += "Destination Port: " + str(packet[TCP].dport) + "\n"
    elif UDP in packet:
        pkt_summary += "Source Port: " + str(packet[UDP].sport) + "\n"
        pkt_summary += "Destination Port: " + str(packet[UDP].dport) + "\n"
    else:
        pkt_summary += "Packet is not a TCP or UDP packet.\n"

    return pkt_summary
