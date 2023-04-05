import re
import threading
from collections import Counter

import tkinter as tk
from scapy.all import *
from scapy.layers.http import *

from arp_sweeper import arp_discovery
from file_manager import read_pcap
from net_interfaces import check_internet, get_default_interface
from net_speed_test import get_speed_mbs
from pcap_parser import public_private_composition, search_org

# Questions that the wizard asks the user
questions = ["Question [1/5] Would you like me to see if I can connect to the internet?",
             "Question [2/5] Would you like me to try and measure the current network speed? If you click yes, please keep in mind that the application will need approximately 20 seconds to run the internet speedtest in the background",
             "Question [3/5] Would you like me to try and discover the names of devices on the network?",
             "Question [4/5] Would you be interested in capturing and analyzing the network traffic on your computer network?",
             "Last but not least, would you like me to analyse an existing network capture file? I can read .pcap files."]


class WizardTelemetry():
    # Holds user telemetry during runtime
    answers = []
    called_functions = set()
    pcap_file_name = ""
    pcap_pkt_list = []

    # A list of tuples where an entry may look like
    # (TWITCH, 29) Where Twtich makes up 29% of a .pcap files traffic
    sorted_percentages = []

    # Composition Read
    ip_counter = Counter()

    def reset(self):
        self.answers = []
        self.called_functions = set()


wzrd_telemetry = WizardTelemetry()


class DiagnosticWizard(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)

        self.pack()
        self.current_question = 0
        self.create_widgets()

        # Reset diagnostic data
        if wzrd_telemetry:
            wzrd_telemetry.reset()

    def create_widgets(self):
        wizard_font = "Calibri"

        # Text area for displaying questions and answers
        self.question_text = tk.Text(self, height=13, width=85,
                                     wrap="word", font=(wizard_font, 15), pady=6, padx=6)
        self.question_text.pack()

        # Yes button
        self.yes_button = tk.Button(
            self, font=(wizard_font, 12), text="Yes", width=15, command=self.answer_yes, pady=1, bg="#5fe884")
        self.yes_button.pack(side="left", pady=5, padx=3)

        # No button
        self.no_button = tk.Button(
            self, font=(wizard_font, 12), text="No", width=15, command=self.answer_no, pady=1, bg="red")
        self.no_button.pack(side="left", pady=5, padx=3)

        # Next button (initially disabled)
        self.next_button = tk.Button(
            self, font=(wizard_font, 12), text="Next Question", width=15, command=self.next_question_btn_clicked, pady=1, state=tk.DISABLED)
        self.next_button.pack(side="left", pady=5, padx=3)

        # Change text inside wizard text area.
        self.display_question()

    def next_question_btn_clicked(self):
        # Called by "Next Question" button
        self.current_question += 1

        # For each new question, enable the choice buttons.
        self.yes_button.config(state=tk.NORMAL)
        self.no_button.config(state=tk.NORMAL)
        self.next_button.config(state=tk.DISABLED)

        if self.current_question < len(questions):
            self.display_question()
        else:
            # Testing
            print(wzrd_telemetry.answers)
            print(wzrd_telemetry.called_functions)

            # RESET WINDOW
            self.master.destroy()

    def display_question(self):
        # Display current question in the text area
        self.question_text.config(state=tk.NORMAL)  # state change

        self.question_text.delete("1.0", tk.END)
        self.question_text.insert(tk.END, questions[self.current_question])

        self.question_text.config(state=tk.DISABLED)  # state change

    def answer_yes(self):
        wzrd_telemetry.answers.append(1)

        self.question_text.config(state=tk.NORMAL)  # state change

        # Find and execute command user has specified
        self.check_list(wzrd_telemetry.answers)

        # User answering a questions results in answer buttons becoming locked.
        # Enable next question button.
        self.yes_button.config(state=tk.DISABLED)
        self.no_button.config(state=tk.DISABLED)
        self.next_button.config(state=tk.NORMAL)

    def answer_no(self):
        wzrd_telemetry.answers.append(0)

        # User answering a questions results in answer buttons becoming locked.
        # Enable next question button.
        self.yes_button.config(state=tk.DISABLED)
        self.no_button.config(state=tk.DISABLED)
        self.next_button.config(state=tk.NORMAL)

    def wiz_file_prompt(self):
        # Configure GUI
        self.yes_button.pack_forget()
        self.no_button.pack_forget()
        self.next_button.pack_forget()

        # Add button that let's users select a file
        self.select_file = tk.Button(
            self, font=("Calibri", 12), text="Select File", width=15, command=self.wiz_file_prompt_handler, pady=1, bg="#ff6223")
        self.select_file.pack(side="left", pady=5, padx=3)

    def wiz_file_prompt_handler(self):
        # Handle user file selection

        self.question_text.config(state=tk.NORMAL)  # state change

        """
        Create or configure buttons depending on whether they exist or not
        hasattr returns true or false, checking if an object exists or not

        Buttons created: 1) Confirm 2) Further Analysis 3) Generate Report
        """
        if hasattr(self, "confirm"):
            self.confirm.config(state=tk.DISABLED)
        else:
            self.confirm = tk.Button(
                self, font=("Calibri", 12), text="Confirm Selection", width=15, command=self.confirm_clicked, pady=1, bg="#ff6223")
            self.confirm.pack(side="left", pady=5, padx=3)
            self.confirm.config(state=tk.DISABLED)

        if hasattr(self, "further_button"):
            self.further_button.config(state=tk.DISABLED)
        else:
            self.further_button = tk.Button(
                self, font=("Calibri", 12), text="Further Analysis", width=15, command=self.protocol_analysis, pady=1, bg="#ff6223")
            self.further_button.pack(side="left", pady=5, padx=3)
            self.further_button.config(state=tk.DISABLED)

        if hasattr(self, "report_button"):
            self.report_button.config(state=tk.DISABLED)
        else:
            self.report_button = tk.Button(
                self, font=("Calibri", 12), text="Generate Report", width=15, command=build_report, pady=1, bg="#ff6223")
            self.report_button.pack(side="left", pady=5, padx=3)
            self.report_button.config(state=tk.DISABLED)

        # Handle file selection from wiz_file_prompt()
        try:
            # Call file manager's file dialog file selector
            wzrd_telemetry.pcap_file_name, wzrd_telemetry.pcap_pkt_list = read_pcap()
            # Update dialog
            msg = "Would you like me to read this file?\nSelect 'Confirm Selection' if yes, or if you would like to change file, click 'Select File' again.\n\nCurrent File:\n\n" + wzrd_telemetry.pcap_file_name
            self.question_text.delete("1.0", tk.END)
            self.question_text.insert(tk.END, msg)

            # Confugre confirm button
            self.confirm.config(state=tk.NORMAL)
        except:
            # User has not selected a file in file explorer OR file is empty
            wzrd_telemetry.pcap_file_name = ""
            wzrd_telemetry.pcap_pkt_list = []

            msg = "No file was selected.\nIf you did select a file, it may have been empty!"
            self.question_text.delete("1.0", tk.END)
            self.question_text.insert(tk.END, msg)

            self.confirm.config(state=tk.DISABLED)

    def confirm_clicked(self):
        # After user selects "confirm" for their .pcap file
        self.question_text.delete("1.0", tk.END)
        self.analysis_thread = threading.Thread(target=self.threaded_analysis)
        self.analysis_thread.start()

    def threaded_analysis(self):
        # Proprietary version of "composition_read_thread()" from "pcap_parser"

        self.select_file.config(state=tk.DISABLED)
        self.confirm.config(state=tk.DISABLED)

        for pkt in wzrd_telemetry.pcap_pkt_list:
            if 'IPv6' in pkt:
                source_ip = pkt['IPv6'].src
                wzrd_telemetry.ip_counter[source_ip] += 1
            elif 'IP' in pkt:
                source_ip = pkt['IP'].src
                wzrd_telemetry.ip_counter[source_ip] += 1

        counter_sum = sum(wzrd_telemetry.ip_counter.values())

        # Counter contains ip addresses and their occurences
        # This list will contain tuples with ip addresses and their percentages.
        ips_with_percentages = []

        for address, occurences in wzrd_telemetry.ip_counter.items():
            percentage = 100 * occurences / counter_sum  # Get percentage
            ips_with_percentages.append(
                (address, percentage))  # Build a list of tuples

        # Sort our IP addresses from most to least common
        sorted_percentages = sorted(
            ips_with_percentages, key=lambda x: x[1], reverse=True)

        # Display message for user
        initial_output = "Below are the percentages representing the composition of:\n" + \
            wzrd_telemetry.pcap_file_name + '\n\n'

        self.question_text.insert(tk.END, initial_output)
        self.question_text.see(tk.END)

        # Iterate list of tuples
        for i, entry in enumerate(sorted_percentages):
            address, percentage = entry  # Each sorted_percentages entry is a tuple

            # Attempt to translate current IP address.
            address = search_org(address)

            # Replace the IP address in the tuple with the translated address
            sorted_percentages[i] = (address, percentage)

            # Update user as addresses are translated
            current_output = ("{}: {:.2f}%\n".format(address, percentage))
            self.question_text.insert(tk.END, str(current_output))
            self.question_text.see(tk.END)

        # Calculate public and private address composition
        # Retruns a message string to be displayed to user
        composition = public_private_composition(
            wzrd_telemetry.pcap_file_name)

        # Does ip counter have more than 1 value?
        # If so, print most common address
        if len(wzrd_telemetry.ip_counter.keys()) > 1:
            most_common_value = wzrd_telemetry.ip_counter.most_common(1)[0][0]
            # Will be an ip address if un-resolvable
            searched_most_common = search_org(most_common_value)

            msg = "\nThe IP address that appeared most often in communications was " + \
                searched_most_common + '\n'

            self.question_text.insert(tk.END, msg)

        # Save translated and sorted IP tuple list
        wzrd_telemetry.sorted_percentages = sorted_percentages

        # End of analysis
        self.question_text.insert(
            tk.END, '\n' + str(composition) + "\n\nI have finished reading your file!\nIf you would like me to analyse another file, click 'Select File'.")
        self.question_text.see(tk.END)

        # Re-enable buttons that were disabled during analysis
        self.select_file.config(state=tk.NORMAL)
        self.confirm.config(state=tk.NORMAL)
        self.report_button.config(state=tk.NORMAL)
        self.further_button.config(state=tk.NORMAL)

        self.question_text.config(state=tk.DISABLED)  # state change

    def protocol_analysis(self):
        self.further_button.config(state=tk.DISABLED)

        packet_list = wzrd_telemetry.pcap_pkt_list

        if packet_list:
            protocol_counter = Counter()

            # Loop through each packet in the list
            for packet in packet_list:
                # Check the protocol of the packet
                if packet.haslayer(scapy.layers.http.HTTP):
                    protocol_counter['HTTP'] += 1
                elif packet.haslayer(scapy.layers.dns.DNS):
                    protocol_counter['DNS'] += 1
                elif packet.haslayer(scapy.layers.inet.TCP):
                    protocol_counter['TCP'] += 1
                elif packet.haslayer(scapy.layers.inet.UDP):
                    protocol_counter['UDP'] += 1

            self.question_text.config(state=tk.NORMAL)  # state change

            # Print the results
            self.question_text.insert(
                tk.END, f"\n\nSure, I can look into this file further. I have listed the following protocols along with their occurences: ")

            for protocol, count in protocol_counter.items():
                # print(f"{protocol}: {count}")
                self.question_text.insert(tk.END, f"\n{protocol}: {count}")

            self.question_text.see(tk.END)
            self.question_text.config(state=tk.DISABLED)  # state change
        else:
            self.question_text.config(state=tk.NORMAL)  # state change
            self.question_text.insert(
                tk.END, f"\n\nI could not identify any protocls in this packet capture file at this time.")
            self.question_text.config(state=tk.DISABLED)  # state change

    def check_list(self, lst):
        """
        As the user answers yes or no, a list of 1's and 0's is built
        The number of answers specifies what question the user is currently on
        and the 1 or 0 specifies their answer to that question
        we only execute functions that the user specifes yes (1) to.
        """
        size = len(lst)
        print("size = " + str(size))

        for i in range(size):
            # if user selected "yes"

            '''
            Called functions are added to the global set names "called_functions".
            This prevents functions that have executed already from running again.

            Instructions: 
            1) For each wizard function, print results to user through "self.question_text" text field
            2) Add executed function to global set
            '''

            if lst[i] == 1:
                if i == 0 and wizard_check_internet not in wzrd_telemetry.called_functions:
                    # Test internet connection
                    result = wizard_check_internet()
                    self.question_text.delete("1.0", tk.END)
                    self.question_text.insert(tk.END, result)
                    wzrd_telemetry.called_functions.add(wizard_check_internet)

                elif i == 1 and wizard_check_speed not in wzrd_telemetry.called_functions:
                    # Test internet speed
                    result = wizard_check_speed()
                    self.question_text.delete("1.0", tk.END)
                    self.question_text.insert(tk.END, result)
                    wzrd_telemetry.called_functions.add(wizard_check_speed)

                elif i == 2 and wizard_device_discover not in wzrd_telemetry.called_functions:
                    # Discover devices on the network
                    devices = wizard_device_discover()
                    self.question_text.delete("1.0", tk.END)
                    self.question_text.insert(tk.END, devices)
                    wzrd_telemetry.called_functions.add(wizard_device_discover)

                elif i == 3 and wizard_analysis not in wzrd_telemetry.called_functions:
                    result = wizard_analysis()
                    self.question_text.delete("1.0", tk.END)
                    self.question_text.insert(tk.END, result)
                    wzrd_telemetry.called_functions.add(wizard_analysis)

                elif i == 4:
                    msg = "Alright, please select a file using the 'Select File' button."
                    self.question_text.delete("1.0", tk.END)
                    self.question_text.insert(tk.END, msg)
                    self.wiz_file_prompt()

        self.question_text.config(state=tk.DISABLED)  # state change


# "Wizard call" functions return their result in to the wizard text area for the user
# during guided analysis.
def wizard_check_internet():
    # DEF 1
    if check_internet():
        msg = "It looks like internet connection is up and running."
    else:
        msg = "There are several possible reasons why your device may not have internet connection:\n\n1. Network issues: Your device may not be connected to a network, or the network you're connected to may be experiencing issues.\n\n2. Router issues: Your router may be malfunctioning, or it may not be properly set up.\n\n3. Software issues: Your device's software may be outdated or may be experiencing compatibility issues with your network or router.\n\n4. Account issues: Your internet service provider (ISP) may have suspended your account or there may be an issue with your payment.\n\n5. Physical damage: Your device's hardware may be damaged or broken, which can affect its ability to connect to the internet.\n\nPlease check these possibilities to troubleshoot the issue and restore your internet connection."

    return msg


def wizard_check_speed():
    # DEF 2
    url, speed_result = get_speed_mbs()
    if speed_result:
        return "I have tested your internet speed! Scroll down for more information.\n" + speed_result + "\nYou can view some more details about your speed test here:" + url
    else:
        return "Sorry, I could not get a speed test at this time. Please try again!"


def wizard_device_discover():
    # DEF 3
    manufacturer = re.findall(r'Manufacturer:\s+(.*?)\n', str(arp_discovery()))
    printable_result = ""

    if manufacturer:
        printable_result = f"I found {len(manufacturer)} devices on your network! Scroll down if needed. If an entry says 'Not Found.', this means I seen a device that I could not identify at this time!\n\n"

        for entry in manufacturer:
            printable_result += f"{entry}\n"

        return printable_result
    else:
        printable_result = "Sorry, I could not find any devices on this network at this current time. This could be due to several reasons:\n"
        printable_result += "- There may not be any devices currently connected to the network.\n"
        printable_result += "- The network may be configured to hide device information.\n"
        printable_result += "- Your computer may not have the necessary privileges to access device information.\n"
        printable_result += "Please try again later or contact your network administrator for more information."
        return printable_result


def wizard_analysis():
    # DEF 4
    try:
        # Get the name of the default interface
        default_iface = get_default_interface()

        result = ""

        result += "To start analyzing your network, first go to the 'Configure Scan' section located in the menu on the left-hand side. In this section, you'll find a list of interfaces available on your device that you can use for the analysis."
        result += "\n\nIf you're not sure which interface to use, I recommend selecting: {}.\nThis is your default interface, and likely the one you are using to connect to the network/internet.".format(
            default_iface)
        result += "\n\nYou have the option to capture all traffic on your network, not just the traffic from your current device. To do this, simply select 'All Interfaces' in the configure scan section. "
        result += "\n\nClick 'Next Question' if you would like to analyse an existing capture file."
        return result

    except Exception as e:
        result += "To start analyzing your network, first go to the 'Configure Scan' section located in the menu on the left-hand side. In this section, you'll find a list of interfaces available on your device that you can use for the analysis."
        print(e)
        return result


def build_report():
    """
    build_report does not take arguments, instead it utilises the wizards
    global variables.
    """

    from tkinter import filedialog
    import os

    """
    Using matplotlib
    agg is a non-interactive backend.
    I use it here as CableOrca creates images when saving graphs
    The CLI would freeze when not using this backend.
    """
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt

    sorted_percentages = wzrd_telemetry.sorted_percentages
    file_name = wzrd_telemetry.pcap_file_name

    # Graphs created contain top 10 most common addresses
    if len(sorted_percentages) >= 10:
        top_ips = sorted_percentages[:10]
    else:
        top_ips = sorted_percentages

    # Extract the IP addresses and their occurrences as separate lists
    ips = [entry[0] for entry in top_ips]
    occurrences = [entry[1] for entry in top_ips]

    # Create the horizontal bar chart
    fig, ax = plt.subplots()
    ax.barh(ips, occurrences)
    ax.set_xlabel('Percentage Occurrence')
    ax.set_ylabel('IP Address')

    # Set the title and adjust the figure size
    ax.set_title('Top 10 IP Addresses in ' + file_name)
    fig.set_size_inches(8, 6)

    # Automatically adjust the spacing between the subplots to fit the labels within the figure
    plt.tight_layout()

    # Use a file dialog to prompt the user to select a filename and location to save the graph
    file_path = filedialog.asksaveasfilename(
        defaultextension=".png", filetypes=[("PNG", "*.png")])

    # Check if the user canceled the dialog or entered an invalid filename
    if not file_path or not os.path.splitext(file_path)[1].lower() == ".png":
        return

    # Save the graph as a PNG image with padding added to each edge
    padding = 0.5
    try:
        plt.savefig(file_path, bbox_inches="tight",
                    pad_inches=padding, dpi=100)
    except IOError as e:
        print(f"Failed to save graph: {e}")
        return
