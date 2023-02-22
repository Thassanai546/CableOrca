from net_interfaces import *
from arp_sweeper import *
from file_manager import *
from net_interfaces import *
from pcap_parser import *
from sniffer_engine import *
from net_speed_test import *


def display_options():
    print("CableOrca CLI Active...")
    print("1. Configure Scan")
    print("2. ARP Sweep")
    print("3. Analyse .pcap file")
    print("4. Network Speed Test")
    print("5. Read a .pcap file without deep analysis")
    print("6. Sniff with specified function as PRN")
    print("\n")


def select_option():
    try:
        selection = int(input("Enter a number (1-6) to select an option: "))
        if selection == 1:
            configure_sniff()
        elif selection == 2:
            arp_discovery()
        elif selection == 3:
            directory_search(".pcap", CableOrcaDirectory)
            display_pcap_composition()
        elif selection == 4:
            op = get_speed_mbs()
            print(op)
        elif selection == 5:
            open_and_read_pcap(socket_translator)
            print("Translated IPs", translated_ips)
            print("Unkown IPs:", unknown_ips)
        elif selection == 6:
            sniff_with(socket_translator)
            print("Translated IPs", translated_ips)
            print("Unkown IPs:", unknown_ips)
        else:
            print("Invalid selection. Please enter a number between 1 and 6.")
    except ValueError:
        print("Invalid input. Please enter a number between 1 and 6.")


if __name__ == "__main__":
    get_current_device()
    display_options()
    select_option()
