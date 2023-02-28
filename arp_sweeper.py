import ipaddress
import time
from datetime import datetime
from mac_vendor_lookup import MacLookup
from scapy.all import ARP, Ether
from scapy.all import *


def get_network(ip_address):
    try:
        # Get a network from an ip address.
        # strict = False -> can accept network addresses and ip addresses.
        network = ipaddress.ip_network(ip_address + '/24', strict=False)
        return network
    except Exception as ex:
        network = "192.168.1.1/24"
        print(ex)
        return network


def arp_discovery():
    try:
        print("ARP Sweep has begun...")
        # Get private IP address of this device.
        # get_network used to get the network address of current device.
        ip_range = get_network(get_if_addr(conf.iface))
        ip_range = str(ip_range)

        # Create an ARP request packet
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        orca_packet = ether/arp

        # Record the start time
        start_time = time.time()

        # Send the packet on the network and get the response
        result = srp(orca_packet, timeout=3, verbose=0)[0]

        # ARP request packet sent to devices in specified IP range.
        lookup = MacLookup()
        output = ""

        # Add current date to output
        current_time = datetime.now()

        output = "<=== Device Discovery Sweep Date: " + \
            str(current_time) + " ===>\n"

        for sent, received in result:
            try:
                #ljust used here for consistent tabbing output.
                mac_address = received.hwsrc
                ip_address = str(received.psrc)
                manufacturer = lookup.lookup(mac_address)
                output += "MAC: " + mac_address + "\tIP: " + \
                    ip_address.ljust(18) + "\tManufacturer: " + \
                    manufacturer + "\n"
            except:
                output += "MAC: " + mac_address + "\tIP: " + \
                    ip_address.ljust(
                        18) + "\tManufacturer: Not Found." + "\n"

        end_time = time.time()
        total_time = end_time - start_time
        total_time = round(total_time)

        output += "<=== Analysis completed in " + \
            str(total_time) + " seconds. The Network Scanned: " + ip_range + " ===>"

        # print(output)
        return output
    except Exception as ex:
        print(ex)
