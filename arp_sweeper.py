import ipaddress
from datetime import datetime
from mac_vendor_lookup import MacLookup
from scapy.all import ARP, Ether, get_if_addr, srp, conf
import time


def get_network(ip_address):
    # Takes an ip address as a string
    try:
        # Get a network from an ip address.
        # strict = False -> can accept network addresses and ip addresses.
        # creates "class 'ipaddress.IPv4Network'"
        network = ipaddress.ip_network(ip_address + '/24', strict=False)
        print("Created network =", network)
        return network
    except Exception as ex:
        print("A network was not created by get_network()." + ex)
        network = "192.168.1.0/24"
        return network


def arp_discovery():
    try:
        # Get private IP address of this device.
        # get_if_addr(conf.iface) returns a string
        device_ip = get_if_addr(conf.iface)

        # get_network used to get the network address of current device.
        # Note that ipv4_network is type ipaddress.IPv4Network, not a string.
        ipv4_network = get_network(device_ip)

        # ipaddress.IPv4Network -> string
        ipv4_network = str(ipv4_network)

        # Create an ARP request packet
        arp = ARP(pdst=ipv4_network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff") # All devices on the network
        orca_packet = ether/arp

        # Record the start time
        start_time = time.time()

        # Send the packet with a 3 second timeout
        result = srp(orca_packet, timeout=3, verbose=0)[0]

        lookup = MacLookup()    # MacLookup object for resolving mac address names
        output = ""             # Output returned from arp_discovery()

        # Add current date to output
        current_time = datetime.now()

        output = "<======= Device Discovery Sweep Date: " + \
            str(current_time) + " =======>\n"

        for sent, received in result:
            try:
                # ljust used here for consistent tabbing output.
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
            str(total_time) + " seconds. The Network Scanned: " + \
            ipv4_network + " ===>"

        print("Scan Complete.", total_time, "seconds.")
        return output
    except Exception as ex:
        print(ex)
