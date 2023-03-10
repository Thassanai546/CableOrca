from scapy.all import *
import socket
import requests


def print_interfaces():
    output = []
    try:
        output.append("Interfaces on this device:\n")
        for net_int in get_working_ifaces():
            output.append("ID:[ %d ] [Name: %s ]\n" %
                          (net_int.index, net_int.name))
        output.append("ID:[ 0 ] = All Interfaces")
    except:
        output.append("Could not get device interfaces.")
    return output


def interfaces_to_index_list():  # TEMP, MAY NO LONGER BE NEEDED.
    # Return a list of indexes of interfaces on this device
    interface_list = []

    for interface in get_working_ifaces():
        current_interface_index = interface.index
        interface_list.append(current_interface_index)

    interface_list.append(0)  # For option "all interfaces"
    return interface_list


def interfaces_to_name_list():
    # Return a list of names of interfaces on the device.
    # [!] Useful for scanning all interfaces using Scapy
    interface_list = []
    for net_int in get_working_ifaces():
        interface_list.append(net_int.name)  # Names such as "Ethernet"
    interface_list.append("All Interfaces.")
    return interface_list


def get_current_device():
    # Get hostname and ip address
    output = ""
    try:
        device_interface = conf.iface.name
        device_ip = get_if_addr(conf.iface)

        if device_ip == "0.0.0.0":  # Get current IP without scapy/winpcap.
            # Get the hostname
            hostname = socket.gethostname()

            # Get the IP address
            ip_address = socket.gethostbyname(hostname)

            device_ip = ip_address

        device_name = socket.gethostbyaddr(socket.gethostname())[0]
        # print("[Your address:",device_ip,"] - [Your device name:",device_name,']')  # This device IP address
        output += (
            f"Your address: {device_ip}\nYour device name: {device_name}\nYour network interface: {device_interface}")
        # print(socket.gethostbyaddr(get_if_addr(conf.iface))[0])
    except:
        output = "Could not get device info."
    return output


def get_public_ip():
    # Get the public ip address of the current device.
    # If we can't reach ipify, try socket.
    try:
        print("Fetching Public IP from ipify.org...")
        response = requests.get('https://api.ipify.org')
        return response.text

    except requests.exceptions.RequestException:
        skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        skt.connect(('8.8.8.8', 80))  # Try google DNS.
        return skt.getsockname()[0]

    except Exception as ex:
        print(ex)
        return "Error"


def check_internet():
    # Use requests library to test for internet connection
    servers = ['https://www.google.com',
               'https://www.bing.com', 'https://github.com/']

    for server in servers:
        try:
            requests.get(server, timeout=5)
            return True
        except requests.exceptions.RequestException:
            # If we can't connect to google, try others.
            continue

    return False
