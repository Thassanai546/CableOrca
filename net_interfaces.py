from scapy.all import *
import socket
import requests


def interfaces_to_name_list():
    # Return a list of names of interfaces on the device.
    # [!] Useful for scanning all interfaces using Scapy
    interface_list = []
    for net_int in get_working_ifaces():
        interface_list.append(net_int.name)  # Names such as "Ethernet"
    interface_list.append("ALL INTERFACES")
    return interface_list


def get_current_device():
    # Get hostname and ip address
    output = []
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
        output.append("Your address: " + device_ip)
        output.append("Your device name: " + device_name)
        output.append("Your network interface: " + device_interface)
    except:
        output.append("Could not get device info.")
    return output


def get_default_interface():
    try:
        default_int = conf.iface.name
        return default_int
    except Scapy_Exception as ex:
        print(f"Error getting default interface: {ex}")
        return None


def get_public_ip():
    # Will try to fetch public IP address of the current device
    # If public IP address cannot be fetched, public IP address is returned
    try:
        print("Fetching Public IP address from AWS...")
        response = requests.get('https://checkip.amazonaws.com').text.strip()
        return response

    except requests.exceptions.RequestException:
        try:
            print("AWS Cannot be Reached. Fetching Public IP from ipify.org...")
            response = requests.get('https://api.ipify.org').text.strip()
            return response

        except requests.exceptions.RequestException:
            skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            skt.connect(('8.8.8.8', 80))  # Try google DNS.
            return skt.getsockname()[0]

    except Exception as ex:
        print(ex)
        return "Error, could not fetch public IP address at this time."


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
