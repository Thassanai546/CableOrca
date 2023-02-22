from tkinter import filedialog
from scapy.all import *
import tkinter as tk
import requests
import os

# When opening and saving files, they are placed in, or read from a directory called "CableOrca_files"
CableOrcaDirectory = "CableOrca_files"


def create_directory():
    # Creates CableOrca directory if it does not already exist.
    if not os.path.exists(CableOrcaDirectory) and not os.path.isdir(CableOrcaDirectory):
        print(
            f"The directory '{CableOrcaDirectory}' does not exist. Making directory...")
        os.makedirs(CableOrcaDirectory)
    else:
        print(f"The directory '{CableOrcaDirectory}' was found!")


def save_to_pcap(pkts):
    # Used by create_pcap_saver_frame
    # Uses filedialog to save to system.
    # Only pcap files are allowed.
    # pkts must be provded for wrcap function!
    try:
        save_window = tk.Tk()
        save_window.withdraw()
        file_path = filedialog.asksaveasfilename(
            defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
        if file_path:
            wrpcap(file_path, pkts)
            print(f"PCAP file saved to: {file_path}")
    except Exception as ex:
        print(ex)
        pass


def open_pcap():
    # return name of a pcap file in the test directory
    try:
        file_to_read = input("Enter the name of the pcap file to read:")

        if not file_to_read.endswith('.pcap'):
            file_to_read += '.pcap'

        read_path = os.path.join(CableOrcaDirectory, file_to_read)

        if os.path.isfile(read_path):
            try:
                print(f"Reading: {read_path}.")
                return read_path
            except Exception as e:
                print(f"An error occurred while trying to read the file: {e}")
                return None
        else:
            print(
                f"The file {file_to_read} does not exist in the CableOrca_files directory.")
            return None
    except Exception as e:
        print(f"An error occurred while trying to retrieve the file name: {e}")
        return None


def create_pcap():
    try:
        created_file = input("Enter the name of the pcap file:")

        if not created_file.endswith('.pcap'):
            created_file += '.pcap'

        create_directory()

        file_path = os.path.join(CableOrcaDirectory, created_file)

        if os.path.isfile(file_path):
            print(
                f'The file {file_path} already exists in directory {CableOrcaDirectory}')

        return file_path

    except Exception as e:
        print("An error occurred while trying to create the pcap file:", e)
        return None


def append(filename, pkts):
    # Filename excpected to include specified directory.
    try:
        if os.path.exists(filename):
            wrpcap(filename, pkts, append=True)
        else:
            wrpcap(filename, pkts)
    except Exception as e:
        print("An error occurred while saving/appending packets to the file:", e)


def save_txt_file(data):
    # Saves data to a text file. If user specified a file
    # that exists already, data will be appended to the file.
    try:
        file_name = input("Enter the name of the file: ")

        if not file_name.endswith('.txt'):
            file_name += '.txt'

        create_directory()

        # add CableOrca directory to filename
        file_path = os.path.join(CableOrcaDirectory, file_name)

        mode = 'a' if os.path.exists(file_path) else 'w'

        with open(file_path, mode) as text_file:
            text_file.write(data)
        print(f'Successfully wrote to {file_path}')

    except Exception as e:
        print(f'An error occurred while writing to the file: {e}')


def open_and_read_pcap(function):  # To be bound with "socket_translator"
    # For each packet in a pcap file, this function will
    # pass that packet in to the function supplied.
    file = open_pcap()
    try:
        pkts = rdpcap(file)
        for pkt in pkts:
            function(pkt)
    except Exception as message:
        print(f"An error occurred: {message}")


def directory_search(extension, directory):
    try:
        # Ensure the directory exists
        if not os.path.isdir(directory):
            print(f"The directory '{directory}' does not exist.")
            return

        # Get all files in the directory
        files = os.listdir(directory)
        matching_files = []
        for file in files:
            # Check if file has the specified extension
            if file.endswith(extension):
                matching_files.append(file)

        # Print all matching files
        if matching_files:
            print(
                f"Found {len(matching_files)} file(s) with extension {extension} in {directory}:")
            for file in matching_files:
                print(f"-> {file}")
        else:
            print(f"No files with extension {extension} found in {directory}.")
    except Exception as e:
        print(f"An error occurred while searching for files: {e}.")


def download_to_cableorca(url):
    # Download a file to "CableOrca_files" directory.
    # Will not download if file exists already.
    try:
        file_path = url.split("/")[-1]
        file_path = os.path.join(CableOrcaDirectory, file_path)
        if os.path.exists(file_path):
            print(f"{file_path} already exists.")
            return 1

        downloaded = requests.get(url)
        # "wb" = write in binary mode.
        with open(file_path, "wb") as specified_folder:
            specified_folder.write(downloaded.content)
        print(f"{file_path} has been downloaded to {CableOrcaDirectory}.")
        return 1
    except:
        print("Could not download that file..")
        return 0


def save_image(url):
    # This function is different to download_to_cableorca due to the fact that
    # It allows a user to choose the destination of the image downloaded.
    # Returns True or False.

    # Open a file dialog to select the image file
    try:
        file_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[
                                                 ("PNG", "*.png"), ("JPEG", "*.jpg"), ("All Files", "*.*")])

        if file_path:
            # Get speedtest.results() image from online.
            downloaded = requests.get(url)
            # "wb" = write in binary mode.
            with open(file_path, "wb") as specified_folder:
                specified_folder.write(downloaded.content)
            return 1
    except:
        print("Could not download that file..")
        return 0


def read_pcap():
    try:
        # Prompt user to select .pcap file
        # Pass that pcap file to "rdpcap()"
        # Return false if nothing selected.
        pcap_file = tk.filedialog.askopenfilename(
            filetypes=[("PCAP files", "*.pcap")])

        if not pcap_file:
            return False  # User clicked "Cancel" or didn't select a file

        # rdpcap returns a python LIST of packets
        readable_packets = rdpcap(pcap_file)
        return pcap_file, readable_packets

    except FileNotFoundError:
        print("Error: File not found")
        return False
    except Scapy_Exception:
        print("Error: Could not read pcap file")
        return False
