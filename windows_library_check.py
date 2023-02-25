import ctypes
import webbrowser
import subprocess

'''
ctypes allows calling functions in DLLs or shared libraries.
I am using it here to attempt to find npcap Windows.

Note! WinPcap and WinDump have ceased development, and instead
Npcap is recommended.
'''


def check_dll(dll_name):
    try:
        #  According to https://npcap.com/guide/npcap-api.html , the Npcap API is exported by wpcap.dll"
        ctypes.WinDLL(dll_name) # wpcap.dll
        has_library = True
        print("Npcap/Winpcap detected!")
    except OSError:
        has_library = False

    return has_library


def open_browser(url):
    try:
        webbrowser.open_new(url)
    except Exception as ex:
        print("Could not open browser.")
        print(ex)
