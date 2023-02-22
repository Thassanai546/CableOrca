from PIL import Image, ImageTk
import tkinter as tk

from find_pcap_library import *
from net_interfaces import *
from net_speed_test import *
from sniffer_engine import *
from pcap_parser import *
from file_manager import *
from arp_sweeper import *
from gui_engine import *

# Globals:
# As windows changes, certain variables need to be held
# so that processing time is saved.
DEVICE_INFO = ""
PUBLIC_IP = ""
LIBRARY_CHECK = False
HAS_PCAP_LIBR = False
INTERNET_CON = bool


class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()

        # Configure title for CO Online, or Offline mode.
        global INTERNET_CON
        INTERNET_CON = check_internet()  # From net_interfaces.py

        if INTERNET_CON:
            self.title("CableOrca - Online Mode")
        else:
            self.title("CableOrca - Offline Mode")

        # Non resizable
        self.resizable(False, False)

        # Creates directory called "CableOrca_files" if it does not exist.
        # This must be done before downloading files to CO directory.
        create_directory()

        # Download icons from public GitHub.
        # These files are stored in "CableOrca_files"
        # They will not be downloaded if the exist in the directory already.
        icon_1 = "https://raw.githubusercontent.com/Thassanai546/CableOrca/main/Assets/CableOrcaIco.ico"
        icon_2 = "https://raw.githubusercontent.com/Thassanai546/CableOrca/main/Assets/CableOrcaIcon.png"

        # Use file_manager's downloader.
        if download_to_cableorca(icon_1):
            self.iconbitmap("CableOrca_files\CableOrcaIco.ico")

        download_to_cableorca(icon_2)

        # Create sidebar
        self.sidebar = tk.Frame(self, bg="#34495e", width=100, height=500)
        self.sidebar.pack(side="left", fill="y")

        # Create and pack buttons for sidebar
        self.button1 = tk.Button(
            self.sidebar, width=20, text="Home", command=lambda: self.change_window(Window1))
        self.button1.pack(padx=5, pady=2)
        self.button5 = tk.Button(
            self.sidebar, width=20, text="Network Speed Test", command=lambda: self.change_window(Window5))
        self.button5.pack(padx=5, pady=2)
        self.button3 = tk.Button(
            self.sidebar, width=20, text="Discover Devices", command=lambda: self.change_window(Window3))
        self.button3.pack(padx=5, pady=2)
        self.button2 = tk.Button(
            self.sidebar, width=20, text="Configure Scan", command=lambda: self.change_window(Window2))
        self.button2.pack(padx=5, pady=2)
        self.button4 = tk.Button(
            self.sidebar, width=20, text="Analyse .pcap file", command=lambda: self.change_window(Window4))
        self.button4.pack(padx=5, pady=2)
        self.button6 = tk.Button(
            self.sidebar, width=20, text="Button 6", command=lambda: self.change_window(Window6))
        self.button6.pack(padx=5, pady=2)

        # Create main window container
        self.container = tk.Frame(self)
        self.container.pack(side="right", fill="both", expand=True)

        # Show main window
        self.show_window(Window1)

    def show_window(self, window_class):
        # Remove current window
        for widget in self.container.winfo_children():
            widget.destroy()

        # Create new window and add it to the container
        new_window = window_class(self.container)
        new_window.pack(fill="both", expand=True)

    def change_window(self, window_class):
        self.show_window(window_class)


class Window1(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)

        # Home/Welcome Page.

        global DEVICE_INFO      # Prevent repeated lookups.
        global LIBRARY_CHECK    # Has the system been checked for a pcap library?
        global HAS_PCAP_LIBR    # Does the system have a pcap library?
        global INTERNET_CON     # Does CO have access to the internet?

        home_font = "Calibri"

        # Prevent need for discovering device name every time it is needed
        if DEVICE_INFO == "":
            DEVICE_INFO = get_current_device()

        # This message is always displayed.
        try:
            tk.Label(self, text="⚡ Welcome to CableOrca, the high-level packet sniffer!",
                     justify="left", font=(home_font, 14), pady=5, padx=5, fg="white", bg="#222a38").pack(pady=10)
        except:
            # Non-special character handling
            tk.Label(self, text="Welcome to CableOrca, the high-level packet sniffer!",
                     justify="left", font=(home_font, 14), pady=5, padx=5, fg="white", bg="#222a38").pack(pady=10)

        # Attempt to display device information
        tk.Label(self, text=DEVICE_INFO,
                 justify="left", font=(home_font, 14)).pack()

        # Attempt to display CableOrca logo
        try:
            image = Image.open("CableOrca_files\CableOrcaIcon.png")
            image = image.resize((230, 230), Image.LANCZOS)
            self.photo = ImageTk.PhotoImage(image)
            tk.Label(self, image=self.photo).pack(pady=5, padx=5)
        except Exception as ex:
            pass

        if INTERNET_CON:
            tk.Label(self, fg="#2fc76d", text="Internet Connection Established - Online Mode Enabled",
                     justify="left", font=(home_font, 14), pady=5, padx=5).pack(pady=5)
        else:
            tk.Label(self, fg="red", text="Internet Connection Disabled - Offline Mode Enabled",
                     justify="left", font=(home_font, 14), pady=5, padx=5).pack(pady=5)

        # Try to search for pcap library on Windows.
        # If it is not found, links npcap download page.
        # Note! It is important to leave space on the homepage for this warning!
        try:
            if library_check is False:
                # Returns true if "wpcap.dll" library found.
                HAS_PCAP_LIBR = find_pcap_lib()
                print("System was searched for a pcap library.")

            if HAS_PCAP_LIBR:
                library_check = True  # System has been checked for wpcap.dll
                message = tk.Label(
                    self, justify="left", text="The required PCAP library has been detected on your system. The application is now ready to run.", fg="#2fc76d", font=(home_font, 14))
                message.pack()

                # Disclaimer is always displayed
                disclaimer = """[ ! ] A packet sniffer is a tool that allows a user to monitor and capture data being transmitted over a network. It is important to understand that the use of packet sniffers can be illegal, especially if used without proper authorization or for malicious purposes."""
                tk.Label(self, text=disclaimer, justify="left", font=(
                    home_font, 11), wraplength=500, fg="red").pack(pady=15)
            else:
                warning = tk.Label(
                    self, font=(home_font, 14), fg="#cd5e6a", text="Attention! CableOrca requires a PCAP library, and it appears that one could not be found on your system.\nTo ensure proper functioning, please follow the link provided below to download and install the necessary library.")
                warning.pack()
                hyperlink = tk.Label(
                    self, font=(home_font, 13), text="Link to Download", fg="blue", cursor="hand2")
                hyperlink.pack()
                # Button-1 = mouseclick
                hyperlink.bind(
                    "<Button-1>", lambda e: open_browser("https://npcap.com/#download"))
        except Exception as ex:
            tk.Label(
                self, text="Failed to search for pcap library on this operating system.").pack()
            print(ex)

        # Link to GitHub at bottom of homescreen.
        git_hyperlink = tk.Label(
            self, text="\nVisit the GitHub", fg="blue", cursor="hand2", font=(home_font, 11))
        git_hyperlink.pack()
        git_hyperlink.bind(
            "<Button-1>", lambda e: open_browser("https://github.com/Thassanai546/CableOrca"))


class Window2(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)

        # Network analysis configuration window.

        # Used in duration text field.
        # Uers should only enter time in seconds.
        def check_if_digit(value):
            return value == "" or value.isdigit()

        scanner_font = "Calibri"

        # Display device information + Heading
        self.device_info = tk.Label(self, text=DEVICE_INFO, justify="left", font=(
            scanner_font, 12), borderwidth=2, relief="ridge", pady=6, padx=6)
        self.device_info.pack(pady=5)

        self.heading = tk.Label(
            self, text="Please select an interface to use.", font=(scanner_font, 14))
        self.heading.pack()

        # create_scrollable_radiobuttons returns 2 variables
        # 1) The value of the selected radio button
        # 2) The frame, so it can be referenced
        self.scrollable_radiobuttons_frame, self.current_radiobutton_selection = create_scrollable_radiobuttons(
            self, interfaces_to_name_list())

        # Enable button + display selected interface on a label.
        self.current_radiobutton_selection.trace(
            "w", self.update_interface_display)

        # Display the selected interface
        # "Selected interface: *name*"
        self.interface_label = tk.Label(self, font=(scanner_font, 12))
        self.interface_label.pack()

        # Duration label
        self.d_label = tk.Label(self, text="Set Scan Duration (In Seconds):",
                                font=(scanner_font, 12))
        self.d_label.pack()

        # Note to user
        self.info = tk.Label(self, text="[ ! ] Leave duration field blank for the default duration of 60 seconds.",
                             font=(scanner_font, 12))
        self.info.pack()

        # Duration text field where validate command is "check_if_digit"
        self.duration_field = tk.Entry(self, validate="key", validatecommand=(
            self.register(check_if_digit), "%P"), width=6, font=(scanner_font, 14))
        self.duration_field.pack(pady=5)

        # Create button to confirm the selected interface
        # It is disabled by default.
        self.confirm_button = tk.Button(
            self, font=(scanner_font, 12), text="Confirm", width=15, command=self.confirm_sniff, state=tk.DISABLED, pady=1, bg="#5fe884")
        self.confirm_button.pack(pady=15)

    # Developer note:
    # These methods need to be separate from __init__ because they are not
    # called when the object is created, but after the user has interacted
    # with the window.

    def update_interface_display(self, *args):
        # selected = current value of the selected interface
        selected = self.current_radiobutton_selection.get()
        self.interface_label.config(
            text="Selected interface: [" + selected + "]")

        # Enable the confirm button once an interface is selected
        if selected:
            self.confirm_button.config(state=tk.NORMAL)

    def confirm_sniff(self):
        # Get the value of the selected interface
        chosen_interface = self.current_radiobutton_selection.get()
        duration = self.duration_field.get()

        # No duration = 60 second default
        try:
            duration = int(duration)
        except:
            duration = 60

        # Remove all widgets on the "Configre Scan" page
        for widget in self.pack_slaves():
            widget.pack_forget()

        # Message above analysis feed
        user_message = "Network analysis in progress on [" + \
            chosen_interface + "] Duration: [" + str(duration) + "] seconds."
        user_message_label = tk.Label(self, text=user_message,
                                      font=("calibri", 13))
        user_message_label.pack(pady=5)

        # Display live analysis window in place of all previous widgets.
        try:
            # sniffer_engine.py's "sniffer_window" is spawned on "self".
            SnifferWindow(self, duration, chosen_interface)
        except Exception as ex:
            print("Sniffer Window has not been created: ")
            print(ex)


class Window3(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)

        # Discover devices on the network using ARP.

        dev_discover_font = "Calibri"

        tk.Label(self, justify="left", text="Network Device Discovery",
                 font=(dev_discover_font, 14)).pack()
        message = tk.Label(self, justify="left", text="The speed at which CableOrca discovers devices depends on your network.", font=(
            dev_discover_font, 12))
        message.pack()

        def start_arp_sweep():
            result_of_arp_discover = arp_discovery()
            arp_text_output.config(state="normal")
            arp_text_output.delete("1.0", tk.END)
            arp_text_output.insert(tk.END, result_of_arp_discover)
            arp_text_output.config(state="disabled")
            message.config(text="Device Discovery Completed!")

        # Start button
        tk.Button(self, text="Start", width=15,
                  command=start_arp_sweep, font=(dev_discover_font, 11), bg="#58d68d").pack()

        # Text Area for output
        arp_text_output = tk.Text(
            self, height=17, width=125, state="disabled", font=("Calibri", 11))
        arp_text_output.pack(pady=10)


class Window4(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)

        # PCAP File Analysis

        pcap_analysis_font = "Calibri"

        heading = tk.Label(
            self, text="Please select a PCAP file to read.", font=(pcap_analysis_font, 14))
        heading.pack()

        self.select_file_btn = tk.Button(self, text="Select File", width=15,
                                         command="", font=(pcap_analysis_font, 12), bg="#58d68d")
        self.select_file_btn.pack(pady=5)

        # Persistant window, displayed before reading starts.
        try:
            ReaderWindow(self)
        except Exception as ex:
            print(ex)


class Window5(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)

        # Network Speed Test

        speed_test_font = "Calibri"

        tk.Label(self, justify="left", text="Network Speedtest",
                 font=(speed_test_font, 14)).pack(pady=5)
        tk.Label(self, justify="left", text="The speed at which CableOrca tests your upload and download speed depends on your network.", font=(
            speed_test_font, 13)).pack()

        # Public IP address is discovered once per session.
        global PUBLIC_IP
        if PUBLIC_IP == "":
            # Try to get public IP address of current device using "api.ipify.org".
            PUBLIC_IP = get_public_ip()

        # If we have a public IP address, display it to gui.
        if PUBLIC_IP:
            pa_output = "This is your public IP address: "
            pa_output += PUBLIC_IP

            self.public_ip_label = tk.Label(
                self, text=pa_output, justify="left", font=(speed_test_font, 13))
            self.public_ip_label.pack()

        # This is the label that will show the results of the network speed test.
        self.result_label = tk.Label(
            self, text="", justify="left", font=(speed_test_font, 15))
        self.result_label.pack()

        # This is the label that will show the "Please stand by" message.
        self.standby_label = tk.Label(
            self, text="", justify="left", font=(speed_test_font, 15))
        self.standby_label.pack(pady=5)

        tk.Button(self, text="Start", width=15,
                  command=self.on_start_button_click, font=(speed_test_font, 12), bg="#58d68d").pack()

    def on_start_button_click(self):
        # Note: labels must first be stored as instance variables if you want to configure them!
        # This is done my using label.pack after creating the label.
        # Do not use  mylabel = tk.Label(...).pack() !
        self.standby_label.config(
            text="Please stand by...")
        # Update the GUI to display the "Please stand by" message.
        self.update_idletasks()

        # Without use of "self.", old results would be saved as an image.
        url, printable_result = get_speed_mbs()

        self.result_label.config(text=printable_result)
        # Hide the "Please stand by" message.
        self.standby_label.config(text="")

        # A save button is created for each speedtest, only spawn one button.
        if not hasattr(self, "save_url_res_button"):
            # Spawn save results button that uses a url to the results.
            self.save_url_res_button = tk.Button(self, text="Save Results", command=lambda: attempt_result_dl(
                url), font=("Calibri", 11), width=15, bg="#85c1e9")
            self.save_url_res_button.pack(pady=10)

        if not hasattr(self, "res_label"):
            self.res_label = tk.Label(
                self, text="", justify="left", font=("Calibri", 12))
            self.res_label.pack()
        else:
            self.res_label.config(text="")

        def attempt_result_dl(url):
            # Call file_manager's save_image function.
            result = save_image(url)

            if result:
                res_text = "Image Saved!"
            else:
                res_text = "Image Not Saved."

            self.res_label.config(text=res_text)


class Window6(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)

        tk.Label(self, text="This is window 6").pack()


app = MainWindow()
app.geometry("1100x650")  # Width x Height
app.mainloop()
