import tkinter as tk
from PIL import Image, ImageTk

from arp_sweeper import *
from file_manager import *
from gui_engine import *
from net_interfaces import *
from net_speed_test import *
from pcap_parser import *
from sniffer_engine import *
from windows_library_check import *
from wizard import *


class GlobalDetails:
    def __init__(self):
        # Globals:
        # As windows changes, certain variables need to be held
        # so that processing time is saved.
        self.device_info = []  # Printable summary
        self.public_ip = ""
        self.library_check = False
        self.has_pcap_libr = False
        self.internet_con = False

    def reset(self):
        # Potentially add button to reset all data.
        self.__init__()

    def display_device_summary(self):
        summary = ""
        for i, item in enumerate(self.device_info):
            # Add a newline to all but the first item
            if i == 0:
                summary += item
            else:
                summary += '\n' + item

        return summary


global_details = GlobalDetails()


class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()

        # Configure title for CO Online, or Offline mode.
        # From net_interfaces.py, returns true/false
        global_details.internet_con = check_internet()

        if global_details.internet_con:
            self.title("CableOrca - Online Mode")
        else:
            self.title("CableOrca - Offline Mode")

        # Non resizable
        self.resizable(False, False)

        # Creates directory called "CableOrca_files" if it does not exist.
        # This must be done before downloading files to CO directory.
        create_directory()

        """
        Image download links
        These files are stored in "CableOrca_files"
        """
        icon_1 = "https://raw.githubusercontent.com/Thassanai546/CableOrca/main/Assets/CableOrcaIco.ico"
        icon_2 = "https://raw.githubusercontent.com/Thassanai546/CableOrca/main/Assets/CableOrcaIcon.png"
        wizard_image = "https://raw.githubusercontent.com/Thassanai546/CableOrca/main/Assets/wizard.png"

        # Use file_manager's downloader to fetch three images
        if download_to_cableorca(icon_1):
            self.iconbitmap("CableOrca_files\CableOrcaIco.ico")
        download_to_cableorca(icon_2)
        download_to_cableorca(wizard_image)

        # Create sidebar
        self.sidebar = tk.Frame(self, bg="#34495e", width=100, pady=5)
        self.sidebar.pack(side="left", fill="y")

        # Create and pack buttons for sidebar
        # Buttons have been placed in order according to network diagnostic steps!
        sidebbar_font = "Calibri"

        self.button1 = tk.Button(
            self.sidebar, width=17, text="Home", command=lambda: self.change_window(Window1), font=(sidebbar_font, 12))
        self.button1.pack(padx=5, pady=3)
        self.button5 = tk.Button(
            self.sidebar, width=17, text="Network Speed Test", command=lambda: self.change_window(Window5), font=(sidebbar_font, 12))
        self.button5.pack(padx=5, pady=3)
        self.button3 = tk.Button(
            self.sidebar, width=17, text="Discover Devices", command=lambda: self.change_window(Window3), font=(sidebbar_font, 12))
        self.button3.pack(padx=5, pady=3)
        self.button2 = tk.Button(
            self.sidebar, width=17, text="Configure Scan", command=lambda: self.change_window(Window2), font=(sidebbar_font, 12))
        self.button2.pack(padx=5, pady=3)
        self.button4 = tk.Button(
            self.sidebar, width=17, text="Analyse .pcap File", command=lambda: self.change_window(Window4), font=(sidebbar_font, 12))
        self.button4.pack(padx=5, pady=3)
        self.button6 = tk.Button(
            self.sidebar, width=17, text="Wizard", command=lambda: self.change_window(Window6), font=(sidebbar_font, 12))
        self.button6.pack(padx=5, pady=3)

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

        home_font = "Calibri"

        # This message is always displayed.
        try:
            tk.Label(self, text="⚡ Welcome to CableOrca, the high-level packet sniffer!",
                     justify="left", font=(home_font, 16), pady=5, padx=5, fg="white", bg="#222a38").pack(pady=10)
        except:
            # Non-special character handling
            tk.Label(self, text="Welcome to CableOrca, the high-level packet sniffer!",
                     justify="left", font=(home_font, 16), pady=5, padx=5, fg="white", bg="#222a38").pack(pady=10)

        # Prevent need for discovering device name every time it is needed
        if len(global_details.device_info) == 0:
            global_details.device_info = get_current_device()

        # Output device info
        summary = global_details.display_device_summary()

        # Attempt to display device information
        tk.Label(self, text=summary,
                 justify="left", font=(home_font, 15)).pack()

        # Attempt to display CableOrca logo
        try:
            image = Image.open("CableOrca_files\CableOrcaIcon.png")
            image = image.resize((270, 270), Image.LANCZOS)
            self.photo = ImageTk.PhotoImage(image)
            tk.Label(self, image=self.photo).pack(pady=5, padx=5)
        except Exception as ex:
            print(ex)

        if global_details.internet_con:
            tk.Label(self, fg="#2fc76d", text="Internet Connection Established - Online Mode Enabled",
                     justify="left", font=(home_font, 16), pady=5, padx=5).pack(pady=5)
        else:
            tk.Label(self, fg="#cd5e6a", text="Internet Connection Disabled - Offline Mode Enabled",
                     justify="left", font=(home_font, 16), pady=5, padx=5).pack(pady=5)

        # Try to search for pcap library on Windows.
        # If it is not found, links npcap download page.
        # Note! It is important to leave space on the homepage for this warning!
        try:
            if global_details.library_check is False:
                # Search for a specified dll on the system.
                global_details.has_pcap_libr = check_dll("wpcap.dll")

            if global_details.has_pcap_libr:
                global_details.library_check = True  # System has been checked for wpcap.dll
                message = tk.Label(
                    self, justify="left", text="The required PCAP library has been detected on your system. The application is now ready to run.", fg="#2fc76d", font=(home_font, 16))
                message.pack()

                # Disclaimer is always displayed
                disclaimer = """[ ! ] A packet sniffer is a tool that allows a user to monitor and capture data being transmitted over a network. It is important to understand that the use of packet sniffers can be illegal, especially if used without proper authorization or for malicious purposes."""
                tk.Label(self, text=disclaimer, justify="left", font=(
                    home_font, 14), wraplength=500, fg="red").pack(pady=10)
            else:
                disclaimer = tk.Label(
                    self, font=(home_font, 14), fg="#cd5e6a", text="Attention! CableOrca requires a PCAP library, and it appears that one could not be found on your system.\nTo ensure proper functioning, please follow the link provided below to download and install the necessary library.")
                disclaimer.pack()
                hyperlink = tk.Label(
                    self, font=(home_font, 14), text="Link to Download", fg="blue", cursor="hand2")
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
            self, text="\nVisit the GitHub", fg="blue", cursor="hand2", font=(home_font, 14))
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

        # Title of current window.
        title = tk.Label(self, justify="left", text="Configure Network Scan",
                         font=(scanner_font, 18))
        title.pack(pady=5)

        # Display device information + heading
        summary = global_details.display_device_summary()

        self.summary_label = tk.Label(self, text=summary,
                                      justify="left", font=(scanner_font, 16))
        self.summary_label.pack(pady=5)

        self.heading = tk.Label(
            self, text="Please select an interface to use.", font=(scanner_font, 18))
        self.heading.pack(pady=5)

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
        self.interface_label = tk.Label(self, font=(scanner_font, 18))
        self.interface_label.pack(pady=5)

        # Note to user
        self.info = tk.Label(self, text="\n[ ! ] Leave duration field blank for the default duration of 60 seconds.",
                             font=(scanner_font, 16))
        self.info.pack()

        # Create a frame to hold d_label, duration_field, and confirm_button
        # Allows for widgets to be placed beside eachother
        scan_duration_frame = tk.Frame(
            self, bd=1, relief="ridge", padx=5, pady=5)
        scan_duration_frame.pack(pady=5)

        # Duration label
        self.d_label = tk.Label(scan_duration_frame, text="Set Scan Duration (In Seconds):",
                                font=(scanner_font, 16))
        self.d_label.pack(side="left", pady=5)

        # Duration text field where validate command is "check_if_digit"
        self.duration_field = tk.Entry(scan_duration_frame, validate="key", validatecommand=(
            self.register(check_if_digit), "%P"), width=7, font=(scanner_font, 18))
        self.duration_field.pack(side="left", padx=5, pady=5)

        # Create a Checkbutton to enable/disable continuous scanning
        self.compact_view = tk.BooleanVar()
        self.compact_view.set(False)
        self.compact_view_checkbox = tk.Checkbutton(
            scan_duration_frame, text="Compact Output", variable=self.compact_view, font=(scanner_font, 16))
        self.compact_view_checkbox.pack(side="left")

        # Create button to confirm the selected interface
        # It is disabled by default.
        self.confirm_button = tk.Button(
            self, font=(scanner_font, 12), text="Start Scan", width=15, command=self.confirm_sniff, state=tk.DISABLED, pady=1, bg="#5fe884")
        self.confirm_button.pack(pady=10)

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
        view_bool = self.compact_view.get()

        # No duration = 60 second default
        try:
            duration = int(duration)
        except ValueError:
            duration = 60
            print(
                "Duration field is not an integer. Setting duration to default value of 60 seconds.")

        # Remove all widgets on the "Configre Scan" page
        for widget in self.pack_slaves():
            widget.pack_forget()

        # Message above analysis feed
        user_message = f"Network analysis in started on [{chosen_interface}] Duration: [{duration}] seconds."

        user_message_label = tk.Label(self, text=user_message,
                                      font=("calibri", 16))
        user_message_label.pack(pady=10)

        # Display live analysis window in place of all previous widgets.
        try:
            # sniffer_engine.py's "sniffer_window" is spawned on "self".
            SnifferWindow(self, duration, chosen_interface, view_bool)
        except Exception as ex:
            print("Sniffer Window has not been created: ")
            print(ex)


class Window3(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)

        # Discover devices on the network using ARP.

        def start_arp_sweep():
            # Called when "Start" button is clicked.
            result_of_arp_discover = arp_discovery()
            arp_text_output.config(state="normal")
            arp_text_output.delete("1.0", tk.END)

            # Count no. devices discovered
            count = 0

            for line in result_of_arp_discover.splitlines():
                if "Manufacturer: Not Found." in line:
                    arp_text_output.insert(tk.END, line + '\n', "red")
                else:
                    arp_text_output.insert(tk.END, line + '\n')

                count = count + 1

            # Set text area tag configuration to change font color
            arp_text_output.tag_config("red", foreground="red")

            start_btn.config(text="Re-scan")
            arp_text_output.config(state="disabled")

            # Post-scan message
            post_scan_msg = f"Device Discovery Completed, {count} Device(s) Found.\n"
            message.config(text=post_scan_msg)

            # Enable save button as we have content to save now.
            save_btn.config(state=tk.NORMAL)

        def call_file_saver():
            # called by "Save Results" button.
            # 1.0 = line 1, col 0. end-1c = end of text -1 character.
            output = arp_text_output.get("1.0", "end-1c")
            if save_txt_file(output):
                message.config(text="Results Have Been Saved.\n")
            else:
                message.config(text="Results Have Not Been Saved.\n")

        dev_discover_font = "Calibri"

        title = tk.Label(self, justify="left", text="Network Device Discovery",
                         font=(dev_discover_font, 18))
        title.pack(pady=5)

        message = tk.Label(self, justify="left", text="The speed at which CableOrca discovers devices depends on your network.\n", font=(
            dev_discover_font, 16))
        message.pack()

        # Start button
        # Calls arp_sweeper.py function
        start_btn = tk.Button(self, text="Begin Discovery", width=15,
                              command=start_arp_sweep, font=(dev_discover_font, 13), bg="#58d68d")
        start_btn.pack(pady=2)

        # Text Area for output of arp sweep results
        arp_text_output = tk.Text(
            self, height=20, width=90, wrap="word", font=(dev_discover_font, 14), pady=15, padx=15)  # wrap="word" = prevent mid-word wrapping.
        arp_text_message = "An ARP request is a type of network packet used to determine the MAC address of a device on the local network. It works by broadcasting a request to all devices on the network, asking the device with a specific IP address to respond with its MAC address. CableOrca will use these ARP requests to discover devices."
        arp_text_output.insert(tk.END, arp_text_message)
        arp_text_output.config(bg="#e9eaeb", state="disabled")
        arp_text_output.pack(pady=10)

        # Create save button that is disabled by default.
        save_btn = tk.Button(self, text="Save Results", width=15,
                             command=call_file_saver, font=(dev_discover_font, 13))
        save_btn.pack(pady=2)
        save_btn.config(state=tk.DISABLED)


class Window4(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        # Read a .pcap file

        # Persistant window, displayed before reading starts.
        try:
            # This spawns a text area.
            ReaderWindow(self)
        except Exception as ex:
            print(ex)


class Window5(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)

        # Network Speed Test

        def on_start_button_click():
            speed_test_output.config(state=tk.NORMAL)
            speed_test_output.delete("1.0", tk.END)

            self.url, self.result = get_speed_mbs()
            speed_test_output.insert('end', self.result)
            speed_test_output.config(state=tk.DISABLED)

            # Enable save button now that we have results
            save_button.config(state=tk.NORMAL)

        def save_btn_clicked():
            # call file_managery.py save image function
            result = save_image(self.url)
            if result:
                save_status.config(text="Speed Test Results Saved!")
            else:
                save_status.config(text="Speed Test Results Not Saved")

        self.url = ""
        self.result = ""
        speed_test_font = "Calibri"

        # Title of current window.
        title = tk.Label(self, justify="left", text="Network Speed Test",
                         font=(speed_test_font, 18))
        title.pack(pady=5)

        # Label for description message.
        message_label = tk.Label(self, justify="left", text="The speed at which CableOrca tests your upload and download speed depends on your network.\n", font=(
            speed_test_font, 14))
        message_label.pack()

        # Display current device hostname
        device_name = global_details.device_info[1]
        int_details = global_details.device_info[2]

        device_name = device_name + '\n' + int_details + '\n'

        device_inf = tk.Label(
            self, text=device_name, font=(speed_test_font, 16))
        device_inf.pack()

        # Check if public IP has been set yet
        # If statement stops public address from being re-fetched, saving time
        current_ip_addr = global_details.public_ip
        if current_ip_addr == "":
            # If public IP not set, try to set it
            current_ip_addr += "IP Address: "
            current_ip_addr += get_public_ip()
            global_details.public_ip = current_ip_addr

        address_label = tk.Label(
            self, text=current_ip_addr + '\n', font=(speed_test_font, 16))
        address_label.pack()

        # Configure speed_test_output window.
        # wrap="word" = prevent mid-word wrapping.
        speed_test_output = tk.Text(self, height=10, width=60, wrap="word", font=(
            speed_test_font, 16), padx=10, pady=10)
        speed_test_output.pack(pady=4)

        default_text = "Please refrain from interacting with the application for approximately 20 seconds while the network speed is being measured."

        speed_test_output.insert('end', default_text)
        speed_test_output.config(state=tk.DISABLED)

        # Button to start network speed test
        tk.Button(self, text="Start", width=15,
                  command=on_start_button_click, font=(speed_test_font, 12), bg="#58d68d").pack(pady=5)

        # Button to save results of network speed test
        save_button = tk.Button(self, text="Save Results", width=15,
                                command=save_btn_clicked, font=(speed_test_font, 12))
        save_button.pack(pady=5)
        save_button.config(state=tk.DISABLED)

        # Save status message
        save_status = tk.Label(self, justify="left", text="", font=(
            speed_test_font, 14))
        save_status.pack()


class Window6(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)

        wizard_font = "Calibri"

        # Attempt to display the wizard image
        try:
            image = Image.open("CableOrca_files\wizard.png")
            image = image.resize((250, 250), Image.LANCZOS)
            self.photo = ImageTk.PhotoImage(image)
            tk.Label(self, image=self.photo).pack(pady=25)

            wizard_says = tk.Label(self, justify="left", text="Bob the Wizard says: ", font=(
                wizard_font, 16))
            wizard_says.pack(pady=8)
        except Exception as ex:
            print(ex)

        # Create a text area and pack it into the text frame
        # This introduces the user
        self.welcome_text_area = tk.Text(self, height=5, width=60,
                                         wrap="word", font=("Arial", 15), pady=15, padx=15)
        self.welcome_text_area .pack(pady=5, padx=5)

        # Insert the introduction text into the widget
        intro_text = "Greetings, my friend! I'm "
        self.welcome_text_area .insert(tk.END, intro_text)
        self.welcome_text_area .insert(tk.END, "Bob the Wizard", "bold")
        self.welcome_text_area .insert(
            tk.END, ", and I'm here to help you troubleshoot your network using CableOrca Packet Sniffer. Network troubleshooting can be a daunting task, but fear not, for I am here to make it easy and user-friendly!")

        # Bob's name is "BOLD" and purple.
        self.welcome_text_area .tag_configure("bold", font=(
            "Arial", 14, "bold"), foreground="purple")

        self.welcome_text_area .config(state=tk.DISABLED)

        # Start button
        self.start_button = tk.Button(
            self, font=(wizard_font, 12), text="Start", width=15, command=self.start_wiz, pady=1, bg="#5fe884")
        self.start_button.pack(pady=15)

    def start_wiz(self):
        self.start_button.pack_forget()
        self.welcome_text_area.pack_forget()

        try:
            DiagnosticWizard(self)
        except:
            print("Wizard tool failed to load.")


app = MainWindow()
app.geometry("1250x750")  # Width x Height of the application window
app.mainloop()
