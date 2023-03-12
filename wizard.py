import re

import tkinter as tk

from net_interfaces import check_internet
from net_speed_test import get_speed_mbs
from arp_sweeper import arp_discovery

# Sample questions
questions = ["Would you like me to see if I can connect to the internet?",
             "Would you like me to try and measure the current network speed?",
             "Would you like me to try and discover the names of devices on the network?"]


class WizardTracker():
    answers = []
    called_functions = set()

    def reset(self):
        self.answers = []
        self.called_functions = set()
        print("Diagnostic Data Reset!")


tracker = WizardTracker()


class DiagnosticWizard(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)

        self.pack()
        self.current_question = 0
        self.create_widgets()

        # Reset diagnostic data
        if tracker:
            tracker.reset()

    def create_widgets(self):
        wizard_font = "Calibri"

        # Text area for displaying questions and answers
        self.question_text = tk.Text(self, height=13, width=85,
                                     wrap="word", font=(wizard_font, 14), pady=5, padx=5)
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
            print(tracker.answers)
            print(tracker.called_functions)

            # RESET WINDOW
            self.master.destroy()

    def display_question(self):
        # Display current question in the text area
        self.question_text.delete("1.0", tk.END)
        self.question_text.insert(tk.END, questions[self.current_question])

    def answer_yes(self):
        tracker.answers.append(1)

        # Find and execute command user has specified
        self.check_list(tracker.answers)

        # User answering a questions results in answer buttons becoming locked.
        # Enable next question button.
        self.yes_button.config(state=tk.DISABLED)
        self.no_button.config(state=tk.DISABLED)
        self.next_button.config(state=tk.NORMAL)

    def answer_no(self):
        tracker.answers.append(0)

        # User answering a questions results in answer buttons becoming locked.
        # Enable next question button.
        self.yes_button.config(state=tk.DISABLED)
        self.no_button.config(state=tk.DISABLED)
        self.next_button.config(state=tk.NORMAL)

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
            Called functions are added to "called_functions".
            This prevents them from being run again for each answer the user supplies to the wizard.
            Instructions: 
            1)Print result to text box 
            2) Add to "called_functions"
            '''

            if lst[i] == 1:
                if i == 0 and wizard_check_internet not in tracker.called_functions:
                    # Test internet connection
                    result = wizard_check_internet()
                    self.question_text.delete("1.0", tk.END)
                    self.question_text.insert(tk.END, result)
                    tracker.called_functions.add(wizard_check_internet)

                elif i == 1 and wizard_check_speed not in tracker.called_functions:
                    # Test internet speed
                    result = wizard_check_speed()
                    self.question_text.delete("1.0", tk.END)
                    self.question_text.insert(tk.END, result)
                    tracker.called_functions.add(wizard_check_speed)

                elif i == 2 and wizard_device_discover not in tracker.called_functions:
                    # Discover devices on the network
                    devices = wizard_device_discover()
                    self.question_text.delete("1.0", tk.END)
                    self.question_text.insert(tk.END, devices)
                    tracker.called_functions.add(wizard_check_speed)
                    tracker.called_functions.add(wizard_device_discover)


# "Wizard call" functions return their result in to the wizard text area for the user
# during guided analysis.
def wizard_check_internet():
    if not check_internet():
        msg = "Internet connection is up and running."
    else:
        msg = "There are several possible reasons why your device may not have internet connection:\n\n1. Network issues: Your device may not be connected to a network, or the network you're connected to may be experiencing issues.\n\n2. Router issues: Your router may be malfunctioning, or it may not be properly set up.\n\n3. Software issues: Your device's software may be outdated or may be experiencing compatibility issues with your network or router.\n\n4. Account issues: Your internet service provider (ISP) may have suspended your account or there may be an issue with your payment.\n\n5. Physical damage: Your device's hardware may be damaged or broken, which can affect its ability to connect to the internet.\n\nPlease check these possibilities to troubleshoot the issue and restore your internet connection."

    return msg


def wizard_check_speed():
    url, speed_result = get_speed_mbs()
    if speed_result:
        return "I have tested your internet speed! Scroll down for more information.\n" + speed_result + "\nYou can view some more details about your speed test here:" + url
    else:
        return "Sorry, I could not get a speed test at this time. Please try again!"


def wizard_device_discover():
    manufacturer = re.findall(r'Manufacturer:\s+(.*?)\n', arp_discovery())
    printable_result = ""

    if manufacturer:
        printable_result = f"I found these devices on your network! Scroll down if needed. If an entry says 'Not Found.' then I seen a device that I could not identify!\n\n"

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


def unsupported():
    print("Unsupported list size")
