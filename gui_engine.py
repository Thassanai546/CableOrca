import tkinter as tk


class ScrollableFrame(tk.Frame):
    # Instructions:
    # Can be called like this: frame = my_frame(parent,200,150) Where 200 = width, 150 = height.

    # Note: Builds frame with a border

    def __init__(self, parent, width, height, relief="groove", *args, **kwargs):
        super().__init__(parent, width=width, height=height, *args, **kwargs)

        # Border around the scrollable list of buttons
        self.config(bd=3, relief=relief)

        # Making canvas widget using specified width and height.
        # Frame is added to this canvas.
        self.canvas = tk.Canvas(self, width=width, height=height)
        self.frame = tk.Frame(self.canvas)

        # vertical scrollbar. It's command is to scroll canvas y view
        self.vsb = tk.Scrollbar(self, orient="vertical",
                                command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vsb.set)

        # scroll bar is on the right side of canvas.
        # fill "y" = fill vertical space with scrollbar.
        self.vsb.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)

        # Window in canvas
        # 4,4 = position of window on canvas.
        # tag can be used to refer to this window later, for example if it needs to be hidden.
        self.canvas.create_window(
            (4, 4), window=self.frame, anchor="nw", tags="self.frame")

        # The <Configure> event is triggered whenever the size or position of the widget changes.
        self.frame.bind("<Configure>", self.on_frame_configure)

    # on_frame_configure, being part of the scrollableFrame class
    # Requires the "self" argument.
    # Instance methods should take self as a first parameter argument.
    # Doing this allows the method to access instance variable + methods of the class
    def on_frame_configure(self, event):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))


def create_scrollable_radiobuttons(parent, items):
    # Takes a parent and a list.
    # Builds and packs radio buttons using specified list.
    # This is used to build a radio button list of network interfaces that the user can choose to sniff the network.

    radio_button_font = "Calibri"

    try:
        if not items:
            raise ValueError("The 'items' list cannot be empty")

        # Set width and height of radio button frame
        frame = ScrollableFrame(parent, 650, 300)
        variable = tk.StringVar()

        # Font of radio buttons can be set here
        for item in items:
            current_button = tk.Radiobutton(frame.frame, text=item, font=(
                radio_button_font, 16), variable=variable, value=item)
            current_button.pack(anchor='w')

        frame.pack()
        return frame, variable

    except Exception as exc:
        print(str(exc))
