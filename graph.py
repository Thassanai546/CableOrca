import matplotlib.pyplot as plt


def build_pc(labels, sizes):
    # pie chart
    try:
        if len(labels) != len(sizes):
            print("Error: The number of labels and sizes must be equal")
            return
        fig1, ax1 = plt.subplots()
        ax1.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
        # Equal aspect ratio ensures that pie is drawn as a circle
        ax1.axis('equal')
        plt.show()
    except Exception as e:
        print("Error in building pie chart:", e)


def build_bc(labels, sizes):
    # bar chart
    try:
        if len(labels) != len(sizes):
            print("Error: The number of labels and sizes must be equal")
            return
        fig, ax = plt.subplots()
        ax.bar(labels, sizes)
        plt.show()
    except Exception as e:
        print("Error in building bar chart:", e)
