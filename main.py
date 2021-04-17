from tkinter import *
from DESfiddle.utils import preprocess_key, preprocess_plaintext, encrypt, generate_round_keys, calc_diff, txt_to_hex, hex_to_bin
import matplotlib.pyplot as plt


'''
Sample plaintext and keys
pt = "This is even cooler" 
key = "Yessss"

pt = "0101010101010101010101010101010101010101010101010101010101010101"
key = "1111111111111111111111111111111100000000000000000000000000000000"
'''

'''
Some examples of weak keys to use

Weak keys->
        Hex                                 Binary(64 bits)
    0101010101010101  ->  0000000100000001000000010000000100000001000000010000000100000001
    1F1F1F1F0E0E0E0E  ->  0001111100011111000111110001111100001110000011100000111000001110
    E0E0E0E0F1F1F1F1  ->  1110000011100000111000001110000011110001111100011111000111110001
    FEFEFEFEFEFEFEFE  ->  1111111011111110111111101111111011111110111111101111111011111110

Semi-weak Keys->
        Hex                                 Binary(64 bits)
    (01FE01FE01FE01FE,         (0000000111111110000000011111111000000001111111100000000111111110,
    FE01FE01FE01FE01) ->        1111111000000001111111100000000111111110000000011111111000000001)

    (1FE01FE00EF10EF1,         (0001111111100000000111111110000000001110111100010000111011110001,
    E01FE01FF10EF10E) ->        1110000000011111111000000001111111110001000011101111000100001110)

    (01E001E001F101F1,         (0000000111100000000000011110000000000001111100010000000111110001,
    E001E001F101F101) ->        1110000000000001111000000000000111110001000000011111000100000001)

    (1FFE1FFE0EFE0EFE,         (0001111111111110000111111111111000001110111111100000111011111110,
    FE1FFE1FFE0EFE0E) ->        1111111000011111111111100001111111111110000011101111111000001110)

    (011F011F010E010E,         (0000000100011111000000010001111100000001000011100000000100001110,
    1F011F010E010E01) ->        0001111100000001000111110000000100001110000000010000111000000001)

    (E0FEE0FEF1FEF1FE,         (1110000011111110111000001111111011110001111111101111000111111110,
    FEE0FEE0FEF1FEF1) ->        1111111011100000111111101110000011111110111100011111111011110001)

Possibly weak subkeys->
        Hex                                 Binary(64 bits)
    1F1F01010E0E0101 ->         0001111100011111000000010000000100001110000011100000000100000001
    E00101E0F10101F1 ->         1110000000000001000000011110000011110001000000010000000111110001
    011F1F01010E0E01 ->         0000000100011111000111110000000100000001000011100000111000000001
    FE1F01E0FE0E01F1 ->         1111111000011111000000011110000011111110000011100000000111110001

'''

# Global Variables
# ----------------------------------------------------------------------------------------------- #
label_padx = 7  # Label padding in x direction of GUI element
field_padx = 10  # Label padding in y direction of GUI element
pady = 5    # Label padding in y direction of GUI element
color_okay = "#359c49"  # Default color of the text fields, signifies no errors
color_error = "#cf3b36"  # Color of the text field when an invalid input is supplied
color_bg = "#000000"    # Background color of the GUI
field_bg = "#0f0f0f"    # Background color of the text fields
color_sectionfg = "#ffffff"  # Font color of section header
color_fg = "#0fff03"    # Foreground colorof GUI
font_section = ("Roboto", 17)    # Font setting of a section header
font_generic = ("Courier", 14)   # Font setting of section elements


# Functions
# ----------------------------------------------------------------------------------------------- #

# Prepare a python string to print the roundkeys
def __pretty_print(RoundKeys):
    s = "Number of unique roundkeys: " + str(len(set(RoundKeys))) + "\n"
    for i in range(len(RoundKeys)):
        s += "Round "+str(i+1)+":\t"+str(RoundKeys[i])+"\n"
    return s.strip()

# Create a GUI label element for output purposes
def __make_label(txt, row, col, bg, fg, width, font):
    _label = Label(root, text=txt, width=width, anchor="w")
    _label.configure(bg=bg, fg=fg, font=font)
    _label.grid(column=col, row=row, pady=5)

# Create a GUI text field element for output purposes
def __make_field(txt, row, col, width, height, bg, fg, ib, hb, font):
    _field = Text(root, width=width, height=height)
    _field.configure(bg=bg, insertbackground=ib, fg=fg,
                     font=font, highlightbackground=hb)
    _field.grid(column=col, row=row, pady=5)

    _field.delete("1.0", "end")
    _field.insert("1.0", txt)

# Plotting the differences, i.e avalanche in each round
def __plot(x, y):
    plt.style.use("ggplot")
    plt.title("Avalanche Effect")
    plt.xlabel("No. of rounds")
    plt.ylabel("Difference")
    plt.plot(x, y)
    plt.show()

# Ham the plaintext and call the encrypt function to generate output


def __helper1(plaintext, key, nor, halfwidth, hamming_dist):
    ref_pt_arr = preprocess_plaintext(plaintext, halfwidth)
    pt_arr = preprocess_plaintext(plaintext, halfwidth, hamming_dist)
    key = preprocess_key(key, halfwidth)
    rkb, rkh = generate_round_keys(key, nor, halfwidth)
    ref_ciphertext, ref_round_ciphertexts = encrypt(
        ref_pt_arr, rkb, nor, halfwidth)
    _, round_ciphertexts = encrypt(pt_arr, rkb, nor, halfwidth)
    diff = calc_diff(ref_round_ciphertexts, round_ciphertexts)

    # Make Output label
    __make_label("Outputs-", 10, 0, color_bg,
                 color_sectionfg, 20, font_section)

    # Make ciphertext output section
    __make_label("Ciphertext:", 11, 0, color_bg, color_fg, 25, font_generic)
    __make_field(ref_ciphertext, 11, 1, 50, 1, field_bg, color_fg,
                 color_sectionfg, color_okay, font_generic)

    # Make Roundkey output section
    output = __pretty_print(rkh)
    __make_label("RoundKeys:", 12, 0, color_bg, color_fg, 25, font_generic)
    __make_field(output, 12, 1, 50, 10, field_bg, color_fg,
                 color_sectionfg, color_okay, font_generic)

    # Plotting the differences to visualize the avalanche effect
    __plot(range(1, nor+1), diff)

# Ham the key and call the encrypt function to generate output
def __helper2(plaintext, key, nor, halfwidth, hamming_dist):
    pt_arr = preprocess_plaintext(plaintext, halfwidth)
    ref_key = preprocess_key(key, halfwidth)
    key = preprocess_key(key, halfwidth, hamming_dist)
    ref_rkb, ref_rkh = generate_round_keys(ref_key, nor, halfwidth)
    rkb, _ = generate_round_keys(key, nor, halfwidth)
    ref_ciphertext, ref_round_ciphertexts = encrypt(
        pt_arr, ref_rkb, nor, halfwidth)
    _, round_ciphertexts = encrypt(pt_arr, rkb, nor, halfwidth)
    diff = calc_diff(ref_round_ciphertexts, round_ciphertexts)

    # Make Output label
    __make_label("Outputs-", 10, 0, color_bg,
                 color_sectionfg, 20, font_section)

    # Make ciphertext output section
    __make_label("Ciphertext:", 11, 0, color_bg, color_fg, 25, font_generic)
    __make_field(ref_ciphertext, 11, 1, 50, 1, field_bg, color_fg,
                 color_sectionfg, color_okay, font_generic)

    # Make Roundkey output section
    output = __pretty_print(ref_rkh)
    __make_label("RoundKeys:", 12, 0, color_bg, color_fg, 25, font_generic)
    __make_field(output, 12, 1, 50, 10, field_bg, color_fg,
                 color_sectionfg, color_okay, font_generic)

    # Plotting the differences to visualize the avalanche effect
    __plot(range(1, nor+1), diff)

# Check for polluted parameters and/or inputs to the encrypt function
def sanity_check(plaintext, key, nor, hamming_dist, halfwidth):
    # Resetting to default values before proceeding
    f1, f2, f3, f4 = 1, 1, 1, 1
    plaintext_field.configure(highlightbackground=color_okay)
    key_field.configure(highlightbackground=color_okay)
    nor_field.configure(highlightbackground=color_okay)
    hamming_field.configure(highlightbackground=color_okay)

    # If plaintext is not supplied
    if(len(plaintext) == 0):
        plaintext_field.configure(highlightbackground=color_error)
        f1 = 0
    # If key is not supplied
    if(len(key) == 0):
        key_field.configure(highlightbackground=color_error)
        f2 = 0

    # Check for type in the nor and hamming dist fields
    try:
        nor = int(nor)  # This internally checks for floating point numbers
    except:
        nor_field.configure(highlightbackground=color_error)
        f3 = 0
    try:
        # This internally checks for floating point numbers
        hamming_dist = int(hamming_dist)
    except:
        hamming_field.configure(highlightbackground=color_error)
        f4 = 0

    # If nor or hamming distance is negative
    if(f3 == 1 and nor < 0):
        nor_field.configure(highlightbackground=color_error)
        f3 = 0
    if(f4 == 1 and hamming_dist < 0):
        hamming_field.configure(highlightbackground=color_error)
        f4 = 0

    if(option2.get() == 1):
        # Check for non-binary plaintext in Binary setting
        for c in plaintext:
            if(c == '1' or c == '0'):
                continue
            else:
                plaintext_field.configure(highlightbackground=color_error)
                f1 = 0
                break
        # Check for non-binary key in Binary setting
        for c in key:
            if(c == '1' or c == '0'):
                continue
            else:
                key_field.configure(highlightbackground=color_error)
                f2 = 0
                break
        # If plaintext satisfies the halfwidth criteria in binary setting
        if(len(plaintext) != 2*halfwidth):
            f1 = 0
            plaintext_field.configure(highlightbackground=color_error)
        # If key satisfies the halfwidth criteria in binary setting
        if(len(key) != 2*halfwidth):
            f2 = 0
            key_field.configure(highlightbackground=color_error)
        # Checking for different plaintext and key lengths
        if(len(key) != len(plaintext)):
            f1 = 0
            f2 = 0
            plaintext_field.configure(highlightbackground=color_error)
            key_field.configure(highlightbackground=color_error)

    # Converting plaintext to binary for further analysis in ASCII setting
    if(option2.get() == 2):
        plaintext = txt_to_hex(plaintext)
        plaintext = hex_to_bin(plaintext)
    # Checking if hamming distance is less than length of the plaintext
    if(f4 == 1 and hamming_dist > len(plaintext)):
        hamming_field.configure(highlightbackground=color_error)
        f4 = 0

    # If settings are okay then resetting the color of the fields to signify the same
    root.focus()
    if(f1 == 1):
        plaintext_field.configure(highlightbackground=color_okay)
    if(f2 == 1):
        key_field.configure(highlightbackground=color_okay)
    if(f3 == 1):
        nor_field.configure(highlightbackground=color_okay)
    if(f4 == 1):
        hamming_field.configure(highlightbackground=color_okay)

    # Notifying the caller that inputs are okay and to proceed with further analysis
    flag = (f1 & f2 & f3 & f4)
    return flag

# Extracts various inputs and settings and calls the encrypt function after an input sanitization
def __analyze():
    # Extracting various inputs provided by the user from GUI fields
    plaintext = plaintext_field.get("1.0", "end-1c")
    key = key_field.get("1.0", "end-1c")
    nor = nor_field.get("1.0", "end-1c")
    halfwidth = option3.get()
    hamming_dist = hamming_field.get("1.0", "end-1c")

    # Checking for polluted parameters in the inputs
    flag = sanity_check(plaintext, key, nor, hamming_dist, halfwidth)
    # If inputs are polluted then stop execution
    if(flag != 1):
        return

    # Now converting string to integer for the various inputs provided
    nor = int(nor)
    halfwidth = int(halfwidth)
    hamming_dist = int(hamming_dist)

    # Calling the appropriate helper function for cross-script referencing
    if(option1.get() == 1 and option2.get() == 1):
        __helper1(plaintext, key, nor, halfwidth, hamming_dist)
    elif(option1.get() == 2 and option2.get() == 1):
        __helper2(plaintext, key, nor, halfwidth, hamming_dist)
    elif(option1.get() == 1 and option2.get() == 2):
        plaintext = txt_to_hex(plaintext)
        plaintext = hex_to_bin(plaintext)
        key = txt_to_hex(key)
        key = hex_to_bin(key)
        __helper1(plaintext, key, nor, halfwidth, hamming_dist)
    else:
        plaintext = txt_to_hex(plaintext)
        plaintext = hex_to_bin(plaintext)
        key = txt_to_hex(key)
        key = hex_to_bin(key)
        __helper2(plaintext, key, nor, halfwidth, hamming_dist)


# GUI part
# ----------------------------------------------------------------------------------------------- #
# Initializing main window
root = Tk()
root.resizable(False, False)
root.configure(bg=color_bg)

# Setting application icon
try:
    favicon = PhotoImage(file="./icon.png")
    root.iconphoto(True, favicon)
except:
    pass

# Title and dimensions of main window
root.title("Data Encryption Standard")
root.geometry('')

# Input Header
input_label = Label(root, text="Inputs-", width="20", anchor="w")
input_label.configure(bg=color_bg, fg=color_sectionfg, font=font_section)
input_label.grid(column=0, row=0, pady=pady, padx=label_padx)

# Plaintext section
plaintext_label = Label(root, text="Plaintext:", width=25, anchor="w")
plaintext_label.configure(bg=color_bg, fg=color_fg, font=font_generic)
plaintext_label.grid(column=0, row=1, pady=pady, padx=label_padx)

plaintext_field = Text(root, width=50, height=1)
plaintext_field.configure(bg=field_bg, insertbackground='#ffffff',
                          fg=color_fg, font=font_generic, highlightbackground=color_okay)
plaintext_field.grid(column=1, row=1, pady=pady, padx=field_padx)

# Key section
key_label = Label(root, text="Key:", width=25, anchor="w")
key_label.configure(bg=color_bg, fg=color_fg, font=font_generic)
key_label.grid(column=0, row=2, pady=pady, padx=label_padx)

key_field = Text(root, width=50, height=1)
key_field.configure(bg=field_bg, insertbackground='#ffffff',
                    fg=color_fg, font=font_generic, highlightbackground=color_okay)
key_field.grid(column=1, row=2, pady=pady, padx=field_padx)

# Settings Header
settings_label = Label(root, text="Specify Settings-", width="20", anchor="w")
settings_label.configure(bg=color_bg, fg=color_sectionfg, font=font_section)
settings_label.grid(column=0, row=3, pady=pady, padx=label_padx)

# Number of rounds (nor) section
nor_label = Label(root, text="No. of rounds:", width=25, anchor="w")
nor_label.configure(bg=color_bg, fg=color_fg, font=font_generic)
nor_label.grid(column=0, row=4, pady=pady, padx=label_padx)

nor_field = Text(root, width=50, height=1)
nor_field.configure(bg=field_bg, insertbackground='#ffffff',
                    fg=color_fg, font=font_generic, highlightbackground=color_okay)
nor_field.insert("1.0", "16")  # Setting default value of nor to 16
nor_field.grid(column=1, row=4, pady=pady, padx=field_padx)

# Hamming distance section
hamming_label = Label(root, text="Hamming distance:", width=25, anchor="w")
hamming_label.configure(bg=color_bg, fg=color_fg, font=font_generic)
hamming_label.grid(column=0, row=5, pady=pady, padx=label_padx)

hamming_field = Text(root, width=50, height=1)
hamming_field.configure(bg=field_bg, insertbackground='#ffffff',
                        fg=color_fg, font=font_generic, highlightbackground=color_okay)
# Setting default value of hamming distance to 1
hamming_field.insert("1.0", 1)
hamming_field.grid(column=1, row=5, pady=pady, padx=field_padx)

# Halfwidth(Radiobutton choices) section
setting3_label = Label(root, text="Half-width of block:", width=25, anchor="w")
setting3_label.configure(bg=color_bg, fg=color_fg, font=font_generic)
setting3_label.grid(column=0, row=6)

# Tkinter special variable to store the state of the radiobutton
option3 = IntVar()
option3.set("32")  # Setting default value of halfwidth to 32

# Creating a radiogroup to group together similar radiobuttons
radiogroup3 = Frame(root)
radiogroup3.configure(bg=color_bg)

# Radiobutton for halflength of 16
setting3_radio1 = Radiobutton(radiogroup3, text="16", variable=option3,
                              value=16, highlightthickness=0, width=9, anchor="w")
setting3_radio1.configure(bg=color_bg, fg=color_fg, font=font_generic, activebackground=color_bg,
                          activeforeground=color_fg, selectcolor=color_bg, cursor="hand1")

# Radiobutton for halflength of 32
setting3_radio2 = Radiobutton(radiogroup3, text="32", variable=option3,
                              value=32, highlightthickness=0, width=9, anchor="w")
setting3_radio2.configure(bg=color_bg, fg=color_fg, font=font_generic, activebackground=color_bg,
                          activeforeground=color_fg, selectcolor=color_bg, cursor="hand1")

# Radiobutton for halflength of 64
setting3_radio3 = Radiobutton(radiogroup3, text="64", variable=option3,
                              value=64, highlightthickness=0, width=9, anchor="w")
setting3_radio3.configure(bg=color_bg, fg=color_fg, font=font_generic, activebackground=color_bg,
                          activeforeground=color_fg, selectcolor=color_bg, cursor="hand1")

# Place the radiobuttons on the GUI
setting3_radio1.grid(column=0, row=0)
setting3_radio2.grid(column=1, row=0)
setting3_radio3.grid(column=2, row=0)
radiogroup3.grid(column=1, row=6, pady=pady)

# Choice to apply hamming to Plaintext or key
setting1_label = Label(
    root, text="Hamming distance for:", width=25, anchor="w")
setting1_label.configure(bg=color_bg, fg=color_fg, font=font_generic)
setting1_label.grid(column=0, row=7)

# Tkinter special variable to store the state of the radiobutton
option1 = IntVar()
option1.set("1")  # Setting default setting to Plaintext

# Creating a radiogroup to group together similar radiobuttons
radiogroup1 = Frame(root)
radiogroup1.configure(bg=color_bg)

# Radiobutton for Plaintext
setting1_radio1 = Radiobutton(radiogroup1, text="Plaintext", variable=option1,
                              value=1, highlightthickness=0, width=15, anchor="w")
setting1_radio1.configure(bg=color_bg, fg=color_fg, font=font_generic, activebackground=color_bg,
                          activeforeground=color_fg, selectcolor=color_bg, cursor="hand1")
# Radiobutton for key
setting1_radio2 = Radiobutton(radiogroup1, text="Key", variable=option1,
                              value=2, highlightthickness=0, width=15, anchor="w")
setting1_radio2.configure(bg=color_bg, fg=color_fg, font=font_generic, activebackground=color_bg,
                          activeforeground=color_fg, selectcolor=color_bg, cursor="hand1")

# Place the radiobuttons on the GUI
setting1_radio1.grid(column=0, row=0)
setting1_radio2.grid(column=1, row=0)
radiogroup1.grid(column=1, row=7, pady=pady)

# Choice to choose the type of plaintext and key
setting2_label = Label(root, text="Plaintext & key in:", width=25, anchor="w")
setting2_label.configure(bg=color_bg, fg=color_fg, font=font_generic)
setting2_label.grid(column=0, row=8)

# Tkinter special variable to store the state of the radiobuttion
option2 = IntVar()
option2.set("1")  # Setting default setting to Binary

# Creating a radiogroup to group together similar radiobuttons
radiogroup2 = Frame(root)
radiogroup2.configure(bg=color_bg)

# Radiobutton for choice of type binary
setting2_radio1 = Radiobutton(radiogroup2, text="Binary", variable=option2,
                              value=1, highlightthickness=0, width=15, anchor="w")
setting2_radio1.configure(bg=color_bg, fg=color_fg, font=font_generic, activebackground=color_bg,
                          activeforeground=color_fg, selectcolor=color_bg, cursor="hand1")

# Radiobutton for choice of type ASCII
setting2_radio2 = Radiobutton(radiogroup2, text="ASCII", variable=option2,
                              value=2, highlightthickness=0, width=15, anchor="w")
setting2_radio2.configure(bg=color_bg, fg=color_fg, font=font_generic, activebackground=color_bg,
                          activeforeground=color_fg, selectcolor=color_bg, cursor="hand1")

# Place the radiobuttons on the GUI
setting2_radio1.grid(column=0, row=0)
setting2_radio2.grid(column=1, row=0)
radiogroup2.grid(column=1, row=8, pady=pady)

# Button to perform analysis
btn = Button(root, text="Analyse", width=25,
             justify="center", command=__analyze)
btn.configure(bg=color_bg, fg=color_sectionfg, activebackground=color_bg,
              activeforeground=color_fg, highlightbackground=color_okay)
btn.grid(column=1, row=9, pady=pady)


# Run the GUI as a standalone app and not when imported in another script
if __name__ == "__main__":
    # Runs the GUI continuously
    root.mainloop()
