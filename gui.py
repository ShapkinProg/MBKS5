from tkinter import *
from tkinter import ttk
from tkinter.messagebox import showerror, showinfo, askyesno  # for messageboxes
from tkinter.filedialog import askopenfilename  # for file open
import tksheet  # for process sheet
import os  # for file path
import gui_back




# start GUI
def start_interface():
    # Create main window
    wndw_root = Tk()
    wndw_root.title("Program")
    root_width = wndw_root.winfo_screenwidth()
    root_height = wndw_root.winfo_screenheight()
    wndw_root.geometry(f'{int(root_width / 2)}x{int(root_height) - 100}')

    # Add notebook
    ntbk = ttk.Notebook(wndw_root)
    ntbk.pack(expand=True, fill='both')

    frm_processes = ttk.Frame(ntbk)
    frm_file = ttk.Frame(ntbk)

    frm_processes.pack(fill='both', expand=True)
    frm_file.pack(fill='both', expand=True)

    ntbk.add(frm_processes, text='Processes')
    ntbk.add(frm_file, text='File')

    # Create process sheet at frm_processes


    # Fill file frame


    # Main loop
    wndw_root.mainloop()

# main function
start_interface()
