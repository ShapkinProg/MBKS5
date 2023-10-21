from tkinter import *
from tkinter import ttk
from tkinter.messagebox import showerror, showinfo, askyesno  # for messageboxes
from tkinter.filedialog import askopenfilename  # for file open
import tksheet  # for process sheet
import os  # for file path
import gui_back


# Open window with dlls
def open_ddls_window(pid):
    # Get list of ddls
    list_of_dlls = gui_back.get_list_of_dlls(pid)

    # Create window
    wndw_dlls = Toplevel()
    wndw_dlls.title("DLLs")
    wndw_dlls.geometry("300x300")

    # Add scrollbar
    scrlbr_lst_dlls = Scrollbar(wndw_dlls)
    scrlbr_lst_dlls.pack(side=RIGHT, fill=Y)

    # Add listbox
    lst_dlls = Listbox(wndw_dlls, yscrollcommand=scrlbr_lst_dlls.set)
    for dll in list_of_dlls:
        lst_dlls.insert(END, dll)

    # Pack everything
    Label(wndw_dlls, text=f"PID:{pid}").pack()
    lst_dlls.pack(side=LEFT, fill=BOTH, expand=True)
    scrlbr_lst_dlls.config(command=lst_dlls.yview)


# Open window with environment vars
def open_env_window(pid):
    # Get list of env vars
    list_of_env_vars = gui_back.get_list_of_env_vars(pid)

    # Create window
    wndw_env = Toplevel()
    wndw_env.title("Environment")
    wndw_env.geometry("300x300")

    # Add label
    Label(wndw_env, text=f"PID:{pid}").pack()

    # Create sheet
    sht_env = tksheet.Sheet(wndw_env,
                            headers=["Name", "Value"])
    sht_env.pack(expand=True, fill='both')
    sht_env.enable_bindings(("single_select",
                             "row_select",
                             "column_select",
                             "column_width_resize",
                             "arrowkeys",
                             "right_click_popup_menu",
                             "rc_select",
                             "copy",
                             ))

    # Fill env sheet
    keys = list(list_of_env_vars.keys())
    data = [[key, list_of_env_vars[key]] for key in keys]
    sht_env.set_sheet_data(data)


def open_integlvl_window(pid):
    cur_il = gui_back.get_integrity_level(int(pid))

    # Create window
    wndw_il = Toplevel()
    wndw_il.title("Integrity level")
    wndw_il.geometry("250x150")
    wndw_il.grab_set()

    # Values for radiobuttons
    list_of_il = ['Protected', 'System', 'High', 'Medium', 'Low', 'Untrusted']
    new_il = StringVar(value=cur_il)

    # Function when new radiobutton selected
    def il_selected():
        nonlocal cur_il
        # If new integrity level is higher than current
        if list_of_il.index(new_il.get()) < list_of_il.index(cur_il):
            new_il.set(cur_il)
            showerror(title="Error", message="Cannot increase integrity level")
        elif list_of_il.index(new_il.get()) == list_of_il.index(cur_il):
            showinfo(title="Info", message=f"Already set '{cur_il}'")
        else:
            yesnores = askyesno(title="Are you sure?", message="Once lowered, the integrity level "
                                                               "cannot be raised again. Continue?")
            if yesnores:
                res = gui_back.set_integrity_level(pid, new_il.get())
                if res == "done":
                    cur_il = new_il.get()
                    showinfo(title="Info", message=f"Integrity level '{cur_il}' set")
                else:
                    showerror(title="Error: cannot change integrity level", message=res)
                    new_il.set(cur_il)
            else:
                new_il.set(cur_il)

    # Create radiobuttons
    rbs = []
    for il in list_of_il:
        rbs.append(ttk.Radiobutton(wndw_il, text=il, variable=new_il, value=il, command=il_selected))
        rbs[-1].pack(anchor=W)




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
