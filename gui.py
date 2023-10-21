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


def fill_frame_processes(frm_processes):
    sht_processes = tksheet.Sheet(frm_processes,
                                  headers=["PID", "Name", "Description", "Exe path", "Parent id",
                                           "Parent name", "Owner name", "Owner SID", "Arch type",
                                           "DEP", "ASLR"])
    sht_processes.pack(expand=True, fill='both')
    sht_processes.enable_bindings(("single_select",
                                   "row_select",
                                   "column_select",
                                   "column_width_resize",
                                   "arrowkeys",
                                   "right_click_popup_menu",
                                   "rc_select",
                                   "copy",
                                   ))

    # Fill processes sheet
    procs_info = gui_back.get_processes_info()
    keys = list(procs_info[0].keys())
    sht_processes.set_sheet_data([[proc_info[key] for key in keys] for proc_info in procs_info])

    # sht_processes.set_sheet_data([[f"{ri * cj}" for cj in range(50)] for ri in range(50)])

    # Right click dll
    def right_click_dll():
        selected = sht_processes.get_currently_selected()
        row_data = sht_processes.get_row_data(selected.row)
        pid = row_data[0]
        open_ddls_window(int(pid))
        # print(row_data)

    # Right click environment
    def right_click_env():
        selected = sht_processes.get_currently_selected()
        row_data = sht_processes.get_row_data(selected.row)
        pid = row_data[0]
        open_env_window(pid)
        # print(row_data)

    # Right click integrity level
    def right_click_integ_lvl():
        selected = sht_processes.get_currently_selected()
        row_data = sht_processes.get_row_data(selected.row)
        pid = row_data[0]
        open_integlvl_window(pid)
        # print(row_data)

    # Add commands in right click popup menu
    sht_processes.popup_menu_add_command(label="Dlls",
                                         func=right_click_dll,
                                         header_menu=False)

    sht_processes.popup_menu_add_command(label="Environment",
                                         func=right_click_env,
                                         header_menu=False)

    sht_processes.popup_menu_add_command(label="Integrity level",
                                         func=right_click_integ_lvl,
                                         header_menu=False)


def fill_frame_file(frm_file):
    lbl_choose_file = ttk.Label(frm_file, text="Choose file ")
    lbl_choose_file.pack(side=TOP, pady=10)

    filepath = None

    # open subject acl window
    def open_subject_acl_wndw(subject):
        wndw_acl_subj = Toplevel()
        wndw_acl_subj.title("ACL")
        wndw_acl_subj.geometry("500x500")
        wndw_acl_subj.grab_set()

        chkbtns = []

        # what to do when checkbutton is clicked
        def on_click(chkbtn_name):
            # get state of 'Full' permission button
            full_btn_state = chkbtns[0]['state'].get()
            # if clicked button is not 'Full' button
            if chkbtn_name != 'Full':
                if full_btn_state == 1:
                    # if full button checked and we remove some permission, uncheck 'Full' button
                    chkbtns[0]['state'].set(0)
            # if clicked button is 'Full' button
            else:
                # set all buttons to checked or unchecked state, depending on state of 'Full' button
                for chkbtn in chkbtns:
                    chkbtn['state'].set(full_btn_state)

        def create_command(chkbtn_name):
            return lambda: on_click(chkbtn_name)

        # create checkbuttons
        for chkbtn_name in subject['permissions'].keys():
            chkbtn_state = IntVar()
            chkbtn_state.set(subject['permissions'][chkbtn_name])
            chkbtn = ttk.Checkbutton(wndw_acl_subj, text=chkbtn_name, variable=chkbtn_state,
                                     command=create_command(chkbtn_name))
            chkbtns.append({"chkbtn": chkbtn, "state": chkbtn_state})
            chkbtn.pack(side=TOP, pady=5)

        # actions when apply button is clicked
        def apply_btn_on_click():
            # save old_permissions
            old_permissions = subject['permissions'].copy()
            # set permissions according to checkbuttons states
            for key, chkbtn in zip(subject['permissions'].keys(), chkbtns):
                subject['permissions'][key] = chkbtn['state'].get()
            # change acl
            gui_back.change_subject_acl(filepath, subject, old_permissions)
            # close window of subject acl
            wndw_acl_subj.destroy()

        # create apply button
        apply_btn = ttk.Button(wndw_acl_subj, text='Apply', command=lambda: apply_btn_on_click())
        apply_btn.pack(side=TOP, pady=10)

    def open_file_acl_wndw():
        # open file
        nonlocal filepath
        filepath = askopenfilename()
        if filepath is not None:
            # get acl
            acl = gui_back.get_acl(filepath)
            # create window
            wndw_acl = Toplevel()
            wndw_acl.title("ACL")
            wndw_acl.geometry("500x500")
            wndw_acl.grab_set()
            lbl1_wndw_acl = ttk.Label(wndw_acl, text="File: " + os.path.abspath(filepath))
            lbl1_wndw_acl.pack(side=TOP, pady=10)

            def create_command(key):
                return lambda: open_subject_acl_wndw({"id": key, "permissions": acl[key]})

            # create buttons of subjects
            btns_subjects = []
            for key in acl.keys():
                btns_subjects.append(ttk.Button(wndw_acl, text=key, command=create_command(key)))
                btns_subjects[-1].pack(side=TOP, pady=10)

    # create open file button
    btn = ttk.Button(frm_file, text='Open file', command=lambda: open_file_acl_wndw())
    btn.pack(side=TOP, pady=10)


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
    fill_frame_processes(frm_processes)

    # Fill file frame
    fill_frame_file(frm_file)

    # Main loop
    wndw_root.mainloop()

# main function
start_interface()
