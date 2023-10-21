# Author: David Colonel
# Date: April 30, 2023
# Description: Backend functions required for GUI (gui.py)

import back_functions as back_funcs

permissions_masks = {
    'Full': 0xF01FF,
    'Files execution/folder traverse': 0x20,
    'Folder content/read data': 0x1,
    'Read attributes': 0x80,
    'Read additional attributes': 0x8,
    'Create files/modify data': 0x2,
    'Create folder/add data': 0x4,
    'Write attribultes': 0x100,
    'Write additional attributes': 0x10,
    'Delete': 0x10000,
    'Read permissions': 0x20000,
    'Change permissions': 0x40000,
    'Change ownership': 0x80000,
    'Allow/Deny': 0x100000
}


# returns the list of dlls for process with passed pid
def get_list_of_dlls(pid):
    return back_funcs.GetDlls(pid)


# returns information about processes
def get_processes_info():
    attr_list = ['pid', 'name', 'description', 'exe', 'ppid', 'pname', 'username', 'UserSID', 'bits', 'DEP',
                 'ASLR']
    processes_info = back_funcs.GetProcessesAttributes(attr_list)
    processes_info_sorted = []
    for proc in processes_info:
        processes_info_sorted.append({key: proc[key] for key in attr_list})
    return processes_info_sorted


# returns environment variables for process with passed pid
def get_list_of_env_vars(pid):
    processes_info = back_funcs.GetProcessesAttributes(['pid', 'environ'])
    desired_proc = next((item for item in processes_info if item["pid"] == int(pid)))
    return desired_proc['environ']


# returns integrity level of process with passed pid
def get_integrity_level(pid):
    return back_funcs.GetIntegrity(pid)


# sets integrity level to new_level for process with passed pid
def set_integrity_level(pid, new_level):
    res = back_funcs.ChangeIntegrity(int(pid), new_level)
    return res
