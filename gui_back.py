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

# returns acl for file
def get_acl(filepath):
    acl = back_funcs.GetDACL(filepath)
    res = {}
    for ace in acl:
        split_res = ace.split(": ")
        obj_perm = {}
        keys = permissions_masks.keys()
        for key in keys:
            if int(split_res[1]) & permissions_masks[key] == permissions_masks[key]:
                obj_perm[key] = 1
            else:
                obj_perm[key] = 0

        # get deny or allow status, add to name of user and delete from permissions list
        if (obj_perm['Allow/Deny'] == 0):
            allow_or_deny = "(deny)"
        else:
            allow_or_deny = "(allow)"
        obj_perm.pop('Allow/Deny')

        res[split_res[0]+":"+allow_or_deny] = obj_perm
    return res


# changes subject acl
def change_subject_acl(filepath, new_subject_ace, old_permissions):
    # get parameters for ChangeDACL()
    subj_name = new_subject_ace['id'].split(":")[0]
    subj_name = subj_name.split(" (")[0]
    allow_or_deny = new_subject_ace['id'].split(":")[1]
    if allow_or_deny == '(deny)':
        is_deny = True
    else:
        is_deny = False

    # for perm in old_permissions.keys():
    #     # if permission is changed
    #     if(old_permissions[perm] != new_subject_ace['permissions'][perm]):
    #         perm_mask = permissions_masks[perm]
    #         if new_subject_ace['permissions'][perm] == 0:
    #             is_delete = True
    #         else:
    #             is_delete = False
    #         back_funcs.ChangeDACL(filepath, subj_name, perm_mask, is_delete, is_deny)

    perm_mask = 0
    for perm in new_subject_ace['permissions'].keys():
        if new_subject_ace['permissions'][perm] == 1:
            perm_mask |= permissions_masks[perm]

    if (is_deny == False): perm_mask |= 0x100000
    back_funcs.ChangeDACL(filepath, subj_name, perm_mask)
