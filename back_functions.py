import psutil
import win32api
import win32con
import win32security
import win32file
import os
import pefile
import ctypes
from ctypes import wintypes
from ctypes import cdll
import ntsecuritycon

def ChangeIntegrity(pid, level):
    lib = cdll.LoadLibrary("./ProcInfo.dll")
    s = level.encode('utf-8')
    level_buf = ctypes.c_char_p(s)
    if lib.ChangeIntegrityLevel(pid,level_buf):
        print("Integrity has changed!")
        res = 'done'
    else:
        print("Integrity hasn't changed")
        res = 'not done'
    return res
    
def GetUserSID(pid):
    try:
        username = psutil.Process(pid).username()#получаю имя пользователя процесса
        #функция возвращает кортеж с SID, Domain и тип аккаунта: пользователь/группа/...
        sid, domain, account_type = win32security.LookupAccountName(None,username)
        sid_str = win32security.ConvertSidToStringSid(sid)
        return sid_str
    except win32security.error as e:
        print("Ошибка: ",e)
        return None 
        
def ChangeDACL(file_path, trustee_name, access_rights):
    # Получаем текущий DACL
    security_descriptor = win32security.GetFileSecurity(
        file_path,
        win32security.DACL_SECURITY_INFORMATION
    )
    dacl = security_descriptor.GetSecurityDescriptorDacl()

    # Создаем новый ACE (Access Control Entry)
    trustee = win32security.LookupAccountName(None, trustee_name)[0]
    
    # Добавляем новый ACE в DACL
    dacl.AddAccessAllowedAce(access_rights,trustee)
    # Обновляем DACL
    dacl.DeleteAce(0)
    security_descriptor.SetSecurityDescriptorDacl(1, dacl, 0)
    win32security.SetFileSecurity(file_path, win32security.DACL_SECURITY_INFORMATION, security_descriptor)


def GetDACL(file_path):
    try:
        dacl_list = [] 
        if(len(file_path) != 0):
            #Получаю дескриптор процесса с информацией о DACL
            security_descriptor = win32security.GetFileSecurity(file_path, win32security.DACL_SECURITY_INFORMATION)
            # Получаю указатель на DACL
            dacl = security_descriptor.GetSecurityDescriptorDacl()
            for i in range(dacl.GetAceCount()):
                ace = dacl.GetAce(i)
                trustee = ace[2]
                trustee_name, domain, _type = win32security.LookupAccountSid(None, trustee)
                mask = ace[1]

                dacl_list.append(f"{trustee_name} ({domain}): {mask}")
        return dacl_list
    except pefile.PEFormatError as e:
        print("Ошибка при получении атрибутов файла: ", e)
    except win32security.error as e:
        print("Ошибка при получении атрибутов файла: ", e)
    return None
#______________________________________________________________________________________________

def GetIntegrity(pid):
    lib = cdll.LoadLibrary("./ProcInfo.dll")
    int_level_buf = ctypes.create_string_buffer(b'size for buf')
    lib.GetIntegrityLevel(pid, int_level_buf)
    int_level_string = ctypes.string_at(int_level_buf)
    int_level_string = int_level_string.rstrip(b'\0').decode('utf-8')

    if int_level_string:
        return int_level_string
    else:
        return None
#______________________________________________________________________________________________

def GetInfoAboutASLR(pid):
    lib = cdll.LoadLibrary("./ProcInfo.dll")
    result = lib.IsASLR(pid)
    if result == True:
        return 'ASLR'
    else:
        return None
#______________________________________________________________________________________________

def GetInfoAboutDEP(pid):
    kernel32 = ctypes.WinDLL('kernel32')

    #PROCESS_QUERY_INFORMATION (0x0400): Required to retrieve certain information about a process
    #PROCESS_VM_READ (0x0010): Required to read memory from a process using ReadProcessMemory.
    process_handle = kernel32.OpenProcess(0x0400 | 0x0010, False, pid)
    if process_handle == 0:
        return None
    dep_enabled = wintypes.DWORD()
    permanent =  wintypes.BOOL()
    success = kernel32.GetProcessDEPPolicy(process_handle, ctypes.byref(dep_enabled), ctypes.byref(permanent))
    kernel32.CloseHandle(process_handle)
    if success == 0:
        return None
    elif((dep_enabled.value > 0 )& (permanent.value == 0)):
        return 'DEP'
    elif((dep_enabled.value > 0) & (permanent.value == 1)):
        return 'DEP (permanent)'
    return None
#______________________________________________________________________________________________

def GetDlls(pid):
    try:
        dll_list = []
        proc = psutil.Process(pid)
        file_path = proc.exe()
        if(len(file_path) != 0):
            if (os.path.exists(file_path)) & (os.path.splitext(file_path)[1] == '.exe'):
                pe = pefile.PE(file_path)
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_list.append(entry.dll.decode('utf-8'))
        return dll_list
    except pefile.PEFormatError as e:
        print("Ошибка при получении атрибутов файла: ", e)
    except win32api.error as e:
        print("Ошибка при получении атрибутов файла: ", e)
    return None
#______________________________________________________________________________________________
def GetParentName(proc):
    try:
        parent_name = None
        if(proc.parent() != None):
            parent_name = proc.parent().name()
        return parent_name
    except win32api.error as e:
        print("Ошибка при получении атрибутов файла: ", e)
    return None
#______________________________________________________________________________________________
def GetFileDescription(file_path):
    if (os.path.exists(file_path)) & (os.path.splitext(file_path)[1] == '.exe'):
        try:
            language, codepage = win32api.GetFileVersionInfo(file_path, '\\VarFileInfo\\Translation')[0]
            # %04X - шестнадцатеричное представление целых чисел
            # 04 - минимальное еоличество символов для представления числа
            # X означает, что буквы в верхнем регистре
            # u - unicode
            stringFileInfo = u'\\StringFileInfo\\%04X%04X\\%s' % (language, codepage, "FileDescription")
            return win32api.GetFileVersionInfo(file_path, stringFileInfo)
        except win32api.error as e:
            print("Ошибка при получении атрибутов файла: ", e)

    return None
#______________________________________________________________________________________________
def GetProcessBits(proc):
    try:
        if (len(proc.exe()) != 0):
            file_path = proc.exe()
            if (os.path.exists(file_path)) & (os.path.splitext(file_path)[1] == '.exe'):
                proc_type = win32file.GetBinaryType(file_path)
                if proc_type == win32file.SCS_32BIT_BINARY:
                    return 32
                else:
                    return 64
    except win32api.error as e:
            print('Ошибка при получении атрибутов файла:',e)
    return None
#______________________________________________________________________________________________
# attributes, the receipt of which is realized
def SplitIntoToLists(attribute_list):
    add_atr_list = []
    for attr in attribute_list:
        match attr:
            case 'bits'|'description'|'pname'|'DEP'|'ASLR'|'integrity'|'DACL'|'UserSID':
                add_atr_list.append(attr)
    for attr in add_atr_list:
        attribute_list.remove(attr)


    return attribute_list, add_atr_list

#______________________________________________________________________________________________
def GetAdditionalInforamtion(proc, add_attr_list):
    add_proc_info = {} #additional information
    for attr in add_attr_list:
        match attr:
            case 'bits':
                bits = {'bits': GetProcessBits(proc)}
                add_proc_info.update(bits)

            case 'description':
                description = {'description': None}
                if (proc.exe() != None):
                    description['description'] = GetFileDescription(proc.exe())
                add_proc_info.update(description)

            case 'pname':
                parent_name = {'pname':GetParentName(proc)}
                add_proc_info.update(parent_name)

            case 'DEP':
                dep = {'DEP':GetInfoAboutDEP(proc.pid)}
                add_proc_info.update(dep)

            case 'ASLR':
                aslr = {'ASLR':GetInfoAboutASLR(proc.pid)}
                add_proc_info.update(aslr)

            case 'integrity':
                integrity = {'integrity':GetIntegrity(proc.pid)}
                add_proc_info.update(integrity)

            case 'DACL':
                GetDACL(proc.exe())
            case 'UserSID':
                user_sid = {'UserSID':GetUserSID(proc.pid)}
                add_proc_info.update(user_sid)

    return add_proc_info

#______________________________________________________________________________________________
def GetProcessesAttributes(attr_list):
    attr_list_copy = attr_list.copy()
    processes_attributes = []

    attr_list_copy, add_attr_list = SplitIntoToLists(attr_list_copy)

    for proc in psutil.process_iter():  # in the list of processes
        try:
            proc_info = proc.as_dict(attrs=attr_list_copy)

            #добавляем аттрибуты, для которых реализованы отдельные функции
            try:
                proc_info.update(GetAdditionalInforamtion(proc, add_attr_list))
            except psutil.AccessDenied as e:
                print('Ошибка:', e)
                empt_attr_dict =  {key: None for key in add_attr_list}
                proc_info.update(empt_attr_dict)

            processes_attributes.append(proc_info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            print('Ошибка: ',e)
    return processes_attributes

def GetProcessAttributes(attrr_list, pid:int):
    attr_list_copy = attrr_list.copy()
    process_attributes = []
    process = psutil.Process(pid)

    attr_list_copy, add_attr_list = SplitIntoToLists(attr_list_copy)
    try:
            proc_info = process.as_dict(attrs=attr_list_copy)

            #добавляем аттрибуты, для которых реализованы отдельные функции
            try:
                proc_info.update(GetAdditionalInforamtion(process, add_attr_list))
            except psutil.AccessDenied as e:
                print('Ошибка:', e)
                empt_attr_dict =  {key: None for key in add_attr_list}
                proc_info.update(empt_attr_dict)

            process_attributes.append(proc_info)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
        print('Ошибка: ',e)
    return process_attributes