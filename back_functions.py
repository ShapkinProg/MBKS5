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
