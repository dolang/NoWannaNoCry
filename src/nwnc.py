# -*- coding: utf-8 -*-
"""
nwnc.py - NoWannaNoCry.  A script to help mitigate against WCry__.

It uses Windows system utilities and PowerShell Cmdlets to implement
its functionality.  These are bound to have different features or are
only available on certain platforms, therefore as I only have access to
a limited number of test systems, the script may not run as intended on
your machine.

__ https://en.wikipedia.org/wiki/WCry

:author: Dominik Lang
:date: 13.05.2017
:copyright: © 2017 dolang
:license: GPL v3
"""

from __future__ import print_function, unicode_literals

__author__ = 'Dominik Lang'
__copyright___ = 'Copyright (c) 2017 Dominik Lang'
__license___ = 'GPL v3'
__version__ = '0.1.dev2'

import sys
from collections import namedtuple
 
if sys.platform != 'win32':
    sys.exit('This script is meant to be run on a Windows machine.'
             ' Only Windows machines are vulnerable to WCry.')

if sys.getwindowsversion().platform != 2:
    sys.exit('Your Windows version is not supported by this script'
             ' (and probably not vulnerable).')

import argparse
import ctypes
from functools import partial
import platform
import re
import subprocess


OsVersions = namedtuple('OsVersions',
                        ['xp', 'vista_s2008', 'win7_2008r2', 'win8',
                        's2012', 'win81_s2012r2', 'win10_s2016'])


OS_ID = OsVersions(
    (5, 1),  # xp
    (6, 0),  # vista_s2008
    (6, 1),  # win7_2008r2
    (6, 2, lambda: platform.uname()[2] == '8'),  # win8
    (6, 2, lambda: platform.uname()[2] != '8'),  # s2012
    (6, 3),  # win81_s2012r2
    (10, 0)  # win10_s2016 
)


REQUIRED_KB = OsVersions(
    ['KB4012598'],  # xp
    ['KB4012598'],  # vista_s2008
    ['KB4012212', 'KB4012215'],  # win7_2008r2
    ['KB4012598'],  # win8
    ['KB4012214', 'KB4012217'],  # s2012
    ['KB4012213', 'KB4012216'],  # win81_s2012r2
    ['KB4012606', 'KB4013198', 'KB4013429', 'KB4015438',  # win10_s2016
     'KB4016635', 'KB4015217', 'KB4019472']
)


# in case we're running Python 2:
if 'raw_input' in dir(__builtins__):
    input = raw_input  # @UndefinedVariable @ReservedAssignment


def os_id_index():
    """Get the index of the machine OS in the `OS_ID` tuple.
    
    The `OS_ID` tuple contains the major and minor version of all
    affected Windows versions.  These are matched against
    the major and minor version of `sys.getwindowsversion()`.
    
    Windows 8 and Server 2012 are special cased because the have the
    same version numbers but require different KBs.
    
    :return: The index of the operating system in `OS_ID`.
    :rtype: int
    """
    winver = sys.getwindowsversion()
    for i, os_id in enumerate(OS_ID):
        if os_id[:2] == (winver.major, winver.minor):
            if len(os_id) == 2:
                return i
            # else evaluate the third item if present which is a lambda:
            if os_id[2]():
                return i
            # otherwise continue with the next item


def os_id_field_name():
    """Get the field name of the machine OS in `OS_ID`.
    
    Because `OS_ID` is a `namedtuple`, each entry has an associated
    name.  E.g. if your system is Windows 8.1, then "win81_s2012r2" is
    returned.
    
    :return: The field name of the operating system in `OS_ID`.
    :rtype: str
    """
    return OsVersions._fields[os_id_index()]


ProcessInfo = namedtuple('ProcessInfo', ['returncode', 'stdout', 'stderr'])


_decode = partial(bytes.decode, encoding='utf-8')


def run(popen_args):
    """Run a `subprocess.Popen()` command and block until completed.
    
    This is a simple wrapper around `subprocess.Popen()`, which is run
    with the given `popen_args`.  It waits until the command completes
    and returns a 3-tuple with return code and the contents both of
    output and error streams, converted to unicode strings.
    
    :param popen_args:
        A string or sequence of command arguments which are accepted
        as the `args` parameter of `subprocess.Popen()`.
    :return:
        A triplet with return code, output and error stream contents.
    :rtype: ProcessInfo
    """
    proc = subprocess.Popen(popen_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.wait()
    proc_info = ProcessInfo(
        proc.returncode, _decode(proc.stdout.read()), _decode(proc.stderr.read()))
    return proc_info


def _strip_to_kb(kb_string):
    """Get rid of additional information in the KB string.
    
    Some KB entries have an expanded string, e.g.
    'KB2712101_Microsoft-Windows-CameraCodec-Package'.
    Strip that down to 'KB2712101'.
    
    :param str kb_string: An unprocessed KB string.
    :return: The cleaned up KB string.
    :rtype: str
    """
    return re.match('KB\d+', kb_string).group()    


def list_kbs():
    """List the KB strings of all installed updates.
    
    KB stands for "Knowledge Base".  The Windows Update identifier
    strings are called that because the updates are associated with
    Knowledge Base articles and the strings themselves start with
    the prefix "KB".
    
    The first line of the executed command is the header "HotFixID" and
    is stripped from the result (through slicing ``...[1:]``).
    
    :return: A list of KB strings.
    :rtype: list(str)
    """
    cmd = ['wmic', 'qfe', 'get', 'hotfixid']
    
    proc_info = run(cmd)
    return [_strip_to_kb(s) for s in proc_info.stdout.split()[1:]]


def check_installed_kbs():
    """Check if one of updates required to prevent WCry is installed.
    
    :return:
        ``True`` if a required update is present; otherwise, ``False``.
    :rtype: bool
    """
    print('Checking if a KB with a fix is installed...', end=' ')
    required_kbs = REQUIRED_KB[os_id_index()]
    installed_kbs = list_kbs()
    
    def kb_found(required_one, all_installed):
        return required_one in all_installed
    
    fix_installed = any(kb_found(required_one, installed_kbs)
                        for required_one in required_kbs)
    print('yes' if fix_installed else 'no')
    return fix_installed


def can_check_smb_v1():
    """Check whether this machine has the Cmdlet to query SMBv1 status.
    
    The PowerShell Cmdlet ``Get-SmbServerConfiguration`` required to
    check the SMBv1 protocol status is not available by default on all
    machines.  Find out if it's present on this one.
    
    :return: ``True`` if the Cmdlet is available; otherwise, ``False``.
    :rtype: bool
    """
    cmd = ['PowerShell', '-Command',
           'Write-Host',
           '$([bool](Get-Command Get-SmbServerConfiguration' 
           ' -ErrorAction SilentlyContinue))']
    proc_info = run(cmd)
    return proc_info.stdout.strip().lower() == 'true'


def check_smb_v1_powershell():
    """Check if the SMBv1 protocol is enabled through a Cmdlet.
    
    Requires that the PowerShell Cmdlet ``SmbServerConfiguration``
    exists, i.e. `can_check_smb_v1()` returns ``True``.
    
    See:
    https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
    
    :return:
        ``True`` if the SMB v1 protocol is active; otherwise, ``False``.
    :rtype: bool
    """
    cmd = ['PowerShell', '-Command',
           'Get-SmbServerConfiguration | Select EnableSMB1Protocol']
    
    proc_info = run(cmd)
    if proc_info.stderr:
        sys.stderr.write('Error:\r\n' + proc_info.stderr)
        sys.exit(1)
    # else:
    print(proc_info.stdout)
    return False
    return proc_info.stdout.split()[2].strip().lower() == 'false'


def check_smb_v1_registry():
    """Query the registry to check if the SMBv1 protocol is enabled.
    
    :return:
        ``True`` if the SMB v1 protocol is active; otherwise, ``False``.
    :rtype: bool
    """
    cmd = ['PowerShell', '-Command',
           'Get-ItemProperty'
           ' -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"'
           ' | Select SMB1']
    
    proc_info = run(cmd)
    # third line contains the value, which should be '0' or '1', or ''
    # if the key doesn't exist.  In that case it's assumed that SMBv1
    # is active by default
    value = proc_info.stdout.split()[2].strip()  
    return True if value == '' else bool(int(value))


def check_smb_v1():
    """Check if the SMBv1 protocol is enabled.
    
    The security hole exploited by WCry is in the SMBv1 protocol.  If 
    it's enabled and no update with a fix is installed, then the system
    is vulnerable.
    
    :return:
        ``True`` if the SMB v1 protocol is active; otherwise, ``False``.
    :rtype: bool
    """
    print('Checking if the SMB v1 protocol is enabled...')
    if can_check_smb_v1():
        return check_smb_v1_powershell()
    # else:
    return check_smb_v1_registry()


def set_smb_v1(enable):  # TODO: this commandlet is only available on Windows 8 and above
    """Enable or disable the SMBv1 protocol.
    
    This requires admin privileges.  If run without, exits the script
    with return code 1.
    
    :param bool enable: Whether to enable or disable the protocol.
    """
    enable = '$true' if enable else '$false'
    cmd = ['PowerShell', '-Command',
           'Set-SmbServerConfiguration', '-EnableSMB1Protocol', enable,
           '-Confirm:$false']
    
    proc_info = run(cmd)
    if proc_info.stderr:
        print()
        sys.stderr.write('Error:' + proc_info.stderr)
        sys.exit(1)
    # else:
    print(proc_info.stdout)
    print('The SMBv1 protocol has been disabled. The system is no longer vulnerable.')
    

def am_admin():
    """Check if the logged-in user's account has admin privileges.
    
    If the user cannot be identified as an administrator, i.e. the
    system call fails, then this errs on the safe side and defaults
    to ``False``.
    
    :return: ``True`` if the user is an admin; otherwise, ``False``.
    :rtype: bool
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        try:
            import os
            # alternative approach: only admin users can read %SystemRoot%\temp
            os.listdir(os.sep.join([os.environ.get('SystemRoot','C:\\windows'),'temp']))
            return True
        except PermissionError:
            return False
        except:
            return False  # safeguard, may want to expand on this later


def run_as_admin():
    """If required, rerun the script and request admin privileges."""
    if not am_admin():
        try:
            print('Restarting and requesting admin privileges.')
            ctypes.windll.shell32.ShellExecuteW(
                None, 'Runas', sys.executable, ' '.join(sys.argv), None, 1)
            sys.exit()
        except Exception as e:
            print(e)
            msg = ('Unable to elevate privileges. You need to rerun the script'
                   ' with Administrator privileges yourself. E.g. try pressing'
                   ' the Windows key + x, then select "Command Prompt (Admin)"'
                   ' and run the script in that console.')
            sys.exit(msg)


def check():
    """Check if the system is vulnerable to the WCry malware.
    
    :return:
         ``True`` if the system is not vulnerable; otherwise, ``False``.
    :rtype: bool
    """
    fix_installed = check_installed_kbs()
    smb_v1_disabled = check_smb_v1()
    not_vulnerable = fix_installed or smb_v1_disabled
    print('The system is {}vulnerable.'.format('not ' if not_vulnerable else ''))
    return not_vulnerable


def mitigate():
    """Mitigate the WCry vulnerability by disabling SMBv1, if necessary.
    
    See:
    https://technet.microsoft.com/en-us/library/security/ms17-010.aspx#ID0E3SAG
    
    `mitigate()` implies running a `check()`.
    
    The system is checked for installed KBs to determine if disabling
    the SMBv1 protocol is necessary.
    
    Disabling the SMBv1 protocol requires admin privileges.
    """
    if check():
        sys.exit()  # system isn't vulnerable
    # else:
    print('Trying to turn off SMBv1, this may require a rerun with admin privileges...')
    run_as_admin()
    set_smb_v1(False)


def fix():
    """TODO: doc
    
    `fix()` implies running a `check()`.
    """
    raise NotImplementedError()  # TODO: download appropriate update & run setup


def cli_args():
    """Parse the command line arguments.
    
    :return: The parsed arguments.
    :rtype: argparse.Namespace
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--check', action='store_true')
    parser.add_argument('-m', '--mitigate', action='store_true')
#     parser.add_argument('-f', '--fix', action='store_true')  # not yet implemented
    return parser.parse_args()


def main():
    """Main entry point for the NoWannaNoCry script."""
    try:
        print(sys.executable)
        print(sys.argv)
        args = cli_args()
        if args.check and not args.mitigate:
            check()
        elif args.mitigate:
            mitigate()
        # TODO: implement & call fix()

        input('\r\nDone. Press any key to exit.')
    except Exception as e:
        sys.exit(e)


if __name__ == '__main__':
    main()
