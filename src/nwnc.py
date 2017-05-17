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
__version__ = '0.1.dev5'

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
import os
import platform
import re
import subprocess
import tempfile
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse
try:
    from urllib.request import urlretrieve
except ImportError:
    from urllib import urlretrieve  # Python 2


# Affected Windows versions.  Grouped by the KB updates to fix them.
OsVersions = namedtuple('OsVersions',    
                        ['xp',             # Windows XP
                         'xpe',            # Windows XP Embedded
                         'xpwes09_pos09',  # Windows XP Embedded; WES09 & POSReady 2009
                         's2003',          # Windows Server 2003 (& Windows XP x64)
                         'vista_s2008',    # Windows Vista & Windows Server 2008
                         'win7_2008r2',    # Windows 7 & Windows Server 2008 R2
                         'win8',           # Windows 8
                         'wine8s_s2012',   # Windows Embedded 8 Standard & Windows Server 2012
                         'win81_s2012r2',  # Windows 8.1 & Windows Server 2012 R2
                         'win10_s2016'])   # Windows 10 & Windows Server 2016


# (Major, Minor, predicate) version numbers of Windows systems and a
# check to distinguish between Windows 8 and Server 2012
#
# Note: Windows XP x64 has version 5.2 like Windows Server 2003 (s2003)
#       and also uses the same patch. 
OS_ID = OsVersions(
    (5, 1, lambda: True),  # xp
    (5, 1, lambda: False),  # xpe; TODO: not yet supported
    (5, 1, lambda: False),  # xpwes09_pos09; TODO: not yet supported
    (5, 2),  # s2003
    (6, 0),  # vista_s2008
    (6, 1),  # win7_2008r2
    (6, 2, lambda: platform.uname()[2] == '8'),  # win8  TODO: win8 vs. wine8s
    (6, 2, lambda: platform.uname()[2] != '8'),  # s2012  TODO: win8 vs. wine8s
    (6, 3),  # win81_s2012r2
    (10, 0)  # win10_s2016 
)


# Systems with multiple applicable KBs only need one of them to not be
# vulnerable.
REQUIRED_KB = OsVersions(
    ['KB4012598'],  # xp
    ['KB4012598'],  # xpe
    ['KB4012598'],  # xpwes09_pos09
    ['KB4012598'],  # s2003    
    ['KB4012598'],  # vista_s2008
    ['KB4012212', 'KB4012215'],  # win7_2008r2
    ['KB4012598'],  # win8
    ['KB4012214', 'KB4012217'],  # s2012
    ['KB4012213', 'KB4012216'],  # win81_s2012r2
    ['KB4012606', 'KB4013198', 'KB4013429', 'KB4015438',  # win10_s2016
     'KB4016635', 'KB4015217', 'KB4019472']
)


KB_DOWNLOAD = OsVersions(
    {  # xp:
        'x86': 'http://download.windowsupdate.com/d/csa/csa/secu/2017/02/windowsxp-kb4012598-x86-custom-enu_eceb7d5023bbb23c0dc633e46b9c2f14fa6ee9dd.exe',
    },
    {  # xpe:
        'x86': 'http://download.windowsupdate.com/c/csa/csa/secu/2017/02/windowsxp-kb4012598-x86-embedded-custom-enu_8f2c266f83a7e1b100ddb9acd4a6a3ab5ecd4059.exe',
    },
    {  # xpwes09_pos09:
        'x86': 'http://download.windowsupdate.com/d/msdownload/update/software/secu/2017/02/windowsxp-kb4012598-x86-embedded-enu_9515c11bc77e39695b83cb6f0e41119387580e30.exe',
    },
    {  # s2003
        'x86': 'http://download.windowsupdate.com/c/csa/csa/secu/2017/02/windowsserver2003-kb4012598-x86-custom-enu_f617caf6e7ee6f43abe4b386cb1d26b3318693cf.exe',
        'x64': 'http://download.windowsupdate.com/d/csa/csa/secu/2017/02/windowsserver2003-kb4012598-x64-custom-enu_f24d8723f246145524b9030e4752c96430981211.exe',
    },
    {  # vista_s2008:
        'x86': 'http://download.windowsupdate.com/d/msdownload/update/software/secu/2017/02/windows6.0-kb4012598-x86_13e9b3d77ba5599764c296075a796c16a85c745c.msu',
        'x64': 'http://download.windowsupdate.com/d/msdownload/update/software/secu/2017/02/windows6.0-kb4012598-x64_6a186ba2b2b98b2144b50f88baf33a5fa53b5d76.msu',
        'ia64': 'http://download.windowsupdate.com/d/msdownload/update/software/secu/2017/02/windows6.0-kb4012598-ia64_83a6f5a70588b27623b11c42f1c8124a25d489de.msu',
    },
    {  # win7_2008r2
        'x86': 'http://download.windowsupdate.com/d/msdownload/update/software/secu/2017/02/windows6.1-kb4012212-x86_6bb04d3971bb58ae4bac44219e7169812914df3f.msu',
        'x64': 'http://download.windowsupdate.com/d/msdownload/update/software/secu/2017/02/windows6.1-kb4012212-x64_2decefaa02e2058dcd965702509a992d8c4e92b3.msu',
        'ia64': 'http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/02/windows6.1-kb4012212-ia64_93a42b16dbea87fa04e2b527676a499f9fbba554.msu',
    },
    {  # win8
        'x86': 'http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/05/windows8-rt-kb4012598-x86_a0f1c953a24dd042acc540c59b339f55fb18f594.msu',
        'x64': 'http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/05/windows8-rt-kb4012598-x64_f05841d2e94197c2dca4457f1b895e8f632b7f8e.msu',
    },
    {  # s2012
        'x86': 'http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/02/windows8-rt-kb4012214-x86_5e7e78f67d65838d198aa881a87a31345952d78e.msu',
        'x64': 'http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/02/windows8-rt-kb4012214-x64_b14951d29cb4fd880948f5204d54721e64c9942b.msu',
    },
    {  # win81_s2012r2
        'x86': 'http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/02/windows8.1-kb4012213-x86_e118939b397bc983971c88d9c9ecc8cbec471b05.msu',
        'x64': 'http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/02/windows8.1-kb4012213-x64_5b24b9ca5a123a844ed793e0f2be974148520349.msu',
    },
    {  # win10_s2016
        # TODO: KBs of Windows 10 / Windows Server 2016 are cumulative,
        #       not yet clear if this particular fix can even be
        #        installed indiviudally, or if the only solution is:
        #       "be up-to-date"
    },
)


# in case we're running Python 2:
if 'raw_input' in dir(__builtins__):
    input = raw_input  # @UndefinedVariable @ReservedAssignment


def os_id_index():
    """Get the index of the machine OS in the `OS_ID` tuple.
    
    The `OS_ID` tuple contains the major and minor version of all
    affected Windows versions.  These are matched against
    the major and minor version of `sys.getwindowsversion()`.
    
    For Windows 8.1 and above `sys.getwindowsversion()` doesn't
    report the correct value, these systems are handled specially. 
    
    Windows 8 and Server 2012 are special cased because the have the
    same version numbers but require different KBs.
    
    :return: The index of the operating system in `OS_ID`.
    :rtype: int
    """
    winver = sys.getwindowsversion()
    # sys.getwindowsversion is not enough by itself as the underlying
    # API has been deprecated.  Only applications which have been
    # developed specifically for Windows 8.1 and above, and write that
    # into their manifest file get the correct Windows version on those
    # systems.  Other applications (Python doesn't have the manifest)
    # get a version that pretends to be Windows 8 (major=6, minor=2).
    # See:
    # https://msdn.microsoft.com/en-us/library/windows/desktop/ms724834.aspx
    major, minor = winver.major, winver.minor
    if (major, minor) == (6, 2):
        # Determine if this system is a newer version than Windows 8 by
        # parsing the version string in `platform.win32_ver()[1]`:
        major, minor = tuple(map(int, platform.win32_ver()[1].split('.')[:2]))
    for i, os_id in enumerate(OS_ID):
        if os_id[:2] == (major, minor):
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
    stdout, stderr = proc.communicate()
    proc_info = ProcessInfo(proc.returncode, _decode(stdout), _decode(stderr))
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


def _is_powershell_cmdlet_available(cmdlet):
    """Check whether a PowerShell Cmdlet exists on this machine.
    
    :return: ``True`` if the Cmdlet is available; otherwise, ``False``.
    :rtype: bool
    """
    cmd = ['PowerShell', '-Command',
           'Write-Host',
           '$([bool](Get-Command ' + cmdlet + ' -ErrorAction SilentlyContinue))']
    proc_info = run(cmd)
    return proc_info.stdout.strip().lower() == 'true'
    

def can_check_smb_v1():
    """Check whether this machine has the Cmdlet to query SMBv1 status.
    
    The PowerShell Cmdlet ``Get-SmbServerConfiguration`` required to
    check the SMBv1 protocol status is not available by default on all
    machines.  Find out if it's present on this one.
    
    :return: ``True`` if the Cmdlet is available; otherwise, ``False``.
    :rtype: bool
    """
    return _is_powershell_cmdlet_available('Get-SmbServerConfiguration')


def check_smb_v1_powershell():
    """Check through a Cmdlet if the SMBv1 protocol is disabled.
    
    Requires that the PowerShell Cmdlet ``SmbServerConfiguration``
    exists, i.e. `can_check_smb_v1()` returns ``True``.
    
    See:
    https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
    
    :return: ``True`` if SMBv1 is disabled; otherwise, ``False``.
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
    return proc_info.stdout.split()[2].strip().lower() == 'false'


def check_smb_v1_registry():
    """Query the registry to check if the SMBv1 protocol is disabled.
    
    :return: ``True`` if SMBv1 is disabled; otherwise, ``False``.
    :rtype: bool
    """
    cmd = ['PowerShell', '-Command',
           'Get-ItemProperty'
           ' -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"'
           ' | Select SMB1']
    
    proc_info = run(cmd)
    # third line contains the value, which should be '0' or '1', or ''
    # if the key doesn't exist.  If the key is missing SMBv1 is active
    # by default.
    result = proc_info.stdout.split()
    if len(result) >= 3:
        enabled = bool(int(result[2].strip()))
    else:
        enabled = True  # True by default
    return not enabled


def check_smb_v1():
    """Check if the SMBv1 protocol is disabled.
    
    The security hole exploited by WCry is in the SMBv1 protocol.  If 
    it's enabled and no update with a fix is installed, then the system
    is vulnerable.
    
    :return: ``True`` if SMBv1 is disabled; otherwise, ``False``.
    :rtype: bool
    """
    print('Checking if the SMB v1 protocol is disabled...')
    if can_check_smb_v1():
        return check_smb_v1_powershell()
    # else:
    return check_smb_v1_registry()


def can_set_smb_v1():
    """Check whether this machine has the Cmdlet to change SMBv1.
    
    The PowerShell Cmdlet ``Set-SmbServerConfiguration`` required to
    enable/disable the SMBv1 protocol is not available by default on all
    machines.  Find out if it's present on this one.
    
    :return: ``True`` if the Cmdlet is available; otherwise, ``False``.
    :rtype: bool
    """
    return _is_powershell_cmdlet_available('Set-SmbServerConfiguration')


def set_smb_v1_powershell(enable):
    """Enable or disable the SMBv1 protocol through a Cmdlet.
    
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


def set_smb_v1_registry(enable):
    """Enable or disable the SMBv1 protocol through the registry.
    
    This requires admin privileges.  If run without, exits the script
    with return code 1.
    
    :param bool enable: Whether to enable or disable the protocol.
    """
    enable = '1' if enable else '0'
    cmd = ['PowerShell', '-Command',
           'Set-ItemProperty',
           '-Path', 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
           'SMB1', '-Type', 'DWORD', '-Value', enable, '-Force']
    proc_info = run(cmd)
    if proc_info.stderr:
        print()
        sys.stderr.write('Error:' + proc_info.stderr)
        sys.exit(1)
    # else:
    print(proc_info.stdout)


def set_smb_v1(enable):
    """Enable or disable the SMBv1 protocol.
    
    This requires admin privileges.  If run without, exits the script
    with return code 1.

    :param bool enable: Whether to enable or disable the protocol.
    """
    if can_set_smb_v1():
        set_smb_v1_powershell(enable)
    else:
        set_smb_v1_registry(enable)
    if not enable:
        print('The SMBv1 protocol has been disabled.'
              ' The system is no longer vulnerable.')
    else:
        print('The SMBv1 protocol has been enabled.'
              'This can make the system vulnerable, if the security hole is unpatched.')


def _get_system_root():
    """Try to get the %SystemRoot% path from the environment.
    
    The %SystemRoot% should be an environment variable holding the path
    to the Windows installation directory.
    
    Default to 'C:\\Windows'.
    
    :return: The %SystemRoot% path string.
    :rtype: str
    """
    if sys.version_info[0] == 2:
        return _decode(os.environ.get('SystemRoot', b'C:\\Windows'))
    # else:
    return os.environ.get('SystemRoot', 'C:\\Windows')


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
            # alternative approach: only admin users can read %SystemRoot%\temp
            os.listdir(os.path.join([_get_system_root(),'temp']))
            return True
        except PermissionError:
            return False
        except:
            return False  # safeguard, may want to expand on this later


def run_as_admin(extra_args=None):
    """If required, rerun the script and request admin privileges.
    
    :params iterable extra_args:
        Additional arguments to pass to the script in case it has to be
        restarted.
    """
    if not am_admin():
        try:
            print('Restarting and requesting admin privileges.')
            args = sys.argv
            if extra_args:
                args = args + extra_args
            exe, args = sys.executable, ' '.join(args)
            if sys.version_info[0] == 2:
                exe = _decode(exe)
            ctypes.windll.shell32.ShellExecuteW(None, 'Runas', exe, args, None, 1)
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


def _get_os_arch():
    """TODO: doc; find out what to do on an ia64 system; test it"""
    return 'x64' if platform.machine().endswith('64') else 'x86'


def fix(download_directory=None):
    """Fix the SMBv1 security hole by installing a Windows KB update.
    
    This tries to automatically find, download and install the right
    update for your system.
    
    `fix()` implies running a `check()`.
    
    In case this doesn't work, try to run the mitigate command and
    install the appropriate update youself. Have a look at the
    `KB_DOWNLOAD` tuple at the top of the script to hopefully find
    the right update.
    
    :param str download_directory:
        Optionally specify a directory where the KB update is saved.
    """
    if check():
        sys.exit()  # system isn't vulnerable
    # else:
    if os_id_field_name() == 'win10_s2016':
        # this script currently doesn't handle Windows 10 / Server 2016
        sys.exit('Downloading and installing an update for Windows 10 or'
                 ' Windows Server 2016 is currently not supported.'
                 ' Please enable automatic updates instead.')
    # else:
    print('Trying to get an update for your system...')
    kb_download_url = KB_DOWNLOAD[os_id_index()][_get_os_arch()]
    # Use the same file name as on the Microsoft server, i.e. the last
    # part of the URL path is the file name:
    kb_file_name = urlparse(kb_download_url).path.split('/')[-1]
    if not download_directory:
        download_directory = tempfile.gettempdir()
    kb_absolute_path = os.path.join(download_directory, kb_file_name)
    
    # Download the KB update only if it doesn't already exist in the
    # download directory.  The script may have been restarted to get
    # admin privileges, so the file could already be there.
    if not os.path.exists(kb_absolute_path):
        try:
            urlretrieve(kb_download_url, kb_absolute_path)
            print("The KB update has been downloaded to: " + kb_absolute_path)
        except Exception as e:
            sys.stderr.write('Error:' + e)
            sys.exit('Unable to download the KB update for your system.')
    
    # install the update:
    if kb_file_name.endswith('.exe'):
        # if it's an .exe then run it directly:
        proc_info = run([kb_absolute_path])
    elif kb_file_name.endswith('.msu'):
        run_as_admin(['--download-directory', download_directory])
        inst_exe = os.path.join(_get_system_root(), 'system32', 'wusa.exe')
        if not os.path.exists(inst_exe):
            # TODO: are there systems where wusa.exe isn't present?
            sys.exit("Windows Update Standalone Installer not found."
                     " You will have to find a way to install the file"
                     " '{}' manually".format(kb_absolute_path))
        # else:
        proc_info = run([inst_exe, kb_absolute_path])
    if proc_info.stderr:
        sys.stderr.write(proc_info)
    print(proc_info.stdout)


def cli_args():
    """Parse the command line arguments.
    
    :return: The parsed arguments.
    :rtype: argparse.Namespace
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--check', action='store_true',
                        help="check if the system is vulnerable to WCry")
    parser.add_argument('-m', '--mitigate', action='store_true',
                        help="mitigate the system's vulnerability by disabling the"
                             " SMBv1 protocol, if necessary; implies --check")
    parser.add_argument('-f', '--fix', action='store_true')
    parser.add_argument('--download-directory',
                        help="Optionally specify a directory where the Microsoft"
                             " KB update is saved when using --fix")
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    # else:
    return parser.parse_args()


def main():
    """Main entry point for the NoWannaNoCry script."""
    try:
        args = cli_args()
        
        if args.check and not args.mitigate and not args.fix:
            check()
        elif args.mitigate:
            mitigate()
        elif args.fix:
            fix(args.download_directory)

        input('\r\nDone. Press any key to exit.')
    except Exception as e:
        sys.exit(e)


if __name__ == '__main__':
    main()
