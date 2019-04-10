using Microsoft.Win32;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;

namespace DefenderCheck
{
    class Program
    {
        static void Main(string[] args)
        {
            //Initial file parse
            string targetfile = args[0];
            string testfilepath = @"C:\Temp\testfile.exe";
            byte[] originalfilecontents = File.ReadAllBytes(targetfile);
            int originalfilesize = originalfilecontents.Length;
            Console.WriteLine("Target file size: {0} bytes", originalfilecontents.Length);
            Console.WriteLine("Analyzing...\n");

            byte[] splitarray1 = new byte[originalfilesize/2];
            Buffer.BlockCopy(originalfilecontents, 0, splitarray1, 0, originalfilecontents.Length / 2);
            int lastgood = 0;

            while (true)
            {
                //Console.WriteLine("Testing {0} bytes", splitarray1.Length);
                File.WriteAllBytes(testfilepath, splitarray1);
                string detectionStatus = Scan(testfilepath).ToString();
                if (detectionStatus.Equals("ThreatFound"))
                {
                    //Console.WriteLine("Threat found. Halfsplitting again...");
                    byte[] temparray = HalfSplitter(splitarray1, lastgood);
                    Array.Resize(ref splitarray1, temparray.Length);
                    Array.Copy(temparray, splitarray1, temparray.Length);
                }
                else if (detectionStatus.Equals("NoThreatFound"))
                {
                    //Console.WriteLine("No threat found. Going up 50% of current size.");
                    lastgood = splitarray1.Length;
                    byte[] temparray = Overshot(originalfilecontents, splitarray1.Length); //Create temp array with 1.5x more bytes
                    Array.Resize(ref splitarray1, temparray.Length);
                    Buffer.BlockCopy(temparray, 0, splitarray1, 0, temparray.Length);
                }
            }
        }

        public static void Setup()
        {
            //Default "enabled" values
            object autoSampleSubmitOrigValue;
            object realtimeProtectionOrigValue;

            RegistryKey autoSampleSubmit = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Spynet", true);
            autoSampleSubmitOrigValue = autoSampleSubmit.GetValue("SubmitSamplesConsent");
            if (autoSampleSubmitOrigValue.Equals(1))
            {
                if (!IsAdmin())
                {
                    Console.WriteLine("[-] Automatic sample submission is enabled. Either run this program as an admin or disable it manually.");
                    Environment.Exit(1);
                }
                else
                {
                    Console.WriteLine("[-] Automatic sample submission is enabled. Disabling via the registry...");
                    autoSampleSubmit.SetValue("SubmitSampleConstent", 0);
                }
            }
            autoSampleSubmit.Close();

            RegistryKey realtimeProtection = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", true);
            realtimeProtectionOrigValue = realtimeProtection.GetValue("DisableRealtimeMonitoring");
            if (realtimeProtectionOrigValue.Equals(0))
            {
                if (!IsAdmin())
                {
                    Console.WriteLine("[-] Real-time protection is enabled. Either run this program as an admin or disable it manually.");
                    Environment.Exit(1);
                }
                else
                {
                    Console.WriteLine("[-] Real-time protection is enabled. Disabling via the registry...");
                    realtimeProtection.SetValue("DisableRealtimeMonitoring", 1);
                }
            }
            realtimeProtection.Close();
        }

        public static bool IsAdmin()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            if (principal.IsInRole(WindowsBuiltInRole.Administrator))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        public static byte[] HalfSplitter(byte[] originalarray, int lastgood) //Will round down to nearest int
        {
            byte[] splitarray = new byte[(originalarray.Length - lastgood)/2+lastgood];
            if (originalarray.Length == splitarray.Length +1)
            {
                Console.WriteLine("[!] Identified end of bad bytes at {0}", originalarray.Length);
                Environment.Exit(0);
            }
            Array.Copy(originalarray, splitarray, splitarray.Length);
            return splitarray;
        }

        public static byte[] Overshot(byte[] originalarray, int splitarraysize)
        {
            int newsize = (originalarray.Length - splitarraysize) / 2 + splitarraysize;
            if (newsize.Equals(originalarray.Length-1))
            {
                Console.WriteLine("Exhausted the search. The binary looks good to go!");
                Environment.Exit(0);
            }
            byte[] newarray = new byte[newsize];
            Buffer.BlockCopy(originalarray, 0, newarray, 0, newarray.Length);
            return newarray;            
        }

        //Adapted from https://github.com/yolofy/AvScan/blob/master/src/AvScan.WindowsDefender/WindowsDefenderScanner.cs
        public static ScanResult Scan(string file)
        {
            if (!File.Exists(file))
            {
                return ScanResult.FileNotFound;
            }

            var process = new Process();
            var mpcmdrun = new ProcessStartInfo(@"C:\Program Files\Windows Defender\MpCmdRun.exe")
            {
                Arguments = $"-Scan -ScanType 3 -File \"{file}\" -DisableRemediation",
                CreateNoWindow = true,
                ErrorDialog = false,
                UseShellExecute = false,
                WindowStyle = ProcessWindowStyle.Hidden
            };

            process.StartInfo = mpcmdrun;
            process.Start();
            process.WaitForExit(30000); //Wait 30s

            if (!process.HasExited)
            {
                process.Kill();
                return ScanResult.Timeout;
            }

            switch (process.ExitCode)
            {
                case 0:
                    return ScanResult.NoThreatFound;
                case 2:
                    return ScanResult.ThreatFound;
                default:
                    return ScanResult.Error;
            }
        }

        public enum ScanResult
        {
            [Description("No threat found")]
            NoThreatFound,
            [Description("Threat found")]
            ThreatFound,
            [Description("The file could not be found")]
            FileNotFound,
            [Description("Timeout")]
            Timeout,
            [Description("Error")]
            Error
        }
    }
}