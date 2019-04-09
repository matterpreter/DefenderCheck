using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;

namespace DefenderCheck
{
    class Program
    {
        static void Main(string[] args)
        {
            string targetfile = args[0];
            string testfilepath = @"C:\Temp\testfile.txt";
            byte[] filecontents = File.ReadAllBytes(targetfile);

            int filesize = filecontents.Length;
            Console.WriteLine("Target file size: {0} bytes", filecontents.Length);

            byte[] splitfile = new byte[filecontents.Length / 2];
            Array.Copy(filecontents, splitfile, filecontents.Length / 2);
            Console.WriteLine("First halfsplit size: {0} bytes", splitfile.Length);
            File.WriteAllBytes(testfilepath, splitfile);

            var detected = Scan(testfilepath);
            Console.WriteLine(detected);

            Console.ReadKey();
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


