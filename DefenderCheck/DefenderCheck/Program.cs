using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;

namespace DefenderCheck
{
    class Program
    {
        //TODO:
        //Disable automatic submissions in the registry and restore the original value if it was set

        static void Main(string[] args)
        {
            //Initial file parse
            string targetfile = @"C:\Users\matt\Desktop\deadbeef.txt";
            string testfilepath = @"C:\Temp\testfile.txt";
            string detectionStatus = null;
            byte[] filecontents = File.ReadAllBytes(targetfile);
            int filesize = filecontents.Length;
            Console.WriteLine("Target file size: {0} bytes", filecontents.Length);

            //First halfsplit to determine which half of the file the detection stems from
            Console.WriteLine("Trying first halfsplit");
            byte[] splitfile = HalfSplitter(filecontents);
            Console.WriteLine("First halfsplit size: {0} bytes", splitfile.Length);
            File.WriteAllBytes(testfilepath, splitfile);
            
            //Scan the first half
            Console.WriteLine("Scanning first split");
            detectionStatus = Scan(testfilepath).ToString();
            Console.WriteLine(detectionStatus);
            if (detectionStatus.Equals("ThreatFound"))
            {
                Console.WriteLine("Threat found. Detection stems from fist half of the file.");

            }
            else if (detectionStatus.Equals("NoThreatFound"))
            {
                Console.WriteLine("Threat not found. Detection stems from the second half of the file.");
            }
            else
            {
                Console.WriteLine("Something went wrong...");
                Environment.Exit(1);
            }

            Console.ReadKey();
        }

        public static byte[] HalfSplitter(byte[] originalarray) //Will round down to nearest int
        {
            int arraysize = originalarray.Length;
            byte[] splitarray = new byte[arraysize / 2];
            Array.Copy(originalarray, splitarray, arraysize / 2);
            return splitarray;
        }

        public static byte[] Overshot(byte[] originalarray, int splitarraysize)
        {
            int newsize = (splitarraysize * 3)/2; //Lazy math to get 150% because of double/int syntax ugliness
            byte[] newarray = new byte[newsize];
            Array.Copy(originalarray, newarray, newarray.Length);
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


