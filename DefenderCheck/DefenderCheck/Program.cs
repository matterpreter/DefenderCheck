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
            string targetfile = @"C:\Temp\mimikatz.exe";
            string testfilepath = @"C:\Temp\testfile.exe";
            byte[] originalfilecontents = File.ReadAllBytes(targetfile);
            int originalfilesize = originalfilecontents.Length;
            Console.WriteLine("Target file size: {0} bytes", originalfilecontents.Length);

            byte[] splitarray1 = new byte[originalfilesize/2];
            Buffer.BlockCopy(originalfilecontents, 0, splitarray1, 0, originalfilecontents.Length / 2);
            int lastgood = 0;

            while (true) //Want to narrow it down to at most 200 bytes to start the manual search.
            {
                Console.WriteLine("Testing {0} bytes", splitarray1.Length);
                File.WriteAllBytes(testfilepath, splitarray1);
                string detectionStatus = Scan(testfilepath).ToString();
                if (detectionStatus.Equals("ThreatFound"))
                {
                    Console.WriteLine("Threat found. Halfsplitting again...");
                    //byte[] tempparray = new byte[];
                    //Console.WriteLine("lastgood val: {0}", lastgood);
                    byte[] temparray = HalfSplitter(splitarray1, lastgood);
                    Array.Resize(ref splitarray1, temparray.Length);
                    Array.Copy(temparray, splitarray1, temparray.Length);
                }
                else if (detectionStatus.Equals("NoThreatFound"))
                {
                    Console.WriteLine("No threat found. Going up 50% of current size.");
                    lastgood = splitarray1.Length;
                    byte[] temparray = Overshot(originalfilecontents, splitarray1.Length); //Create temp array with 1.5x more bytes
                    Array.Resize(ref splitarray1, temparray.Length);
                    Buffer.BlockCopy(temparray, 0, splitarray1, 0, temparray.Length);
                }
            }

            Console.ReadKey();
        }

        public static byte[] HalfSplitter(byte[] originalarray, int lastgood) //Will round down to nearest int
        {
            //int arraysize = originalarray.Length;
            //Console.WriteLine("len of orig: {0}", originalarray.Length);
            byte[] splitarray = new byte[(originalarray.Length - lastgood)/2+lastgood];
            //Console.WriteLine("len of split: {0}", splitarray.Length);
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