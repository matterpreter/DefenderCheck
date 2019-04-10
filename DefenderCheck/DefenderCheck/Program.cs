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
            string targetfile = @"C:\Temp\lorem.txt";
            string testfilepath = @"C:\Temp\testfile.txt";
            string detectionStatus = null;
            byte[] originalfilecontents = File.ReadAllBytes(targetfile);
            int originalfilesize = originalfilecontents.Length;
            Console.WriteLine("Target file size: {0} bytes", originalfilecontents.Length);

            byte[] splitarray1 = new byte[originalfilesize];
            splitarray1 = HalfSplitter(originalfilecontents);
            byte[] splitarray2 = new byte[originalfilesize]; //writing to this buffer fixes it, but we can't use this buffer. We probably need to instantiate the first buffer and then just work from there
            //Array.Copy(originalfilecontents, splitarray1, splitarray1.Length);

            while (splitarray1.Length > 200)
            {
                //Array.Copy(splitarray2, splitarray1, splitarray2.Length);
                Console.WriteLine("Testing {0} bytes", splitarray1.Length);
                File.WriteAllBytes(testfilepath, splitarray1);
                detectionStatus = Scan(testfilepath).ToString();
                if (detectionStatus.Equals("ThreatFound"))
                {
                    Console.WriteLine("Threat found. Halfsplitting again...");
                    byte[] temparray = HalfSplitter(splitarray1);
                    Array.Copy(temparray, splitarray1, temparray.Length);
                }
                else if (detectionStatus.Equals("NoThreatFound"))
                {
                    Console.WriteLine("No threat found. Going up 50% of current size.");
                    byte[] temparray = Overshot(originalfilecontents, splitarray1.Length); //Create temp array with 1.5x more byers
                    //Array.Clear(splitarray1, 0, splitarray1.Length);
                    
                    Array.Resize(ref splitarray1, temparray.Length);
                    Buffer.BlockCopy(temparray, 0, splitarray1, 0, temparray.Length);
                }
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
            //int newsize = (splitarraysize * 3)/2; //Lazy math to get 150% because of double/int syntax ugliness
            int newsize = (originalarray.Length - splitarraysize) / 2 + splitarraysize;
            Console.WriteLine("newsize: {0}", newsize);
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


