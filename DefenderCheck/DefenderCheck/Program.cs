using Microsoft.Win32;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace DefenderCheck
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Usage: DefenderCheck.exe [path/to/file]");
                return;
            }
            
            bool debug = false;
            if (args.Length == 2 && args[1].Contains("debug"))
            {
                debug = true;
            }

            string targetfile = args[0];
            if (!File.Exists(targetfile))
            {
                Console.WriteLine("[-] Can't access the target file");
                return;
            }
            
            string originalFileDetectionStatus = Scan(targetfile).ToString();
            if (originalFileDetectionStatus.Equals("NoThreatFound"))
            {
                if (debug) { Console.WriteLine("Scanning the whole file first"); }
                Console.WriteLine("[+] No threat found in submitted file!");
                return;
            }
            
            if (!Directory.Exists(@"C:\Temp"))
            {
                Console.WriteLine(@"[-] C:\Temp doesn't exist. Creating it...");
                Directory.CreateDirectory(@"C:\Temp");
            }
                   
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
                if (debug) { Console.WriteLine("Testing {0} bytes", splitarray1.Length); }
                File.WriteAllBytes(testfilepath, splitarray1);
                string detectionStatus = Scan(testfilepath).ToString();
                if (detectionStatus.Equals("ThreatFound"))
                {
                    if (debug) { Console.WriteLine("Threat found. Halfsplitting again..."); }
                    byte[] temparray = HalfSplitter(splitarray1, lastgood);
                    Array.Resize(ref splitarray1, temparray.Length);
                    Array.Copy(temparray, splitarray1, temparray.Length);
                }
                else if (detectionStatus.Equals("NoThreatFound"))
                {
                    if (debug) { Console.WriteLine("No threat found. Going up 50% of current size."); };
                    lastgood = splitarray1.Length;
                    byte[] temparray = Overshot(originalfilecontents, splitarray1.Length); //Create temp array with 1.5x more bytes
                    Array.Resize(ref splitarray1, temparray.Length);
                    Buffer.BlockCopy(temparray, 0, splitarray1, 0, temparray.Length);
                }
            }
        }

        //public static void Setup()
        //{
        //    RegistryKey defenderService = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows Defender");
        //    object defenderServiceValue = defenderService.GetValue("DisableAntiSpyware");
        //    if (!defenderServiceValue.Equals(0)) //This is the case in situations like Commando
        //    {
        //        Console.WriteLine("[-] The defender antispyware service is not enabled, so MpCmdRun will fail. Exiting...");
        //        Environment.Exit(1);
        //    }
        //    defenderService.Close();

        //    if (!Directory.Exists(@"C:\temp"))
        //    {
        //        Console.WriteLine(@"[-] C:\Temp\ doesn't exist. Creating it.");
        //        Directory.CreateDirectory(@"C:\Temp");
        //    }

        //}

        public static byte[] HalfSplitter(byte[] originalarray, int lastgood) //Will round down to nearest int
        {
            byte[] splitarray = new byte[(originalarray.Length - lastgood)/2+lastgood];
            if (originalarray.Length == splitarray.Length +1)
            {
                Console.WriteLine("[!] Identified end of bad bytes at offset 0x{0:X} in the original file", originalarray.Length);
                Scan(@"C:\Temp\testfile.exe", true);
                byte[] offendingBytes = new byte[256];

                if (originalarray.Length < 256)
                {
                    Array.Resize(ref offendingBytes, originalarray.Length);
                    Buffer.BlockCopy(originalarray, originalarray.Length, offendingBytes, 0, originalarray.Length);
                }
                else
                {
                    Buffer.BlockCopy(originalarray, originalarray.Length - 256, offendingBytes, 0, 256);
                }
                HexDump(offendingBytes, 16);
                File.Delete(@"C:\Temp\testfile.exe");
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
        public static ScanResult Scan(string file, bool getsig = false)
        {
            if (!File.Exists(file))
            {
                return ScanResult.FileNotFound;
            }

            var process = new Process();
            var mpcmdrun = new ProcessStartInfo(@"C:\Program Files\Windows Defender\MpCmdRun.exe")
            {
                Arguments = $"-Scan -ScanType 3 -File \"{file}\" -DisableRemediation -Trace -Level 0x10",
                CreateNoWindow = true,
                ErrorDialog = false,
                UseShellExecute = false,
                RedirectStandardOutput = true,
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

            if (getsig)
            {
                string stdout;
                string sigName;
                while ((stdout = process.StandardOutput.ReadLine()) != null)
                {
                    if (stdout.Contains("Threat  "))
                    {
                        string[] sig = stdout.Split(' ');
                        sigName = sig[19]; // Lazy way to get the signature name from MpCmdRun
                        Console.WriteLine($"File matched signature: \"{sigName}\"\n");
                        break;
                    }
                }
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

        //Adapted from https://www.codeproject.com/Articles/36747/Quick-and-Dirty-HexDump-of-a-Byte-Array
        public static void HexDump(byte[] bytes, int bytesPerLine = 16)
        {
            if (bytes == null)
            {
                Console.WriteLine("[-] Empty array supplied. Something is wrong...");
            }
            int bytesLength = bytes.Length;

            char[] HexChars = "0123456789ABCDEF".ToCharArray();

            int firstHexColumn =
                  8                   // 8 characters for the address
                + 3;                  // 3 spaces

            int firstCharColumn = firstHexColumn
                + bytesPerLine * 3       // - 2 digit for the hexadecimal value and 1 space
                + (bytesPerLine - 1) / 8 // - 1 extra space every 8 characters from the 9th
                + 2;                  // 2 spaces 

            int lineLength = firstCharColumn
                + bytesPerLine           // - characters to show the ascii value
                + Environment.NewLine.Length; // Carriage return and line feed (should normally be 2)

            char[] line = (new String(' ', lineLength - Environment.NewLine.Length) + Environment.NewLine).ToCharArray();
            int expectedLines = (bytesLength + bytesPerLine - 1) / bytesPerLine;
            StringBuilder result = new StringBuilder(expectedLines * lineLength);

            for (int i = 0; i < bytesLength; i += bytesPerLine)
            {
                line[0] = HexChars[(i >> 28) & 0xF];
                line[1] = HexChars[(i >> 24) & 0xF];
                line[2] = HexChars[(i >> 20) & 0xF];
                line[3] = HexChars[(i >> 16) & 0xF];
                line[4] = HexChars[(i >> 12) & 0xF];
                line[5] = HexChars[(i >> 8) & 0xF];
                line[6] = HexChars[(i >> 4) & 0xF];
                line[7] = HexChars[(i >> 0) & 0xF];

                int hexColumn = firstHexColumn;
                int charColumn = firstCharColumn;

                for (int j = 0; j < bytesPerLine; j++)
                {
                    if (j > 0 && (j & 7) == 0) hexColumn++;
                    if (i + j >= bytesLength)
                    {
                        line[hexColumn] = ' ';
                        line[hexColumn + 1] = ' ';
                        line[charColumn] = ' ';
                    }
                    else
                    {
                        byte b = bytes[i + j];
                        line[hexColumn] = HexChars[(b >> 4) & 0xF];
                        line[hexColumn + 1] = HexChars[b & 0xF];
                        line[charColumn] = (b < 32 ? '·' : (char)b);
                    }
                    hexColumn += 3;
                    charColumn++;
                }
                result.Append(line);
            }
            Console.WriteLine(result.ToString());
        }
    }
}
