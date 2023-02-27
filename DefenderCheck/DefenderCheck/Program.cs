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
        private static string DefenderPath = Path.Combine(Environment.GetEnvironmentVariable("ProgramFiles"), "Windows Defender", "MpCmdRun.exe");

        static void Main(string[] args)
        {
            string targetfile = args[0];
            if (!File.Exists(targetfile))
            {
                Console.WriteLine("[-] Can't access the target file");
                return;
            }

            byte[] originalfilecontents = File.ReadAllBytes(targetfile);
            int left = 0;
            int mid = originalfilecontents.Length - 1;
            int right = mid;

            bool threatFound = false;

            while (true)
            {
                // Scan the file
                ScanResult r = Scan(originalfilecontents, mid);

                if (r == ScanResult.ThreatFound)
                {
                    threatFound = true;

                    // If it's stil a threat, search a smaller segment:
                    right = mid;
                    mid = left + ((mid - left) / 2);

                    if (right == mid)
                    {
                        // No change, we're done.
                        break;
                    }
                } 
                else if (r == ScanResult.NoThreatFound)
                {
                    // We skipped the bad part, expand!
                    left = mid;
                    mid = mid + ((right - mid) / 2);

                    if (left == mid)
                    {
                        // No change, we're done.
                        break;
                    }
                }
                else
                {
                    Console.WriteLine("Unexpected scan result: {0}. Aborting.", r);
                    break;
                }
            }

            if (threatFound)
            {
                Console.WriteLine("Threat found at byte 0x{0:X}:", mid);
                int max = mid < 256 ? mid : 256;
                byte[] tmp = new byte[max];
                Buffer.BlockCopy(originalfilecontents, mid - max, tmp, 0, max);
                HexDump(tmp);
            } else
            {
                Console.WriteLine("No threats found!");
            }
        }

        public static ScanResult Scan(byte[] fileBytes, int length, bool getsig = false)
        {
            string tmpFile = Path.GetTempFileName();
            using (FileStream fs = File.OpenWrite(tmpFile))
            {
                fs.Write(fileBytes, 0, length);
            }

            var process = new Process();
            var mpcmdrun = new ProcessStartInfo(DefenderPath)
            {
                Arguments = $"-Scan -ScanType 3 -File \"{tmpFile}\" -DisableRemediation -Trace -Level 0x10",
                CreateNoWindow = true,
                ErrorDialog = false,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };

            process.StartInfo = mpcmdrun;
            process.Start();
            process.WaitForExit(30000); //Wait up to 30s

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

            File.Delete(tmpFile);

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
