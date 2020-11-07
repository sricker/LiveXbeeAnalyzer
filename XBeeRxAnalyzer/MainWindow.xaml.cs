using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Ports;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using ProtocolHelper;
using ProtocolHelper.DataFieldTypes;
using Path = System.IO.Path;

namespace XBeeRxAnalyzer
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private SerialPort port;

        string path = Path.GetDirectoryName(System.Reflection.Assembly.GetEntryAssembly().Location);

        private Timer ProcessTimer;

        public MainWindow()
        {
            InitializeComponent();

            // ReadFile("C:\\temp\\Roof Network Serial Tap_hex.txt");

            // ConvertSniffFileToNoEscapeMessages("C:\\temp\\live_asc_with_time.txt");

            // ConvertSniffFileToNoEscapeMessages("C:\\temp\\live_asc_with_time.txt", true, true);

            // ProcessDefectsInOrder("C:\\temp\\live_asc_with_time_proc_w_time.txt");
            // ProcessReadyMessages("C:\\temp\\live_asc_with_time_proc.txt");

            // ProcessInOrder("C:\\temp\\live_asc_with_time_proc.txt");

            // ProcessTimer = new Timer(DoWorkOnTimer, null, 1000, 1000);

        }

        // private void DoWorkOnTimer(object state)
        // {
        //     ProcessDefectsInOrder("C:\\temp\\live_asc_with_time_proc.txt");
        // }

        private List<byte> rxBytes =new List<byte>();

        private void PortOnDataReceived(object sender, SerialDataReceivedEventArgs e)
        {   
            SerialPort sp = (SerialPort)sender;
            byte[] rxData = new byte[sp.BytesToRead];
            sp.Read(rxData, 0, rxData.Length);
            
            foreach (var b in rxData) // gotta go through each one in case there is no break between messages
            {
                if (b == 0x7E && rxBytes.Count>0)
                {
                    var lastLine = RemoveEscapes(rxBytes.ToArray());

                    string diagOutput = $"{DateTime.Now:O} :{DebugHelper.ByteArrayToHexString(lastLine)}";

                    // using (StreamWriter sw = new StreamWriter( path + "\\live_asc_with_time.txt", true))
                    // {
                    //
                    //     sw.WriteLine(diagOutput);
                    //     sw.Flush();
                    //     sw.Close();
                    // }

                    Debug.WriteLine(diagOutput);
                    // ProcessLiveData(lastLine, DateTime.Now);
                    rxBytes.Clear();
                }
                
                rxBytes.Add(b);
                var readyBytes = RemoveEscapes(rxBytes.ToArray());

                if (readyBytes.Length >= 48 && readyBytes[2] == 0x2C)
                {
                    ProcessLiveData(readyBytes, DateTime.Now);
                }


            }
        }

        public void ConvertSniffFileToNoEscapeMessages(string path, bool keepTimeStamp, bool asHex)
        {
            StreamReader tr = new StreamReader(path);

            string line;

            while ((line = tr.ReadLine()) != null)
            {
                if(!line.Contains(':')) continue;

                var time = Regex.Split(line, @" :")[0]; // get the time stamp
                line = Regex.Split(line, @" :")[1]; // get everything after the colon

                // remove whitespace
                string rxMessage = String.Concat(line.Where(c => !Char.IsWhiteSpace(c))); // remove white space

                // convert to bytes
                var justBytes = StringToByteArray(rxMessage);

                var noEscapes = RemoveEscapes(justBytes);

                if (noEscapes[3] != 0x90) continue;

                string newSuffix = keepTimeStamp ? "_proc_w_time.txt" : "_proc.txt";

                using (StreamWriter sw = new StreamWriter(path.Replace(".txt", newSuffix ), true))
                {
                    long unixTime = new DateTimeOffset(DateTime.Parse(time)).ToUnixTimeMilliseconds();
                    if(keepTimeStamp) sw.Write(unixTime+" :");

                    if (asHex)
                    {
                        sw.WriteLine(DebugHelper.ByteArrayToHexString(noEscapes));
                    }
                    else
                    {
                        sw.WriteLine(new NodeDataBySerialNumber(noEscapes).ToString());
                    }

                    sw.Flush();
                    sw.Close(); // don't care how inefficient this is
                }
            }
        }

        private static List<NodeDataByTimeAndSerialNumber> datas = new List<NodeDataByTimeAndSerialNumber>();

        private static List<PBCounter> maxPbsForEachSN = new List<PBCounter>();

        private static int lineCount = 0;

        public void ProcessLiveData(byte[] asBytes, DateTime time)
        {
            if (asBytes.Length < 48 || asBytes[3] != 0x90) return; // change if we want to see other messages or add other messages to parse

            NodeDataByTimeAndSerialNumber nd = new NodeDataByTimeAndSerialNumber(asBytes, time.ToString());

            var existing = datas.FirstOrDefault(o => o.SerialId.Value == nd.SerialId.Value
                                                     && o.Timestamp.Value == nd.Timestamp.Value); // grab it if it exists already

            if (existing == null)
            {
                // is there one that needs to be analyzed from the previous time period?
                var lastOne = datas.FirstOrDefault(o => o.SerialId.Value == nd.SerialId.Value); // grab it if it exists already

                if (lastOne != null)
                {
                    var result = lastOne.EvaluateYourself(time.ToString());
                    // see if the number of pbs is off

                    var maxCounterForThisSN =
                        maxPbsForEachSN.FirstOrDefault(o => o.serialNumber == lastOne.SerialId.Value);

                    if (maxCounterForThisSN == null)
                    {
                        PBCounter newMaxPbCounter = new PBCounter(0xd0);
                        newMaxPbCounter.serialNumber = lastOne.SerialId.Value;
                        newMaxPbCounter.Count = lastOne.Codes.Count;
                        maxPbsForEachSN.Add(newMaxPbCounter);
                    }
                    else
                    {
                        if (maxCounterForThisSN.Count < lastOne.Codes.Count)
                        {
                            result += ",possible (GAP)";
                        }
                    }

                    if (result != string.Empty)
                    {
                        Debug.WriteLine(result);

                        if (!CheckAccess())
                        {
                            // On a different thread
                            Dispatcher.Invoke(() => OutputTextBox.Text += result);
                            return;
                        }
                        
                    }
                    else
                    {
                        Debug.WriteLine($"{DateTime.Now} Good reading for {lastOne.SerialId.Value}");
                    }

                    datas.Remove(lastOne);
                }

                // doesn't exist, create it
                datas.Add(nd);
            }
            else // does exist, add to it
            {
                existing.AddCode(asBytes[15]);
                existing.AddIndex(asBytes[16]);
            }
        }

        private int LineNumber = 0;
        public void ProcessDefectsInOrder(string path)
        {
            string line;
            int lineCount = 0;

            try
            {
                using (StreamReader tr = new StreamReader(path))
                {
                    while ((line = tr.ReadLine()) != null)
                    {
                        if (!line.Contains(" :")) return;

                        if(lineCount++ < LineNumber) continue;
                        
                        var time = Regex.Split(line, @" :")[0]; // get the time stamp
                        line = Regex.Split(line, @" :")[1]; // get everything after the colon

                        // remove whitespace
                        string message = string.Concat(line.Where(c => !char.IsWhiteSpace(c))); // remove white space

                        // convert to bytes
                        var asBytes = StringToByteArray(message);

                        ProcessLiveData(asBytes, DateTime.Parse(time));

                        LineNumber = lineCount;
                    }
                }
            }
            catch
            {
                // ignored
            }
        }
        public void ProcessInOrder(string path)
        {
            string line;

            using (StreamReader tr = new StreamReader(path))
            {
                while ((line = tr.ReadLine()) != null)
                {
                    // remove whitespace
                    string message = String.Concat(line.Where(c => !Char.IsWhiteSpace(c))); // remove white space

                    // convert to bytes
                    var asBytes = StringToByteArray(message);

                    if (asBytes[3] != 0x90) continue;

                    NodeDataBySerialNumber nd = new NodeDataBySerialNumber(asBytes);

                    Debug.WriteLine(nd.ToString());

                }
            }
        }
        public void ProcessReadyMessages(string path)
        {
            // read file remove escapes, sort message types, parse time, serial number and packet number
            List<Metrics> metrics = new List<Metrics>();
            
            string line;

            using (StreamReader tr = new StreamReader(path))
            {
                while ((line = tr.ReadLine()) != null)
                {
                    // remove whitespace
                    string message = String.Concat(line.Where(c => !Char.IsWhiteSpace(c))); // remove white space

                    // convert to bytes
                    var asBytes = StringToByteArray(message);

                    if (asBytes[3] != 0x90) continue;

                    NodeDataBySerialNumber nd = new NodeDataBySerialNumber(asBytes);
                    // NodeDataByTimeAndSerialNumber nd = new NodeDataByTimeAndSerialNumber(asBytes);

                    if (nd.Code == 0) continue;

                    var metric = metrics.FirstOrDefault(o => o.SerialId == nd.SerialId.Value);

                    if (metric == null)
                    {
                        metrics.Add(new Metrics(nd)); 
                    }
                    else
                    {
                        metric.Add(nd); 
                    }
                }

                foreach (var m in metrics)
                {
                    m.PrintMetrics();
                }
            }
        }
        
        public void ReadFile(string path)
        {
            // read file remove escapes, sort message types, parse time, serial number and packet number
            List<Metrics> metrics = new List<Metrics>();

            using (StreamReader tr = new StreamReader(path))
            {
                // divide file into individual messages
                string wholeFile = tr.ReadToEnd();

                string[] wholeFileAsStrings = Regex.Split(wholeFile, @"7E");
                //
                using (StreamWriter sw = new StreamWriter("c:\\temp\\messages.txt"))
                {
                    foreach (string s in wholeFileAsStrings)
                    {
                        if (s == "") continue;
                        // remove whitespace
                        string message = String.Concat(s.Where(c => !Char.IsWhiteSpace(c))); // remove white space

                        // convert to bytes
                        var asBytes = StringToByteArray(message);

                        // remove escapes
                        var noEscapes = RemoveEscapes(asBytes);

                        NodeDataBySerialNumber nd = new NodeDataBySerialNumber(noEscapes);

                        if (nd.Code != 0)
                        {
                            var metric = metrics.FirstOrDefault(o => o.SerialId == nd.SerialId.Value);

                            if (metric == null)
                            {
                                metrics.Add(new Metrics(nd));
                            }
                            else
                            {
                                metric.Add(nd);
                            }
                        }

                        // convert back to a string, lol
                        string noEscapesString = DebugHelper.ByteArrayToHexString(noEscapes);

                        // write it to file
                        sw.WriteLine($"7E{noEscapesString}".Trim());
                    }

                    foreach (var m in metrics)
                    {
                        m.PrintMetrics();
                    }

                    sw.Flush();
                    sw.Close();
                }



                // using (StreamWriter sw = new StreamWriter("C:\\temp\\Roof.txt"))
                // {
                //     sw.Write(wholeFileAsString);
                //
                //     sw.Flush();
                //     sw.Close();
                // }
            }


            // using (BinaryWriter writer = new BinaryWriter(File.Open("C:\\temp\\Roof.bin", FileMode.Create)))
            // {
            //     var messageBytes = RemoveEscapes(wholeFileAsBytes);
            //     
            //     writer.Flush();
            //     writer.Close();
            // }
        }

        private void ProcessMessage(byte[] messageBytes)
        {
            if (messageBytes.Length != 47) return;

            uint offset = 2;

            if (messageBytes[2] == 0x90)
            {
                byte[] substring = new byte[32];

                Buffer.BlockCopy(messageBytes, 14, substring, 0, 32);

                UInt32DataField sn = new UInt32DataField(false);

                sn.UnPack(substring, ref offset);

                GeokonDateTimeField st = new GeokonDateTimeField();

                st.UnPack(substring, ref offset);

                Debug.WriteLine($"{sn.Value}, {st.Value}, code={substring[0]:x2}, index={substring[1]:x2}");
            }
        }

        public byte[] RemoveEscapes(byte[] input)
        {
            bool nextCharEscaped = false;
            int escapeCount = 0;
            int bytesIn = 0;
            int bytesOut = 0;

            List<byte> output = new List<byte>();

            foreach (byte b in input)
            {
                bytesIn++;

                if (b == 0x7D)
                {
                    escapeCount++;
                    nextCharEscaped = true;
                    continue;
                }

                bytesOut++;
                if (nextCharEscaped)
                {
                    output.Add((byte)(b ^ 0x20));
                    nextCharEscaped = false;
                }
                else
                {
                    output.Add(b);
                }
            }

            // Debug.WriteLine($"Bytes in = {bytesIn}, bytes out = {bytesOut}, escape count = {escapeCount}");

            return output.ToArray();
        }

        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }

        private void SerialPortComboBox_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (port != null)
            {
                port.DataReceived -= PortOnDataReceived;
                port.Close();
                port = null;
            }

            port = new SerialPort(SerialPortComboBox.SelectedValue.ToString(), 57600);
            port.DataReceived += PortOnDataReceived;
            port.Open();
        }
    }

    public class GeokonDateTimeField
    {
        public DateTime Value;

        public GeokonDateTimeField(DateTime time)
        {
            Value = time;
        }

        public GeokonDateTimeField()
        {
        }
        public uint Length => 6;

        public void UnPack(byte[] array, ref uint offset)
        {
            if (array.Length < offset + 6)
                throw new ArgumentOutOfRangeException(nameof(offset));

            var timeData = new byte[6];

            for (int index = 0; index < Length; index++)
                timeData[index] = array[offset++];

            //                      year                month        day           hour       minute       second
            try
            {
                Value = new DateTime(timeData[5] + 2000, timeData[4], timeData[3], timeData[2], timeData[1], timeData[0]);

            }
            catch (Exception)
            {
                Value = DateTime.MinValue;
            }
        }

    }

    public class IndexCounter
    {
        public byte Index;
        public int Count;

        public IndexCounter(byte index)
        {
            Index = index;
        }
    }

    public class PBCounter
    {
        public uint serialNumber;
        public byte Code;
        public int Count;

        public PBCounter(byte code)
        {
            Code = code;
        }

    }
    public class Metrics
    {
        private List<NodeDataByTimeAndSerialNumber> dataByTime;
        private List<NodeDataBySerialNumber> daters;
        public uint SerialId = 0; 
        public List<PBCounter> pbcounts  = new List<PBCounter>();
        public List<IndexCounter> indexCounts = new List<IndexCounter>();

        public void Add(byte [] messageBytes)
        {
            NodeDataByTimeAndSerialNumber newGuy = new NodeDataByTimeAndSerialNumber(messageBytes, DateTime.Now.ToString());

            if (dataByTime == null)
            {
                dataByTime = new List<NodeDataByTimeAndSerialNumber> {newGuy};
                return;
            }

            var existingRecord = dataByTime.FirstOrDefault(o => o.SerialId.Value == newGuy.SerialId.Value && o.Timestamp == newGuy.Timestamp);

            if (existingRecord == null)
            {
                dataByTime.Add(newGuy);
                return;
            }

            byte[] substring = new byte[32];

            Buffer.BlockCopy(messageBytes, 15, substring, 0, 32);

            existingRecord.AddCode(substring[0]); // code 
            existingRecord.AddCode(substring[1]); // index

        }

        public void Add(NodeDataBySerialNumber newData)
        {
            if (SerialId == newData.SerialId.Value)
            {
                daters.Add(newData);
            }

            if (pbcounts.All(s => s.Code != newData.Code))
            {
                pbcounts.Add(new PBCounter(newData.Code));
            }

            foreach (var c in pbcounts.Where(c => c.Code == newData.Code))
            {
                c.Count++;
            }

            if (indexCounts.All(s => s.Index != newData.Index))
            {
                indexCounts.Add(new IndexCounter(newData.Index));
            }

            foreach (var c in indexCounts.Where(c => c.Index == newData.Index))
            {
                c.Count++;
            }
        }

        public Metrics(NodeDataByTimeAndSerialNumber nodeData)
        {
            if (dataByTime == null)
            {
                dataByTime = new List<NodeDataByTimeAndSerialNumber> {nodeData};
                SerialId = nodeData.SerialId.Value;
            }
        }

        public Metrics(NodeDataBySerialNumber nodeData)
        {
            if (daters == null)
            {
                daters = new List<NodeDataBySerialNumber>();
                SerialId = nodeData.SerialId.Value;
            }

            Add(nodeData);

        }

        public void PrintMetrics()
        {
            DateTime readTime = DateTime.MinValue;

            Debug.Write(Environment.NewLine + $"SerialId = {SerialId}/0x{SerialId:X2}");
            
            byte lastCode = 0;
            byte lastIndex = 0;
            int duplicates = 0;
            int unusable = 0;
            int indexChanges = 0;

            foreach (var pb in daters)
            {
                // on each time stamp, print comma delimited codes
                if (pb.Timestamp.Value != readTime)
                {
                    if (lastCode != 0xD0) unusable++;
                    Debug.WriteLine("");
                    readTime =  pb.Timestamp.Value;
                    Debug.Write($"{readTime:s}, I=0x{pb.Index:X2}");
                }

                if (lastCode == pb.Code) duplicates++;

                lastCode = pb.Code;
                if (lastIndex != pb.Index) indexChanges++;
                lastIndex = pb.Index;
                Debug.Write($", 0x{pb.Code:X2}");
            }

            Debug.WriteLine(Environment.NewLine + $"total readings = {daters.Count}, duplicates={duplicates}, unusable={unusable}, indexChanges={indexChanges}");

            foreach (var count in pbcounts)
            {
                Debug.WriteLine($"{count.Code:X2} : {count.Count}");
            }

            foreach (var indexCount in indexCounts)
            {
                Debug.WriteLine($"{indexCount.Index:X2} : {indexCount.Count}");
            }

        }

    }

    public class NodeDataByTimeAndSerialNumber
    {
        public UInt32DataField SerialId = new UInt32DataField(false);
        public GeokonDateTimeField Timestamp = new GeokonDateTimeField();
        public List<byte> Codes = new List<byte>();
        public byte Index;
        public int duplicates = 0;
        public bool isUsable = false;
        public int indexChanges = 0;
        public string When;

        public void AddCode(byte code)
        {
            if (code == 0xD0) isUsable = true;

            if (Codes.Contains(code))
            {
                duplicates++; // count duplicates
            }
            else
            {
                Codes.Add(code);
            }
        }

        public void AddIndex(byte index)
        {
            if (Index != index)
            {
                indexChanges++;
                Index = index;
            }
        }

        public NodeDataByTimeAndSerialNumber(byte[] messageBytes, string instantiationTime)
        {
            uint offset = 2;

            byte[] substring = new byte[32];

            Buffer.BlockCopy(messageBytes, 15, substring, 0, 32);

            SerialId.UnPack(substring, ref offset);

            Timestamp.UnPack(substring, ref offset);
            Timestamp.Value = ConvertSampleTimeToUtc(Timestamp.Value, -240); // todo: hard coded

            AddCode(substring[0]);

            Index = substring[1];
        }

        public static DateTime ConvertSampleTimeToUtc(DateTime sampleTime, int offsetFromUtcMinutes)
        {
            TimeSpan offset = new TimeSpan(0, 0, offsetFromUtcMinutes, 0);

            sampleTime = sampleTime - offset;  // subtract, ie, remove offset

            return DateTime.SpecifyKind(sampleTime, DateTimeKind.Utc);
        }

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append($"{Timestamp.Value},{SerialId.Value},index={Index:x2}");
            foreach (byte b in Codes)
            {
                sb.Append($",{b:X2}");
            }
            return sb.ToString();
        }
        /// <summary>
        /// evaluate the class parameters and report if anything is amiss and at what time this was noticed
        /// </summary>
        /// <param name="time"></param>
        /// <returns></returns>
        public string EvaluateYourself(string time)
        {
            // var happenTime = DateTimeOffset.FromUnixTimeMilliseconds(long.Parse(time));
            StringBuilder error = new StringBuilder($"@ {time:O}" + $", {SerialId.Value} , {Timestamp.Value.ToString()} ");
            bool isError = false;

            if (!isUsable)
            {
                error.Append(", is unusable (GAP)");
                isError = true;
            }

            // if (duplicates > 0)
            // {
            //     error.Append(", has duplicates");
            //     isError = true;
            // }

            // if (Codes.Last() == 0xD0) Codes.RemoveAt(Codes.Count - 1);
            byte[] codes = Codes.ToArray(); // convert to array

            // convert to int array (need this for SequenceEqual)
            var originalList = Enumerable.Range(0, codes.Length / 4)
                .Select(i => BitConverter.ToInt32(codes, i * 4))
                .ToList();

            if (!originalList.SequenceEqual(Enumerable.Range(1, originalList.Count())))
            {
                error.Append(", is not sequential (GAP) ");
                foreach (var c in codes)
                {
                    error.Append($",{c:X2}");
                }
            }

            error.Append(Environment.NewLine);
            if (isError)
                return error.ToString();
            return string.Empty;
        }
    }

    public class NodeDataBySerialNumber
    {
        public UInt32DataField SerialId = new UInt32DataField(false);
        public GeokonDateTimeField Timestamp = new GeokonDateTimeField();
        public byte Code;
        public byte Index;

        public NodeDataBySerialNumber(byte[] messageBytes)
        {
            uint offset = 2;

            // if (messageBytes[2] != 0x90) return;

            byte[] substring = new byte[32];

            Buffer.BlockCopy(messageBytes, 15, substring, 0, 32);

            SerialId.UnPack(substring, ref offset);

            Timestamp.UnPack(substring, ref offset);
            Timestamp.Value = ConvertSampleTimeToUtc(Timestamp.Value, -240); // todo: hard coded

            Code = substring[0];
            Index = substring[1];
        }

        public static DateTime ConvertSampleTimeToUtc(DateTime sampleTime, int offsetFromUtcMinutes)
        {
            TimeSpan offset = new TimeSpan(0, 0, offsetFromUtcMinutes, 0);

            sampleTime = sampleTime - offset;  // subtract, ie, remove offset

            return DateTime.SpecifyKind(sampleTime, DateTimeKind.Utc);
        }

        public override string ToString()
        {
            return $"{SerialId.Value},{new DateTimeOffset(Timestamp.Value)},{Index:x2}";
        }

        // public override string ToString()
        // {
        //     if (Index == 0xff) Index = 0;
        //     return $"{SerialId.Value},{new DateTimeOffset(Timestamp.Value).ToUnixTimeMilliseconds() },{Code-0xD0},{Index:x2}";
        // }
    }

}
