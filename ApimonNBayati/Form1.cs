using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Diagnostics.Eventing.Reader;
using System.Xml;
using System.Xml.Linq;
using System.IO;
using System.Net;
using System.Security.Principal;
using System.Diagnostics;

namespace ApimonNBayati
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void dataGridView1_CellContentClick(object sender, DataGridViewCellEventArgs e)
        {
            Process eventProc = new Process();
            eventProc.StartInfo.FileName = "cmd.exe";
            eventProc.StartInfo.Arguments = @"/k Auditpol /set /subcategory:""File System"" /success:enable";
            eventProc.StartInfo.UseShellExecute = false;
            
            eventProc.Start();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            DataTable datatable = new DataTable();
            datatable.Clear();
            DataRow datarow;
            datatable.Columns.Add("EventRecordID");
            datatable.Columns.Add("ProcessId");
            datatable.Columns.Add("ProcessName");
            datatable.Columns.Add("AccessList");
            datatable.Columns.Add("ObjectName");
            datatable.Columns.Add("TimeCreated");

            System.Diagnostics.Stopwatch watch = new System.Diagnostics.Stopwatch();
            watch.Reset();
            watch.Start();
            //int count = 0;
            // int x = 0;
            var query = new EventLogQuery("C:\\Windows\\System\\winevt\\Logs\\Security.evtx", PathType.FilePath, "*[System/EventID=4663]");
            using (var reader = new System.Diagnostics.Eventing.Reader.EventLogReader(query))
            {

                List<EventRecord> eventList = new List<EventRecord>();
                for (EventRecord eventInstance = reader.ReadEvent();
                    null != eventInstance; eventInstance = reader.ReadEvent())
                {
                    eventInstance.FormatDescription();
                    if ((eventInstance.Id == 4663))
                    {
                        XmlDocument xmlDoc = new XmlDocument();
                        String eventXml = eventInstance.ToXml();   //we can read Event data from xml, Like xml file reading ;)


                        xmlDoc.LoadXml(eventXml);
                        XmlElement root = xmlDoc.DocumentElement;
                        XmlElement el = (XmlElement)root.SelectSingleNode("Event");
                        xmlDoc.DocumentElement.SetAttribute("xmlns", "");
                        xmlDoc.LoadXml(xmlDoc.InnerXml);

                        datarow = datatable.NewRow();
                        XmlNode node_EventRecordID = xmlDoc.SelectSingleNode("Event/System/EventRecordID");
                        datarow["EventRecordID"] = node_EventRecordID.InnerText;

                        XmlNodeList nodeList = (xmlDoc.SelectNodes("Event/System/TimeCreated"));
                        foreach (XmlNode elem in nodeList)
                        {
                            datarow["TimeCreated"] = elem.Attributes["SystemTime"].Value;
                        }

                        XmlNode node_ProcessId = xmlDoc.SelectSingleNode("Event/EventData/Data[@Name='ProcessId']");
                        datarow["ProcessId"] = node_ProcessId.InnerText;

                        XmlNode node_ProcessName = xmlDoc.SelectSingleNode("Event/EventData/Data[@Name='ProcessName']");
                        datarow["ProcessName"] = node_ProcessName.InnerText;

                        XmlNode node_ObjectName = xmlDoc.SelectSingleNode("Event/EventData/Data[@Name='ObjectName']");
                        datarow["ObjectName"] = node_ObjectName.InnerText;

                        XmlNode node_AccessList = xmlDoc.SelectSingleNode("Event/EventData/Data[@Name='AccessList']");
                        if (node_AccessList.InnerText.Substring(0, 6) == "%%4423")
                        {
                            datarow["AccessList"] = "ReadAttributes";
                        }
                        else if (node_AccessList.InnerText.Substring(0, 6) == "%%1538")
                        {
                            datarow["AccessList"] = "READ_CONTROL";
                        }
                        else if (node_AccessList.InnerText.Substring(0, 6) == "%%4416")
                        {
                            datarow["AccessList"] = "ReadData (or ListDirectory)";
                        }
                        else if (node_AccessList.InnerText.Substring(0, 6) == "%%4416")
                        {
                            datarow["AccessList"] = "ReadData (or ListDirectory)";
                        }
                        else if (node_AccessList.InnerText.Substring(0, 6) == "%%4417")
                        {
                            datarow["AccessList"] = "WriteData (or AddFile)";
                        }
                        else if (node_AccessList.InnerText.Substring(0, 6) == "%%4418")
                        {
                            datarow["AccessList"] = "AppendData (or AddSubdirectory or CreatePipeInstance)";
                        }
                        else if (node_AccessList.InnerText.Substring(0, 6) == "%%1537")
                        {
                            datarow["AccessList"] = "DELETE";
                        }
                        else
                        {
                            datarow["AccessList"] = node_AccessList.InnerText;
                        }

                        datatable.Rows.InsertAt(datarow, 0);
                    }
                    //x = x + 1;
                }
            }
            dataGridView1.DataSource = datatable;
            timer1.Enabled = true;
        }

        private void button2_Click(object sender, EventArgs e)
        {
            label1.Visible = true;
            FolderBrowserDialog folderdialog = new FolderBrowserDialog();
            if (folderdialog.ShowDialog() == DialogResult.OK)
            {
                textBox1.Text = folderdialog.SelectedPath;
                Process eventProc = new Process();
                eventProc.StartInfo.FileName = "cmd.exe";
                eventProc.StartInfo.Arguments = @"/k subinacl /subdirectories=directoriesonly " + textBox1.Text + " /sallowdeny=users=f && subinacl /subdirectories=directoriesonly " + textBox1.Text + " /sallowdeny=Administrators=f";
                eventProc.StartInfo.UseShellExecute = false;
              
                eventProc.Start();
            }
        }

        private void timer1_Tick(object sender, EventArgs e)
        {
            DataTable datatable = new DataTable();
            datatable.Clear();
            DataRow datarow;
            datatable.Columns.Add("EventRecordID");
            datatable.Columns.Add("TimeCreated");
            datatable.Columns.Add("ProcessId");
            datatable.Columns.Add("ProcessName");
            datatable.Columns.Add("ObjectName");
            datatable.Columns.Add("AccessList");

            System.Diagnostics.Stopwatch watch = new System.Diagnostics.Stopwatch();
            watch.Reset();
            watch.Start();
            // int count = 0;
            //int x = 0;
            var query = new EventLogQuery("C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", PathType.FilePath, "*[System/EventID=4663]");
            using (var reader = new System.Diagnostics.Eventing.Reader.EventLogReader(query))
            {

                List<EventRecord> eventList = new List<EventRecord>();
                for (EventRecord eventInstance = reader.ReadEvent();
                    null != eventInstance; eventInstance = reader.ReadEvent())
                {
                    eventInstance.FormatDescription();
                    if ((eventInstance.Id == 4663))
                    {
                        XmlDocument xmlDoc = new XmlDocument();
                        String eventXml = eventInstance.ToXml();   


                        xmlDoc.LoadXml(eventXml);
                        XmlElement root = xmlDoc.DocumentElement;
                        XmlElement el = (XmlElement)root.SelectSingleNode("Event");
                        xmlDoc.DocumentElement.SetAttribute("xmlns", "");
                        xmlDoc.LoadXml(xmlDoc.InnerXml);

                        datarow = datatable.NewRow();
                        XmlNode node_EventRecordID = xmlDoc.SelectSingleNode("Event/System/EventRecordID");
                        datarow["EventRecordID"] = node_EventRecordID.InnerText;

                        XmlNodeList nodeList = (xmlDoc.SelectNodes("Event/System/TimeCreated"));
                        foreach (XmlNode elem in nodeList)
                        {
                            datarow["TimeCreated"] = elem.Attributes["SystemTime"].Value;
                        }

                        XmlNode node_ProcessId = xmlDoc.SelectSingleNode("Event/EventData/Data[@Name='ProcessId']");
                        datarow["ProcessId"] = node_ProcessId.InnerText;

                        XmlNode node_ProcessName = xmlDoc.SelectSingleNode("Event/EventData/Data[@Name='ProcessName']");
                        datarow["ProcessName"] = node_ProcessName.InnerText;

                        XmlNode node_ObjectName = xmlDoc.SelectSingleNode("Event/EventData/Data[@Name='ObjectName']");
                        datarow["ObjectName"] = node_ObjectName.InnerText;

                        XmlNode node_AccessList = xmlDoc.SelectSingleNode("Event/EventData/Data[@Name='AccessList']");
                        if (node_AccessList.InnerText.Substring(0, 6) == "%%4423")
                        {
                            datarow["AccessList"] = "ReadAttributes";
                        }
                        else if (node_AccessList.InnerText.Substring(0, 6) == "%%1538")
                        {
                            datarow["AccessList"] = "READ_CONTROL";
                        }
                        else if (node_AccessList.InnerText.Substring(0, 6) == "%%4416")
                        {
                            datarow["AccessList"] = "ReadData (or ListDirectory)";
                        }
                        else if (node_AccessList.InnerText.Substring(0, 6) == "%%4416")
                        {
                            datarow["AccessList"] = "ReadData (or ListDirectory)";
                        }
                        else if (node_AccessList.InnerText.Substring(0, 6) == "%%4417")
                        {
                            datarow["AccessList"] = "WriteData (or AddFile)";
                        }
                        else if (node_AccessList.InnerText.Substring(0, 6) == "%%4418")
                        {
                            datarow["AccessList"] = "AppendData (or AddSubdirectory or CreatePipeInstance)";
                        }
                        else if (node_AccessList.InnerText.Substring(0, 6) == "%%1537")
                        {
                            datarow["AccessList"] = "DELETE";
                        }
                        else
                        {
                            datarow["AccessList"] = node_AccessList.InnerText;
                        }


                        datatable.Rows.InsertAt(datarow, 0);
                    }
                    //x = x + 1;
                }
            }
            dataGridView1.DataSource = datatable;
        }

        private void label1_Click(object sender, EventArgs e)
        {

        }
    }
}
//nazaninbayati