using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Web;
using System.Net;
using System.Collections.Specialized;
using System.IO;
using System.Xml;
using System.Globalization;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure;
using ClientUtility.Control;
using System.Threading;
using ClientUtility.forms;
using System.Security;
using System.Security.Cryptography;
using Microsoft.WindowsAzure.Storage.Blob;

namespace ClientUtility
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        // fullpath for BLOB
        public string strFullPath;
        public List<string> lstFIles;

        // 128bit(16byte)IV and Key
        private const string AesIV = @"!QAZ2WSX#EDC4RFV";
        private const string AesKey = @"5TGB&YHN7UJM(IK<";

        // security settings for WS
        static string serviceNamespace = "urbanwater";
        static string acsHostUrl = "accesscontrol.windows.net";
        static string uid = "urbanw";
        static string pwd = "hT4mC#dO";

        private static bool bEncrypt = false;
        private static string targetContainerName = string.Empty;

        private delegate void EncryptDelegate(string strFileName);
        private EncryptDelegate EncryptDeleg;

        public static forms.ActivityPopUp PopUp;

        public MainWindow()
        {
            InitializeComponent();
            this.WindowStartupLocation = WindowStartupLocation.CenterScreen;
            PopUp = new forms.ActivityPopUp();
            PopUp.WindowStartupLocation = WindowStartupLocation.CenterScreen;
            PopUp.Hide();
            EncryptDeleg = new EncryptDelegate(this.EncryptAndUpload);
        }


        private static string GetTokenFromACS(string scope)
        {
            string wrapPassword = pwd;
            string wrapUsername = uid;

            // request a token from ACS
            WebClient client = new WebClient();
            client.BaseAddress = string.Format("https://{0}.{1}", serviceNamespace, acsHostUrl);

            NameValueCollection values = new NameValueCollection();
            values.Add("wrap_name", wrapUsername);
            values.Add("wrap_password", wrapPassword);
            values.Add("wrap_scope", scope);

            byte[] responseBytes = client.UploadValues("WRAPv0.9/", "POST", values);

            string response = Encoding.UTF8.GetString(responseBytes);

            Console.WriteLine("\nreceived token from ACS: {0}\n", response);

            return HttpUtility.UrlDecode(
                response
                .Split('&')
                .Single(value => value.StartsWith("wrap_access_token=", StringComparison.OrdinalIgnoreCase))
                .Split('=')[1]);
        }

        private void btnfile_Click(object sender, RoutedEventArgs e)
        {
            WSFileUpload.UrbanWater_FileUploadClient client = new WSFileUpload.UrbanWater_FileUploadClient();
            XmlTextReader contents = new XmlTextReader(@"C:\Users\Martin.Keniron\mk.xml");
            string text = System.IO.File.ReadAllText(@"C:\Users\Martin.Keniron\mk.xml");
            // convert string to stream
            byte[] byteArray = Encoding.UTF8.GetBytes(contents.Value);
            //byte[] byteArray = Encoding.ASCII.GetBytes(contents);
            //MemoryStream stream = new MemoryStream(byteArray);
            //Stream x = (Stream)reader.Value
            //StreamReader reader = File.OpenText(@"c:\test.xml");
            System.IO.Stream stream = new System.IO.FileStream(@"C:\Users\Martin.Keniron\mk.xml", System.IO.FileMode.Open);


            client.UploadFile("sagemcom", 10, "HeadEndSystem", stream);
            client.Close();
        }


        private const int MaxBlockSize = 4000000; // Approx. 4MB chunk size

        public Uri UploadBlob(string filePath, CloudStorageAccount account, string containerName)
        {

            byte[] fileContent = File.ReadAllBytes(filePath);

            string blobName = System.IO.Path.GetFileName(filePath);
            return UploadBlob(fileContent, account, containerName, blobName);
        }

        public Uri UploadBlob(byte[] fileContent, CloudStorageAccount account, string containerName, string blobName)
        {
            CloudBlobClient blobClient = account.CreateCloudBlobClient();
            CloudBlobContainer container = blobClient.GetContainerReference(containerName);
            container.CreateIfNotExists();
            CloudBlockBlob blob = container.GetBlockBlobReference(blobName);

            HashSet<string> blocklist = new HashSet<string>();
            foreach (FileBlock block in GetFileBlocks(fileContent))
            {
                blob.PutBlock(
                    block.Id,
                    new MemoryStream(block.Content, true),
                    null
                    );
                blocklist.Add(block.Id);
            }

            blob.PutBlockList(blocklist);
            return blob.Uri;
        }

        private string Encrypt(string text, string strMeterID)
        {

            string strAESKey = string.Empty;
            //Need to check does the key exist

            using (var db = new uwkeydataEntities1())
            {
                foreach (MeterKey mk in db.MeterKeys)
                {
                    if (mk.MeterID == strMeterID)
                    {
                        strAESKey = mk.AesKey;
                    }
                }
            }

            //if key does not already exist
            if (strAESKey == string.Empty)
            {
                //make key on the fly
                using (RijndaelManaged myRijndael = new RijndaelManaged())
                {
                    myRijndael.KeySize = 128;
                    myRijndael.GenerateKey();
                    // we dont need iv just key value
                    //myRijndael.GenerateIV();

                    byte[] xkey = myRijndael.Key;
                    //var xIV = myRijndael.IV;

                    AesCryptoServiceProvider aes;
                    // AesCryptoServiceProvider
                    using (aes = new AesCryptoServiceProvider())
                    {
                        aes.BlockSize = 128;
                        aes.KeySize = 128;
                        aes.IV = Encoding.UTF8.GetBytes(AesIV);
                        aes.Key = xkey;
                        aes.Mode = CipherMode.CBC;
                        aes.Padding = PaddingMode.PKCS7;

                        //store meterID AES Key AES IV in Database

                        using (var db = new uwkeydataEntities1())
                        {
                            MeterKey mk = new MeterKey();
                            mk.MeterID = strMeterID;
                            mk.AesKey = Convert.ToBase64String(aes.Key);
                            db.MeterKeys.Add(mk);
                            db.SaveChanges();
                        }

                        //byte[] encrypted = EncryptStringToBytes(original, myRijndael.Key, myRijndael.IV);
                        // Convert string to byte array
                        byte[] src = Encoding.Unicode.GetBytes(text);

                        // encryption
                        using (ICryptoTransform encrypt = aes.CreateEncryptor())
                        {
                            byte[] dest = encrypt.TransformFinalBlock(src, 0, src.Length);
                            aes.Clear();
                            aes.Dispose();
                            encrypt.Dispose();
                            // Convert byte array to Base64 strings
                            return Convert.ToBase64String(dest);
                        }
                    }
                }
            }
            else
            {
                //we have the key 
                AesCryptoServiceProvider aes;
                // AesCryptoServiceProvider
                using (aes = new AesCryptoServiceProvider())
                {
                    aes.BlockSize = 128;
                    aes.KeySize = 128;
                    aes.IV = Encoding.UTF8.GetBytes(AesIV);
                    //aes.Key = Encoding.UTF8.GetBytes(strAESKey);
                    aes.Key = System.Convert.FromBase64String(strAESKey);
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    //byte[] encrypted = EncryptStringToBytes(original, myRijndael.Key, myRijndael.IV);
                    // Convert string to byte array
                    byte[] src = Encoding.Unicode.GetBytes(text);

                    // encryption
                    using (ICryptoTransform encrypt = aes.CreateEncryptor())
                    {
                        byte[] dest = encrypt.TransformFinalBlock(src, 0, src.Length);
                        aes.Clear();
                        aes.Dispose();
                        encrypt.Dispose();
                        // Convert byte array to Base64 strings
                        return Convert.ToBase64String(dest);
                    }
                }
            }
        }

        private IEnumerable<FileBlock> GetFileBlocks(byte[] fileContent)
        {
            HashSet<FileBlock> hashSet = new HashSet<FileBlock>();
            if (fileContent.Length == 0)
                return new HashSet<FileBlock>();
            int blockId = 0;
            int ix = 0;
            int currentBlockSize = MaxBlockSize;
            while (currentBlockSize == MaxBlockSize)
            {
                if ((ix + currentBlockSize) > fileContent.Length)
                    currentBlockSize = fileContent.Length - ix;

                byte[] chunk = new byte[currentBlockSize];

                Array.Copy(fileContent, ix, chunk, 0, currentBlockSize);
                hashSet.Add(
                    new FileBlock()
                    {
                        Content = chunk,
                        Id = Convert.ToBase64String(System.BitConverter.GetBytes(blockId))
                    });

                ix += currentBlockSize;
                blockId++;
            }
            return hashSet;
        }


        private void Button_Click_3(object sender, RoutedEventArgs e)
        {
            txtBoxBrowse1.Clear();

            // Create OpenFileDialog 
            Microsoft.Win32.OpenFileDialog dlg = new Microsoft.Win32.OpenFileDialog();
            dlg.Multiselect = true;
            // Set filter for file extension and default file extension 
            dlg.DefaultExt = ".txt";
            //dlg.Filter = "XML Files (*.xml)|*.xml";

            // Display OpenFileDialog by calling ShowDialog method 
            Nullable<bool> result = dlg.ShowDialog();


            // Get the selected file name and display in a TextBox 
            if (result == true)
            {
                // Open document 
                string filename = dlg.FileName;
                txtBoxBrowse1.Text = strFullPath = filename;

                lstFIles = dlg.FileNames.ToList();
            }
        }

        private void EncryptAndUpload(string strFileName)
        {
            Guid gu = Guid.NewGuid();
            if (lstFIles.Count() == 0)
            {
                lstFIles = new List<string>();
            }

            if (bEncrypt != false)
            {
                string strOutputFile = string.Empty;

                try
                {
                    int intLocation = strFileName.LastIndexOf(@"\") + 1;
                    strOutputFile = strFileName.Insert(intLocation, gu.ToString());
 
                    using (StreamReader sr = new StreamReader(strFileName))
                    {
                        int fileNumber = 0;

                        while (!sr.EndOfStream)
                        {
                            int count = 0;

                            using (StreamWriter sw = new StreamWriter(strOutputFile + ++fileNumber))
                            {
                                sw.AutoFlush = true;

                                while (!sr.EndOfStream && ++count < 200001)
                                {
                                    //read file one line at a time for large files
                                    string[] values = sr.ReadLine().Split(',');
                                    string strMeterID = values[0].ToString();
                                    string dtTimeStamp = values[1].ToString();

                                    string strReading = values[2].ToString();
                                    strReading = Encrypt(strReading, strMeterID);
                                    string strEntry = strMeterID + "," + dtTimeStamp + "," + strReading;

                                    sw.WriteLine(strEntry);
                                }


                                lstFIles.Add(strOutputFile + fileNumber);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show("A problem occured during the encryption of your data\n" + ex.ToString(), "UrbanWater Upload Client");
                }
            }

            try
            {
                if (lstFIles.Count != 0)
                {
                    foreach (string file in lstFIles)
                    {
                        CloudStorageAccount cs =
                            CloudStorageAccount.Parse("DefaultEndpointsProtocol=https;AccountName=uwdataupload;AccountKey=9bOm1IxjkfBi8hcnvXn+GjiSbrPQFY+ZqEtSf7l2/Eja5JZgNBJ7w4GF/19VV/W50iT4ScnpzJSMdZz0C4geOg==");

                        switch (targetContainerName)
                        {
                            case "Tavira":
                                UploadBlob(file, cs, "tavirameterdata");
                                break;
                            case "Aqualia":
                                UploadBlob(file, cs, "aqualiameterdata");
                                break;
                            case "Ovod":
                                UploadBlob(file, cs, "ovodmeterdata");
                                break;
                            case "Weather data":
                                UploadBlob(file, cs, "weatherdata");
                                break;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("A problem occured during the Upload of your data\n" + ex.ToString(), "UrbanWater Upload Client");
            }
        }



        private void btnClose_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        delegate void ParametrizedMethodInvoker5(IAsyncResult arg);


        private void EncryptionAndUploadComplete(IAsyncResult iar)
        {
            if (!Dispatcher.CheckAccess()) // CheckAccess returns true if you're on the dispatcher thread
            {
                Dispatcher.Invoke(new ParametrizedMethodInvoker5(EncryptionAndUploadComplete), iar);
                return;
            }

            PopUp.Hide();
            txtBoxBrowse1.Text = "";
            btnClear.IsEnabled = true;
            btnClose.IsEnabled = true;
            btnEncrypt.IsEnabled = false;
            btnSelect.IsEnabled = true;
            btnPlain.IsEnabled = true;
        }

        private void btnPlain_Click(object sender, RoutedEventArgs e)
        {
            bEncrypt = false;
            targetContainerName = ContainerTarget.Text.ToString();

            //EncryptAndUpload(txtBoxBrowse1.Text);
            string strFileName = string.Empty;
            strFileName = txtBoxBrowse1.Text;
            PopUp.Show();

            if (txtBoxBrowse1.Text != "" && txtBoxBrowse1.Text != string.Empty)
            {
                EncryptDeleg.BeginInvoke(strFileName, new AsyncCallback(EncryptionAndUploadComplete), EncryptDeleg);
            }
            else
            {
                PopUp.Hide();
                MessageBox.Show("Please select a file before attempting encryption and upload", "UrbanWater Upload Client");
            }

            btnClear.IsEnabled = false;
            btnClose.IsEnabled = false;
            btnPlain.IsEnabled = false;
            btnSelect.IsEnabled = false;
            btnEncrypt.IsEnabled = false;
        }

        private void btnClearText_Click(object sender, RoutedEventArgs e)
        {
            txtBoxBrowse1.Clear();
        }

        private void btnEncrypt_Click(object sender, RoutedEventArgs e)
        {
            bEncrypt = true;

            //EncryptAndUpload(txtBoxBrowse1.Text);
            string strFileName = string.Empty;
            strFileName = txtBoxBrowse1.Text;
            PopUp.Show();

            if (txtBoxBrowse1.Text != "" && txtBoxBrowse1.Text != string.Empty)
            {
                EncryptDeleg.BeginInvoke(strFileName, new AsyncCallback(EncryptionAndUploadComplete), EncryptDeleg);
            }
            else
            {
                PopUp.Hide();
                MessageBox.Show("Please select a file before attempting encryption and upload", "UrbanWater Upload Client");
            }

            btnClear.IsEnabled = false;
            btnClose.IsEnabled = false;
            btnEncrypt.IsEnabled = false;
            btnSelect.IsEnabled = false;
            btnPlain.IsEnabled = false;
        }
    }


    internal class FileBlock
    {

        public string Id
        {
            get;
            set;
        }

        public byte[] Content
        {
            get;
            set;
        }

    }
}