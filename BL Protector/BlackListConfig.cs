using System;
using System.Collections.Generic;
using System.Text;
using System.Configuration;

namespace ClinPhone.BLProtector
{
    public class BlacklistConfig : ConfigurationSection
    {
        private const string c_Section = "blProtector";
        private const string c_AccessKey = "accessKey";
        private const string c_BlockedUrl = "blockedUrl";
        private const string c_Threshold = "threatThreshold";
        private const string c_TestMode = "testMode";
        private const string c_IPHeader = "ipHeader";
        private const string c_IgnoreSearchEngines = "ignoreSearchEngines";

        [ConfigurationProperty(c_AccessKey)]
        public string AccessKey
        {
            get { return (string)this[c_AccessKey]; }
            set { this[c_AccessKey] = value; }
        }

        [ConfigurationProperty(c_BlockedUrl)]
        public string BlockedUrl
        {
            get { return (string)this[c_BlockedUrl]; }
            set { this[c_BlockedUrl] = value; }
        }

        [ConfigurationProperty(c_Threshold)]
        public int Threshold
        {
            get { return (int)this[c_Threshold]; }
            set { this[c_Threshold] = value; }
        }

        [ConfigurationProperty(c_TestMode)]
        public bool TestMode
        {
            get { return (bool)this[c_TestMode]; }
            set { this[c_TestMode] = value; }
        }

        [ConfigurationProperty(c_IPHeader)]
        public string IPHeader
        {
            get
            {
                if (this[c_IPHeader] == null) return "REMOTE_ADDR";
                return (string)this[c_IPHeader];
            }
            set { this[c_IPHeader] = value; }
        }

        [ConfigurationProperty(c_IgnoreSearchEngines)]
        public bool IgnoreSearchEngines
        {
            get { return (bool)this[c_IgnoreSearchEngines]; }
            set { this[c_IgnoreSearchEngines] = value; }
        }

        public static BlacklistConfig GetConfig()
        {
            return (BlacklistConfig)ConfigurationManager.GetSection(c_Section);
        }
    }
}
