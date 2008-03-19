using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Text.RegularExpressions;

namespace ClinPhone.BLProtector
{
    [Flags]
    public enum VisitorTypes
    {
        SearchEngine = 0,
        Suspicious = 1,
        Harvester = 2,
        CommentSpammer = 4,
        Unknown = 8
    }

    public class BlacklistResponse
    {

        internal const string LastBlock = "__LastBlackList";
        public const string COOKIENAME = "__blSafe";

        private TimeSpan _LastActivity;
        private int _ThreatScore;
        private VisitorTypes _Type;
        private IPAddress _Address;

        /// <summary>
        /// Days since last recorded activity for the queried IP address
        /// </summary>
        public TimeSpan LastActivity
        {
            get { return _LastActivity; }
        }

        /// <summary>
        /// Threat score for the queried IP address
        /// </summary>
        public int ThreatScore
        {
            get { return _ThreatScore; }
        }

        /// <summary>
        /// Type of vistor the queried IP address is
        /// </summary>
        public VisitorTypes VisitorType
        {
            get { return _Type; }
        }

        /// <summary>
        /// Request IP address used for the check
        /// </summary>
        public IPAddress Address
        {
            get { return _Address; }
        }

        /// <summary>
        /// Access key from Project Honey Pot
        /// </summary>
        private static string AccessKey
        {
            get { return BlacklistConfig.GetConfig().AccessKey; }
        }

        public BlacklistResponse(IPAddress address): this()
        {
            _Address = address;
            LookupAddress();
        }

        public BlacklistResponse(string address) : this()
        {
            try
            {
                if (address.Contains(","))
                {
                    string[] arr = address.Split(',');
                    address = arr[0];
                }

                if (Regex.IsMatch(address, "(?:\\d{1,3}\\.){3}\\d{1,3}"))
                    _Address = IPAddress.Parse(address);
                else
                    return;
            }
            catch
            {
                return;
            }
            LookupAddress();
        }

        private BlacklistResponse()
        {
            _LastActivity = new TimeSpan();
            _ThreatScore = 0;
            _Type = VisitorTypes.Unknown;
        }

        /// <summary>
        /// Convert the result IP into readable values
        /// </summary>
        /// <param name="entry">IP address result from Project Honeypot</param>
        private void Init(IPAddress entry)
        {
            byte[] arr = entry.GetAddressBytes();
            
            if (arr[0] != 127) throw new ArgumentException("The IP address (" + entry.ToString() + ") was not a valid blacklist response.");

            _LastActivity = new TimeSpan((int)arr[1], 0, 0, 0);
            _ThreatScore = (int)arr[2];

            if (arr[3] > 7) throw new ArgumentException("The IP address (" + entry.ToString() + ") contained an invalid vistor type.");
            _Type = (VisitorTypes)arr[3];
       }

        /// <summary>
        /// Do a DNS lookup on the first request IP address
        /// </summary>
        private void LookupAddress()
        {
            if (_Address == null) throw new ArgumentException("IP address cannot be null.");

            byte[] ipBytes = _Address.GetAddressBytes();
            IPAddress[] result = null;
            try
            {
                result = Dns.GetHostAddresses(string.Format("{0}.{1}.{2}.{3}.{4}.dnsbl.httpbl.org", BlacklistResponse.AccessKey, ipBytes[3], ipBytes[2], ipBytes[1], ipBytes[0]));
            }
            catch (System.Net.Sockets.SocketException ex)
            {
                //Assume it was a valid address, therefore return nothing.
                return;
            }

            Init(result[0]);
        }

        /// <summary>
        /// Lookup an IP address on Project Honey Pot.
        /// </summary>
        /// <param name="address">IP address to query for</param>
        /// <returns>The response from Project Honey Pot. Null probably means the address is clean.</returns>
        //public static BlackListResponse LookupAddress(IPAddress address)
        //{
        //    if (address == null) throw new ArgumentException("IP address cannot be null.");

        //    byte[] ipBytes = address.GetAddressBytes();
        //    IPAddress[] result = null;
        //    try
        //    {
        //        result = Dns.GetHostAddresses(string.Format("{0}.{1}.{2}.{3}.{4}.dnsbl.httpbl.org", BlackListResponse.AccessKey, ipBytes[3], ipBytes[2], ipBytes[1], ipBytes[0]));
        //    }
        //    catch (System.Net.Sockets.SocketException ex)
        //    {
        //        //Assume it was a valid address, therefore return nothing.
        //        return null;
        //    }

        //    if (result.Length == 0) return null;
        //    return new BlackListResponse(result[0]);
        //}

        /// <summary>
        /// Lookup an IP address on Project Honey Pot.
        /// </summary>
        /// <param name="address">IP address to query for</param>
        /// <returns>The response from Project Honey Pot. Null probably means the address is clean.</returns>
        //public static BlackListResponse LookupAddress(string address)
        //{
        //    try
        //    {
        //        if (address.Contains(","))
        //        {
        //            string[] arr = address.Split(',');
        //            address = arr[0];
        //        }

        //        if (Regex.IsMatch(address, "(?:\\d{1,3}\\.){3}\\d{1,3}"))
        //            return BlackListResponse.LookupAddress(IPAddress.Parse(address));
        //        else
        //            return null;
        //    }
        //    catch
        //    {
        //        return null;
        //    }
        //}

        /// <summary>
        /// Returns the last response, if available.
        /// </summary>
        /// <returns>BlackList response object</returns>
        public static BlacklistResponse GetLastBlacklistResponse()
        {
            System.Web.HttpContext context = System.Web.HttpContext.Current;

            BlacklistResponse ret = null;
            if (context.Request.QueryString["a"] != null && context.Request.QueryString["i"] != null)
            {
                ret = new BlacklistResponse();
                ret.Init(IPAddress.Parse(context.Request.QueryString["a"]));
                ret._Address = IPAddress.Parse(context.Request.QueryString["i"]);
                //ret._LastActivity = new TimeSpan(int.Parse(context.Request.QueryString["la"]), 0, 0, 0);
                //ret._ThreatScore = int.Parse(context.Request.QueryString["ts"]);
                //ret._Type = (VistorType)int.Parse(context.Request.QueryString["t"]);
                //ret._Address = IPAddress.Parse(context.Request.QueryString["a"]);
            }

            return ret;
        }

        /// <summary>
        /// Converts the object to a querystring
        /// </summary>
        /// <returns>querystring formatted response</returns>
        internal string ToQueryString()
        {
            StringBuilder ret = new StringBuilder();
            ret.Append("?a=127.");
            ret.AppendFormat("{0}.", _LastActivity.Days);
            ret.AppendFormat("{0}.", _ThreatScore);
            ret.Append(_Type.ToString("d"));
            ret.AppendFormat("&i={0}", _Address);

            return ret.ToString();
        }

        /// <summary>
        /// Generate a random test address to blacklisting
        /// </summary>
        /// <returns>the response for the address</returns>
        public static BlacklistResponse Test()
        {
            byte[] values = new byte[] { 10, 20, 40, 80 };
            Random rnd = new Random();

            IPAddress addr = null;
            switch (rnd.Next(1,3))
            {
                case 1:
                    addr = new IPAddress(new byte[] { 127, 1, 1, (byte)rnd.Next(0, 7) });
                    break;
                case 2:
                    addr = new IPAddress(new byte[] { 127, values[rnd.Next(0, 3)], 1, 1 });
                    break;
                case 3:
                    addr = new IPAddress(new byte[] { 127, 1, values[rnd.Next(0, 3)], 1 });
                    break;
            }

            return new BlacklistResponse(addr);
        }

        /// <summary>
        /// Check if the 'bypass' cookie has been set
        /// </summary>
        /// <returns>true if cookie is set and not tampered with</returns>
        public static bool HasCookie()
        {
            System.Web.HttpCookie cookie = System.Web.HttpContext.Current.Request.Cookies[BlacklistResponse.COOKIENAME];

            if (cookie == null) return false;

            //add a check here for an md5 check for tampering.
            return true;
        }

        /// <summary>
        /// Set the 'bypass' cookie
        /// </summary>
        public static void SetCookie()
        {
            System.Web.HttpCookie cookie = new System.Web.HttpCookie(BlacklistResponse.COOKIENAME);
            //add md5 tamper check here

            System.Web.HttpContext.Current.Response.Cookies.Add(cookie);
        }
    }
}
