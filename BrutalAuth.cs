

using System;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
namespace BrutalAuth
{
    public class BAuth
    {
        private readonly string _applicationId;
        private readonly string _host;

        public BAuth(string applicationId, string host)
        {
            if (string.IsNullOrEmpty(applicationId)) throw new ArgumentNullException(nameof(applicationId));
            if (string.IsNullOrEmpty(host)) throw new ArgumentNullException(nameof(host));

            _applicationId = applicationId;
            _host = host.Trim();
            if (_host.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                _host = _host.Substring("https://".Length).TrimEnd('/');
            if (_host.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                _host = _host.Substring("http://".Length).TrimEnd('/');

            try
            {
                ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072;
            }
            catch { }
        }

        public bool RegisterUser(string licenseKey, string username, string password)
        {
            string hwid = GetHardwareId();
            string json = MakeJsonRegister(licenseKey, username, password, hwid, _applicationId);
            string url = $"https://{_host}/register-user";

            string response;
            bool ok = PostJson(url, json, out response);
            if (!ok)
            {
                return false;
            }
            if (ContainsSuccessTrue(response))
            {
                return true;
            }
            return false;
        }

        public bool LoginUser(string username, string password)
        {
            string hwid = GetHardwareId();
            string json = MakeJsonLogin(username, password, hwid, _applicationId);
            string url = $"https://{_host}/login-user";

            string response;
            bool ok = PostJson(url, json, out response);
            if (!ok)
            {
                return false;
            }
            if (ContainsSuccessTrue(response))
            {
                return true;
            }
            return false;
        }

        private static bool PostJson(string url, string json, out string responseBody)
        {
            responseBody = "";
            try
            {
                var req = (HttpWebRequest)WebRequest.Create(url);
                req.Method = "POST";
                req.ContentType = "application/json";
                req.UserAgent = "BrutalAuth/1.0";
                req.AllowAutoRedirect = true;

                using (var reqStream = req.GetRequestStream())
                using (var writer = new StreamWriter(reqStream, new UTF8Encoding(false)))
                {
                    writer.Write(json);
                }

                using (var resp = (HttpWebResponse)req.GetResponse())
                using (var respStream = resp.GetResponseStream())
                using (var reader = new StreamReader(respStream ?? Stream.Null, Encoding.UTF8))
                {
                    responseBody = reader.ReadToEnd();
                }
                return true;
            }
            catch (WebException wex)
            {
                try
                {
                    using (var resp = (HttpWebResponse)wex.Response)
                    using (var s = resp?.GetResponseStream())
                    using (var r = s != null ? new StreamReader(s) : null)
                    {
                        var body = r?.ReadToEnd();
                        responseBody = body ?? wex.ToString();
                    }
                }
                catch
                {
                    responseBody = wex.ToString();
                }
                return false;
            }
            catch (Exception ex)
            {
                responseBody = ex.ToString();
                return false;
            }
        }

        private static string JsonEscape(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            var sb = new StringBuilder(s.Length + 16);
            foreach (var ch in s)
            {
                switch (ch)
                {
                    case '\"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (ch < 32)
                            sb.AppendFormat("\\u{0:X4}", (int)ch);
                        else
                            sb.Append(ch);
                        break;
                }
            }
            return sb.ToString();
        }

        private static string MakeJsonRegister(string licenseKey, string username, string password, string hwid, string applicationId)
        {
            var sb = new StringBuilder(128);
            sb.Append('{');
            sb.Append("\"licenseKey\":\"").Append(JsonEscape(licenseKey)).Append("\",");
            sb.Append("\"username\":\"").Append(JsonEscape(username)).Append("\",");
            sb.Append("\"password\":\"").Append(JsonEscape(password)).Append("\",");
            sb.Append("\"hwid\":\"").Append(JsonEscape(hwid)).Append("\",");
            sb.Append("\"applicationId\":\"").Append(JsonEscape(applicationId)).Append("\"");
            sb.Append('}');
            return sb.ToString();
        }

        private static string MakeJsonLogin(string username, string password, string hwid, string applicationId)
        {
            var sb = new StringBuilder(128);
            sb.Append('{');
            sb.Append("\"username\":\"").Append(JsonEscape(username)).Append("\",");
            sb.Append("\"password\":\"").Append(JsonEscape(password)).Append("\",");
            sb.Append("\"hwid\":\"").Append(JsonEscape(hwid)).Append("\",");
            sb.Append("\"applicationId\":\"").Append(JsonEscape(applicationId)).Append("\"");
            sb.Append('}');
            return sb.ToString();
        }

        private static bool ContainsSuccessTrue(string body)
        {
            if (string.IsNullOrEmpty(body)) return false;
            var p = body.IndexOf("\"success\"", StringComparison.OrdinalIgnoreCase);
            if (p < 0) return false;
            var t = body.IndexOf("true", p, StringComparison.OrdinalIgnoreCase);
            var f = body.IndexOf("false", p, StringComparison.OrdinalIgnoreCase);
            return t >= 0 && (f < 0 || t < f);
        }

        private static string GetHardwareId()
        {
            if (IsWindows())
                return GetWindowsHwid();

            try
            {
                var id = File.ReadAllText("/etc/machine-id").Trim();
                if (!string.IsNullOrWhiteSpace(id))
                    return id;
            }
            catch { }

            return "default-hwid";
        }


        private static bool IsWindows()
        {

            var p = (int)Environment.OSVersion.Platform;
            return p == 2;
        }

        private static string GetWindowsHwid()
        {
            try
            {
                using (var id = WindowsIdentity.GetCurrent())
                {
                    var sid = id?.User?.Value;
                    if (!string.IsNullOrEmpty(sid) && !IsSystemSid(sid))
                        return sid;
                }
            }
            catch { }

            try
            {
                uint sessionId = WTSGetActiveConsoleSessionId();
                if (sessionId != 0xFFFFFFFF)
                {
                    if (WTSQueryUserToken(sessionId, out IntPtr hToken))
                    {
                        try
                        {
                            using (var id = new WindowsIdentity(hToken))
                            {
                                var sid = id?.User?.Value;
                                if (!string.IsNullOrEmpty(sid))
                                    return sid;
                            }
                        }
                        finally
                        {
                            CloseHandle(hToken);
                        }
                    }
                }
            }
            catch { }

            try
            {
                using (var id = WindowsIdentity.GetCurrent())
                {
                    var sid = id?.User?.Value;
                    if (!string.IsNullOrEmpty(sid))
                        return sid;
                }
            }
            catch { }

            return "default-hwid";
        }

        private static bool IsSystemSid(string sid)
            => sid != null && string.Equals(sid, "S-1-5-18", StringComparison.OrdinalIgnoreCase);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);
    }
}