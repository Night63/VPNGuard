using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32;

namespace VpnGuard
{
    public class VpnState
    {
        public bool ProcessRunning;
        public bool TunnelUp;
        public string Reason = "";
    }

    /// <summary>
    /// Следит за состоянием туннеля. Каждый опрос (и каждое изменение сети) вызывает
    /// OnPoll со свежим состоянием — решение что делать принимает MainForm.
    /// </summary>
    public class VpnMonitor : IDisposable
    {
        private readonly Config _cfg;
        private readonly Logger _log;
        private System.Threading.Timer _timer;
        private int _busy;          // защита от параллельных проверок
        private bool _started;

        public event Action<VpnState> OnPoll;

        public VpnMonitor(Config cfg, Logger log)
        {
            _cfg = cfg;
            _log = log;
        }

        public void Start()
        {
            if (_started) return;
            _started = true;
            NetworkChange.NetworkAddressChanged += OnNetworkChanged;
            NetworkChange.NetworkAvailabilityChanged += OnNetworkAvailability;
            _timer = new System.Threading.Timer(delegate { Check(); }, null, 0, _cfg.PollIntervalMs);
        }

        public void Stop()
        {
            if (!_started) return;
            _started = false;
            NetworkChange.NetworkAddressChanged -= OnNetworkChanged;
            NetworkChange.NetworkAvailabilityChanged -= OnNetworkAvailability;
            if (_timer != null) { _timer.Dispose(); _timer = null; }
        }

        public void Dispose() { Stop(); }

        private void OnNetworkChanged(object sender, EventArgs e) { Check(); }
        private void OnNetworkAvailability(object sender, NetworkAvailabilityEventArgs e) { Check(); }

        public void Check()
        {
            if (!_started) return;
            if (Interlocked.Exchange(ref _busy, 1) == 1) return;
            try
            {
                var st = Detect();
                var h = OnPoll;
                if (h != null) h(st);
            }
            catch (Exception ex)
            {
                _log.Error("Ошибка проверки VPN: " + ex.Message);
            }
            finally
            {
                Interlocked.Exchange(ref _busy, 0);
            }
        }

        public VpnState Detect()
        {
            var st = new VpnState();
            st.ProcessRunning = IsProcessRunning(_cfg.GetVpnProcName());
            if (!st.ProcessRunning)
            {
                st.Reason = "процесс " + _cfg.GetVpnProcName() + " не запущен";
                return st;
            }

            string mode = (_cfg.DetectionMode ?? "auto").Trim().ToLowerInvariant();

            if (mode == "process")
            {
                st.TunnelUp = true;
                st.Reason = "процесс запущен (режим process — туннель не проверяется)";
                return st;
            }

            string note = "процесс запущен, но туннель не найден (адаптер VPN не поднят)";
            if (mode == "auto" || mode == "adapter")
            {
                NetworkInterface ni = FindVpnAdapter(_cfg.GetAdapterKeywords());
                if (ni != null)
                {
                    string desc = ni.Name + " (" + ni.Description + ")";
                    if (!_cfg.RequireVpnRoute || RoutesThrough(ni))
                    {
                        st.TunnelUp = true;
                        st.Reason = "адаптер: " + desc + (_cfg.RequireVpnRoute ? ", трафик идёт через него" : "");
                        return st;
                    }
                    note = "адаптер " + desc + " включён, но трафик идёт мимо VPN (через " + BestInterfaceName() + ")";
                    if (mode == "adapter") { st.Reason = note; return st; }
                }
            }

            if (mode == "auto" || mode == "proxy")
            {
                string proxy = GetSystemProxy();
                if (proxy != null)
                {
                    st.TunnelUp = true;
                    st.Reason = "системный прокси: " + proxy;
                    return st;
                }
            }

            st.Reason = note;
            return st;
        }

        public static bool IsProcessRunning(string name)
        {
            try
            {
                var procs = Process.GetProcessesByName(name);
                foreach (var p in procs) p.Dispose();
                return procs.Length > 0;
            }
            catch { return false; }
        }

        /// <summary>Поднятый VPN-адаптер с рабочим IP-адресом или null.</summary>
        public static NetworkInterface FindVpnAdapter(string[] keywords)
        {
            if (keywords == null || keywords.Length == 0) return null;
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                string name = (ni.Name ?? "").ToLowerInvariant();
                string desc = (ni.Description ?? "").ToLowerInvariant();
                bool match = false;
                foreach (var k in keywords)
                {
                    var kk = k.ToLowerInvariant();
                    if (name.Contains(kk) || desc.Contains(kk)) { match = true; break; }
                }
                if (!match) continue;
                if (!HasUsableAddress(ni)) continue;
                return ni;
            }
            return null;
        }

        /// <summary>Идёт ли трафик в интернет (на 1.1.1.1) через этот адаптер.</summary>
        public static bool RoutesThrough(NetworkInterface ni)
        {
            try
            {
                uint best;
                uint dest = BitConverter.ToUInt32(IPAddress.Parse("1.1.1.1").GetAddressBytes(), 0);
                if (GetBestInterface(dest, out best) != 0) return false;
                var p4 = ni.GetIPProperties().GetIPv4Properties();
                return p4 != null && p4.Index == best;
            }
            catch { return false; }
        }

        /// <summary>Через какой адаптер сейчас идёт интернет-трафик (для диагностики).</summary>
        public static string BestInterfaceName()
        {
            try
            {
                uint best;
                uint dest = BitConverter.ToUInt32(IPAddress.Parse("1.1.1.1").GetAddressBytes(), 0);
                if (GetBestInterface(dest, out best) != 0) return "не определён";
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    try
                    {
                        var p4 = ni.GetIPProperties().GetIPv4Properties();
                        if (p4 != null && p4.Index == best) return ni.Name + " (" + ni.Description + ")";
                    }
                    catch { }
                }
                return "индекс " + best;
            }
            catch (Exception ex) { return "ошибка: " + ex.Message; }
        }

        [DllImport("iphlpapi.dll")]
        private static extern int GetBestInterface(uint dwDestAddr, out uint pdwBestIfIndex);

        private static bool HasUsableAddress(NetworkInterface ni)
        {
            try
            {
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                {
                    var a = ua.Address;
                    if (a.AddressFamily == AddressFamily.InterNetwork)
                    {
                        var b = a.GetAddressBytes();
                        if (b[0] == 169 && b[1] == 254) continue; // APIPA — адрес не выдан
                        if (IPAddress.IsLoopback(a)) continue;
                        return true;
                    }
                    if (a.AddressFamily == AddressFamily.InterNetworkV6 && !a.IsIPv6LinkLocal && !IPAddress.IsLoopback(a))
                        return true;
                }
            }
            catch { }
            return false;
        }

        /// <summary>Включённый системный прокси (HKCU\...\Internet Settings) или null.</summary>
        public static string GetSystemProxy()
        {
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Internet Settings"))
                {
                    if (k == null) return null;
                    object en = k.GetValue("ProxyEnable");
                    string srv = k.GetValue("ProxyServer") as string;
                    if (en != null && Convert.ToInt32(en) != 0 && !string.IsNullOrWhiteSpace(srv))
                        return srv;
                }
            }
            catch { }
            return null;
        }

        public static List<string> DescribeAdapters()
        {
            var list = new List<string>();
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    var ips = new List<string>();
                    try
                    {
                        foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                            ips.Add(ua.Address.ToString());
                    }
                    catch { }
                    list.Add(ni.OperationalStatus + " | " + ni.Name + " | " + ni.Description +
                             " | " + ni.NetworkInterfaceType + " | " + string.Join(", ", ips.ToArray()));
                }
            }
            catch (Exception ex) { list.Add("Ошибка: " + ex.Message); }
            return list;
        }
    }
}
