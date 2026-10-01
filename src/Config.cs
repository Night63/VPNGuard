using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace VpnGuard
{
    public class Config
    {
        // --- VPN ---
        public string VpnProcessName = "Browsec";
        public string VpnProcessPath = "";
        public int VpnStartupWaitSec = 15;
        public bool KeepVpnRunning = true;          // запускать Browsec, если он закрыт

        // Как определять, что туннель поднят:
        //   auto    — сетевой адаптер ИЛИ системный прокси (рекомендуется)
        //   adapter — только сетевой адаптер VPN
        //   proxy   — только системный прокси Windows
        //   process — только наличие процесса (ненадёжно!)
        public string DetectionMode = "auto";
        public string VpnAdapterKeywords = "browbox,sing-tun,browsec,wintun,wireguard,tap-windows,openvpn";
        // Считать туннель активным, только если интернет-трафик реально идёт через адаптер VPN
        // (адаптер может оставаться «включённым» после отключения в окне Browsec)
        public bool RequireVpnRoute = true;

        // Автоподключение Browsec (нажатие кнопки в его окне через Accessibility)
        // Если в Browsec включено «Автоподключение VPN», это лучше оставить выключенным:
        // ползунок подключения в Browsec не подписан, и нажать его по имени нельзя.
        public bool AutoConnectVpn = false;
        // Перезапустить Browsec (чтобы сработало его автоподключение), если он запущен,
        // а туннель не поднят дольше N секунд. 0 — не перезапускать.
        public int VpnRestartIfDownSec = 0;
        public string ConnectButtonNames = "Connect,Подключить,Подключиться,Turn on,Включить,Start,Protect me";
        public int AutoConnectRetrySec = 20;

        // --- Целевое приложение ---
        public string TargetProcessName = "Telegram";
        public string TargetProcessPath = "";
        public string TargetStartArgs = "";
        public bool StartTargetOnLaunch = true;
        public bool AutoRestartTarget = true;

        // --- Поведение ---
        public int PollIntervalMs = 500;
        public bool UseProcessKill = true;
        public bool UseFirewallBlock = true;
        public bool LaunchUnelevated = true;        // запускать Telegram/Browsec БЕЗ прав администратора
        public bool NoUacLaunch = true;             // задача Планировщика: запуск VpnGuard без окна UAC
        public bool AutostartAtLogon = true;        // запуск VpnGuard при входе в Windows
        public string TaskSignature = "";

        // --- Окно VpnGuard ---
        public bool MinimizeToTray = true;          // сворачивать в трей после запуска приложения
        public int TrayDelayFirstSec = 10;          // через сколько секунд после первого запуска приложения
        public int TrayDelayAfterRestoreSec = 5;    // через сколько секунд после перезапуска (VPN восстановлен)
        public bool ShowOnVpnDrop = true;           // при обрыве VPN показывать окно поверх всех окон           // служебное: с какими параметрами уже создана задача

        private static string ConfigPath
        {
            get { return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "appsettings.json"); }
        }

        /// <summary>
        /// Имя процесса для поиска. Берётся из имени .exe в пути (terminal64.exe → terminal64),
        /// потому что «MetaTrader 5 Client Terminal» в Диспетчере задач — это описание, а не имя процесса.
        /// </summary>
        public string GetTargetProcName() { return ProcName(TargetProcessPath, TargetProcessName); }
        public string GetVpnProcName() { return ProcName(VpnProcessPath, VpnProcessName); }

        private static string ProcName(string path, string fallback)
        {
            try
            {
                if (!string.IsNullOrWhiteSpace(path))
                {
                    var n = Path.GetFileNameWithoutExtension(path.Trim().Trim('"'));
                    if (!string.IsNullOrWhiteSpace(n)) return n;
                }
            }
            catch { }
            var f = (fallback ?? "").Trim();
            if (f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) f = f.Substring(0, f.Length - 4);
            return f;
        }

        public string[] GetAdapterKeywords() { return Split(VpnAdapterKeywords); }
        public string[] GetConnectButtonNames() { return Split(ConnectButtonNames); }

        private static string[] Split(string s)
        {
            var list = new List<string>();
            foreach (var p in (s ?? "").Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var t = p.Trim();
                if (t.Length > 0) list.Add(t);
            }
            return list.ToArray();
        }

        public static Config Load()
        {
            var cfg = new Config();
            try
            {
                if (!File.Exists(ConfigPath)) { cfg.Save(); return cfg; }
                var json = File.ReadAllText(ConfigPath, Encoding.UTF8);
                var ser = new JavaScriptSerializer();
                var raw = ser.Deserialize<Dictionary<string, object>>(json);
                var dict = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
                foreach (var kv in raw) dict[kv.Key] = kv.Value;

                foreach (var f in typeof(Config).GetFields())
                {
                    object v;
                    if (!dict.TryGetValue(f.Name, out v) || v == null) continue;
                    try
                    {
                        if (f.FieldType == typeof(string)) f.SetValue(cfg, Convert.ToString(v));
                        else if (f.FieldType == typeof(int)) f.SetValue(cfg, Convert.ToInt32(v));
                        else if (f.FieldType == typeof(bool)) f.SetValue(cfg, Convert.ToBoolean(v));
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Ошибка чтения appsettings.json: " + ex.Message +
                    "\nБудут использованы настройки по умолчанию.",
                    "VpnGuard", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            if (cfg.PollIntervalMs < 200) cfg.PollIntervalMs = 200;
            if (cfg.TrayDelayFirstSec < 1) cfg.TrayDelayFirstSec = 1;
            if (cfg.TrayDelayAfterRestoreSec < 1) cfg.TrayDelayAfterRestoreSec = 1;
            // Пути могут содержать переменные окружения: %LOCALAPPDATA%, %APPDATA%, %USERPROFILE%...
            cfg.VpnProcessPath = Environment.ExpandEnvironmentVariables(cfg.VpnProcessPath ?? "");
            cfg.TargetProcessPath = Environment.ExpandEnvironmentVariables(cfg.TargetProcessPath ?? "");
            if (cfg.AutoConnectRetrySec < 5) cfg.AutoConnectRetrySec = 5;
            return cfg;
        }

        public void Save()
        {
            try
            {
                var sb = new StringBuilder();
                sb.Append("{\r\n");
                var fields = typeof(Config).GetFields();
                for (int i = 0; i < fields.Length; i++)
                {
                    var f = fields[i];
                    object v = f.GetValue(this);
                    string sv;
                    if (v is string) sv = JsonString((string)v);
                    else if (v is bool) sv = ((bool)v) ? "true" : "false";
                    else sv = Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture);
                    sb.Append("  \"").Append(f.Name).Append("\": ").Append(sv);
                    if (i < fields.Length - 1) sb.Append(",");
                    sb.Append("\r\n");
                }
                sb.Append("}\r\n");
                File.WriteAllText(ConfigPath, sb.ToString(), new UTF8Encoding(false));
            }
            catch (Exception ex)
            {
                MessageBox.Show("Ошибка сохранения appsettings.json: " + ex.Message,
                    "VpnGuard", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private static string JsonString(string s)
        {
            var sb = new StringBuilder("\"");
            foreach (char c in s ?? "")
            {
                switch (c)
                {
                    case '\\': sb.Append("\\\\"); break;
                    case '"': sb.Append("\\\""); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
                        else sb.Append(c);
                        break;
                }
            }
            return sb.Append("\"").ToString();
        }
    }
}
