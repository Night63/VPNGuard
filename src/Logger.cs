using System;
using System.IO;

namespace VpnGuard
{
    public class Logger
    {
        private readonly string _logPath;
        private readonly object _lock = new object();

        public event Action<string> OnLog;

        public Logger()
        {
            _logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "VpnGuard.log");
            try
            {
                // не даём логу расти бесконечно
                var fi = new FileInfo(_logPath);
                if (fi.Exists && fi.Length > 5 * 1024 * 1024)
                {
                    var old = _logPath + ".old";
                    if (File.Exists(old)) File.Delete(old);
                    File.Move(_logPath, old);
                }
            }
            catch { }
        }

        public void Info(string message) { Write("INFO", message); }
        public void Warn(string message) { Write("WARN", message); }
        public void Error(string message) { Write("ERROR", message); }

        private void Write(string level, string message)
        {
            var line = "[" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "] [" + level + "] " + message;
            lock (_lock)
            {
                try { File.AppendAllText(_logPath, line + Environment.NewLine); }
                catch { }
            }
            var h = OnLog;
            if (h != null)
            {
                try { h(line); } catch { }
            }
        }
    }
}
