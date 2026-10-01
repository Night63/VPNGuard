using System;
using System.Diagnostics;

namespace VpnGuard
{
    /// <summary>
    /// Блокировка приложения через Windows Firewall.
    /// Работает через netsh: "delete rule name=..." гарантированно удаляет ВСЕ правила
    /// с этим именем (в старой версии удаление через COM не работало вообще,
    /// и правила оставались навсегда — из-за этого Telegram переставал работать).
    /// </summary>
    public class FirewallBlocker
    {
        public const string RuleName = "VpnGuard_Block_Target";
        public const string RuleNameIn = "VpnGuard_Block_Target_IN";

        private readonly Logger _log;
        private bool _blocked;

        public FirewallBlocker(Logger log) { _log = log; }

        public bool IsBlocked { get { return _blocked; } }

        public void Block(string exePath)
        {
            if (string.IsNullOrWhiteSpace(exePath)) return;
            RemoveRules();
            bool ok1 = Netsh("advfirewall firewall add rule name=\"" + RuleName +
                "\" dir=out action=block enable=yes profile=any program=\"" + exePath + "\"");
            bool ok2 = Netsh("advfirewall firewall add rule name=\"" + RuleNameIn +
                "\" dir=in action=block enable=yes profile=any program=\"" + exePath + "\"");
            _blocked = ok1 || ok2;
            if (ok1 && ok2) _log.Info("Firewall: сеть для приложения заблокирована");
            else _log.Error("Firewall: не удалось установить правило блокировки");
        }

        public void Unblock()
        {
            RemoveRules();
            if (_blocked) _log.Info("Firewall: блокировка снята");
            _blocked = false;
        }

        /// <summary>Удаляет правила VpnGuard (в т.ч. оставшиеся от старой версии).</summary>
        public static int RemoveRules()
        {
            int removed = 0;
            if (Netsh("advfirewall firewall delete rule name=\"" + RuleName + "\"")) removed++;
            if (Netsh("advfirewall firewall delete rule name=\"" + RuleNameIn + "\"")) removed++;
            return removed;
        }

        private static bool Netsh(string args)
        {
            try
            {
                var psi = new ProcessStartInfo("netsh.exe", args);
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                using (var p = Process.Start(psi))
                {
                    p.StandardOutput.ReadToEnd();
                    p.StandardError.ReadToEnd();
                    if (!p.WaitForExit(15000)) { try { p.Kill(); } catch { } return false; }
                    return p.ExitCode == 0;
                }
            }
            catch
            {
                return false;
            }
        }
    }
}
