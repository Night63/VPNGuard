using System;
using System.Diagnostics;
using System.IO;
using System.Security;
using System.Security.Principal;
using System.Text;

namespace VpnGuard
{
    /// <summary>
    /// Задача Планировщика Windows «VpnGuard» с наивысшими правами.
    /// Запуск через неё не показывает окно UAC — им пользуется и автозапуск при входе,
    /// и обычный двойной щелчок по VpnGuard.exe (см. Program.cs).
    /// </summary>
    public static class TaskSetup
    {
        public const string TaskName = "VpnGuard";

        /// <summary>Создаёт/обновляет (или удаляет) задачу. Требует прав администратора.</summary>
        public static bool Apply(bool enabled, bool atLogon, Logger log)
        {
            if (!enabled)
            {
                if (Schtasks("/delete /tn \"" + TaskName + "\" /f"))
                    log.Info("Задача Планировщика «" + TaskName + "» удалена");
                return true;
            }

            string exe = Process.GetCurrentProcess().MainModule.FileName;
            string dir = Path.GetDirectoryName(exe);
            string user;
            using (var id = WindowsIdentity.GetCurrent()) user = id.Name;

            var x = new StringBuilder();
            x.AppendLine("<?xml version=\"1.0\" encoding=\"UTF-16\"?>");
            x.AppendLine("<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">");
            x.AppendLine("  <RegistrationInfo><Description>VpnGuard: контроль VPN (создано автоматически)</Description></RegistrationInfo>");
            if (atLogon)
            {
                x.AppendLine("  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>" + Esc(user) +
                             "</UserId><Delay>PT15S</Delay></LogonTrigger></Triggers>");
            }
            x.AppendLine("  <Principals><Principal id=\"Author\"><UserId>" + Esc(user) +
                         "</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>");
            x.AppendLine("  <Settings>");
            x.AppendLine("    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>");
            x.AppendLine("    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>");
            x.AppendLine("    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>");
            x.AppendLine("    <AllowHardTerminate>true</AllowHardTerminate>");
            x.AppendLine("    <StartWhenAvailable>false</StartWhenAvailable>");
            x.AppendLine("    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>");
            x.AppendLine("    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>");
            x.AppendLine("    <AllowStartOnDemand>true</AllowStartOnDemand>");
            x.AppendLine("    <Enabled>true</Enabled>");
            x.AppendLine("    <Hidden>false</Hidden>");
            x.AppendLine("    <RunOnlyIfIdle>false</RunOnlyIfIdle>");
            x.AppendLine("    <WakeToRun>false</WakeToRun>");
            x.AppendLine("    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>");
            x.AppendLine("    <Priority>4</Priority>");
            x.AppendLine("  </Settings>");
            x.AppendLine("  <Actions Context=\"Author\"><Exec><Command>\"" + Esc(exe) + "\"</Command><WorkingDirectory>" +
                         Esc(dir) + "</WorkingDirectory></Exec></Actions>");
            x.AppendLine("</Task>");

            string tmp = Path.Combine(Path.GetTempPath(), "VpnGuard_task.xml");
            try
            {
                File.WriteAllText(tmp, x.ToString(), Encoding.Unicode);
                bool ok = Schtasks("/create /tn \"" + TaskName + "\" /xml \"" + tmp + "\" /f");
                if (ok) log.Info("Задача Планировщика «" + TaskName + "» настроена: запуск без UAC" +
                                 (atLogon ? ", автозапуск при входе в Windows" : ", без автозапуска"));
                else log.Error("Не удалось создать задачу Планировщика «" + TaskName + "»");
                return ok;
            }
            catch (Exception ex)
            {
                log.Error("Ошибка настройки Планировщика: " + ex.Message);
                return false;
            }
            finally
            {
                try { File.Delete(tmp); } catch { }
            }
        }

        /// <summary>Запускает задачу (работает и без прав администратора).</summary>
        public static bool RunTask()
        {
            return Schtasks("/run /tn \"" + TaskName + "\"");
        }

        private static string Esc(string s) { return SecurityElement.Escape(s ?? ""); }

        private static bool Schtasks(string args)
        {
            try
            {
                var psi = new ProcessStartInfo("schtasks.exe", args);
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
            catch { return false; }
        }
    }
}
