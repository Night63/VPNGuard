using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Windows.Forms;

namespace VpnGuard
{
    internal static class Program
    {
        private const string MutexName = "Local\\VpnGuard_SingleInstance";
        public const string ShowEventName = "Local\\VpnGuard_ShowWindow";

        [STAThread]
        private static int Main(string[] args)
        {
            bool cleanup = false;
            foreach (var a in args)
                if (string.Equals(a, "--cleanup", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(a, "/cleanup", StringComparison.OrdinalIgnoreCase)) cleanup = true;

            // ---------- Запуск без прав администратора (обычный двойной щелчок) ----------
            if (!ProcessLauncher.IsElevated())
            {
                if (cleanup) { RelaunchElevated("--cleanup"); return 0; }

                // 1) VpnGuard уже работает — просто показываем его окно
                if (SignalExistingInstance()) return 0;

                // 2) Есть задача Планировщика — запускаем через неё: окна UAC не будет
                if (TaskSetup.RunTask() && WaitForInstance(8000)) return 0;

                // 3) Задачи нет (первый запуск) — обычный запрос прав администратора
                RelaunchElevated("");
                return 0;
            }

            // ---------- Мы уже с правами администратора ----------
            if (cleanup)
            {
                int n = FirewallBlocker.RemoveRules();
                MessageBox.Show(n > 0 ? "Правила блокировки VpnGuard удалены из Windows Firewall."
                                      : "Правил VpnGuard в Windows Firewall не найдено.",
                    "VpnGuard", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return 0;
            }

            bool createdNew;
            using (var mutex = new Mutex(true, MutexName, out createdNew))
            {
                if (!createdNew)
                {
                    SignalExistingInstance();
                    return 1;
                }

                using (var showEvent = CreateShowEvent())
                {
                    AppDomain.CurrentDomain.UnhandledException += delegate { FirewallBlocker.RemoveRules(); };
                    Application.ThreadException += delegate(object s, ThreadExceptionEventArgs e)
                    {
                        MessageBox.Show("Ошибка: " + e.Exception.Message, "VpnGuard", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    };
                    Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);

                    Application.EnableVisualStyles();
                    Application.SetCompatibleTextRenderingDefault(false);
                    Application.Run(new MainForm(showEvent));
                }
                GC.KeepAlive(mutex);
            }
            return 0;
        }

        /// <summary>Событие «покажи окно», которое может выставить и необлагороженный процесс.</summary>
        private static EventWaitHandle CreateShowEvent()
        {
            try
            {
                var sec = new EventWaitHandleSecurity();
                sec.AddAccessRule(new EventWaitHandleAccessRule(
                    new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                    EventWaitHandleRights.Synchronize | EventWaitHandleRights.Modify,
                    AccessControlType.Allow));
                sec.AddAccessRule(new EventWaitHandleAccessRule(
                    new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                    EventWaitHandleRights.FullControl, AccessControlType.Allow));
                bool created;
                return new EventWaitHandle(false, EventResetMode.AutoReset, ShowEventName, out created, sec);
            }
            catch
            {
                return new EventWaitHandle(false, EventResetMode.AutoReset, ShowEventName);
            }
        }

        private static bool SignalExistingInstance()
        {
            try
            {
                using (var ev = EventWaitHandle.OpenExisting(ShowEventName,
                    EventWaitHandleRights.Synchronize | EventWaitHandleRights.Modify))
                {
                    ev.Set();
                    return true;
                }
            }
            catch { return false; }
        }

        /// <summary>Ждём, пока запущенная задачей копия VpnGuard создаст своё событие.</summary>
        private static bool WaitForInstance(int timeoutMs)
        {
            var sw = Stopwatch.StartNew();
            while (sw.ElapsedMilliseconds < timeoutMs)
            {
                try
                {
                    using (EventWaitHandle.OpenExisting(ShowEventName, EventWaitHandleRights.Synchronize))
                        return true;
                }
                catch (UnauthorizedAccessException) { return true; } // существует, но нет доступа
                catch { }
                Thread.Sleep(200);
            }
            return false;
        }

        private static void RelaunchElevated(string args)
        {
            try
            {
                var psi = new ProcessStartInfo(Application.ExecutablePath, args);
                psi.UseShellExecute = true;
                psi.Verb = "runas";
                Process.Start(psi);
            }
            catch (Win32Exception)
            {
                // пользователь нажал «Нет» в окне UAC
            }
            catch (Exception ex)
            {
                MessageBox.Show("Не удалось запустить VpnGuard с правами администратора: " + ex.Message,
                    "VpnGuard", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}
