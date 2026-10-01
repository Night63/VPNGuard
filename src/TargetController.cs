using System;
using System.Diagnostics;

namespace VpnGuard
{
    public class TargetController
    {
        private readonly Config _cfg;
        private readonly Logger _log;

        public TargetController(Config cfg, Logger log)
        {
            _cfg = cfg;
            _log = log;
        }

        public bool IsRunning()
        {
            return VpnMonitor.IsProcessRunning(_cfg.GetTargetProcName());
        }

        public bool StartTarget()
        {
            try
            {
                string how = ProcessLauncher.Start(_cfg.TargetProcessPath, _cfg.TargetStartArgs, _cfg.LaunchUnelevated);
                _log.Info("Приложение запущено (" + how + "): " + _cfg.GetTargetProcName());
                return true;
            }
            catch (Exception ex)
            {
                _log.Error("Ошибка запуска приложения: " + ex.Message);
                return false;
            }
        }

        /// <summary>Завершает все процессы цели. Возвращает число завершённых.</summary>
        public int KillTarget()
        {
            int killed = 0;
            Process[] procs;
            try { procs = Process.GetProcessesByName(_cfg.GetTargetProcName()); }
            catch (Exception ex) { _log.Error("Ошибка поиска процесса: " + ex.Message); return 0; }

            foreach (var p in procs)
            {
                try
                {
                    p.Kill();
                    killed++;
                }
                catch (Exception ex)
                {
                    _log.Warn("Не удалось завершить процесс " + p.Id + ": " + ex.Message);
                }
            }
            foreach (var p in procs)
            {
                try { p.WaitForExit(2000); } catch { }
                p.Dispose();
            }
            if (killed > 0)
                _log.Warn("Приложение отключено (VPN не активен): " + _cfg.GetTargetProcName());
            return killed;
        }

        public void KillVpn()
        {
            try
            {
                foreach (var p in Process.GetProcessesByName(_cfg.GetVpnProcName()))
                {
                    try { p.Kill(); p.WaitForExit(3000); } catch { }
                    p.Dispose();
                }
            }
            catch (Exception ex) { _log.Error("Ошибка завершения VPN: " + ex.Message); }
        }

        public bool StartVpn()
        {
            try
            {
                string how = ProcessLauncher.Start(_cfg.VpnProcessPath, "", _cfg.LaunchUnelevated);
                _log.Info("Запущен VPN (" + how + "): " + _cfg.VpnProcessPath);
                return true;
            }
            catch (Exception ex)
            {
                _log.Error("Ошибка запуска VPN: " + ex.Message);
                return false;
            }
        }
    }
}
