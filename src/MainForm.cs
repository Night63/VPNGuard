using System;
using System.Drawing;
using System.IO;
using System.Threading;
using System.Windows.Forms;

namespace VpnGuard
{
    public class MainForm : Form
    {
        private readonly Config _cfg;
        private readonly Logger _log;
        private readonly VpnMonitor _vpn;
        private readonly TargetController _target;
        private readonly FirewallBlocker _firewall;

        private Label lblVpn;
        private Label lblTarget;
        private ListBox lstLog;
        private Button btnSettings;
        private Button btnToggle;
        private Button btnExit;
        private NotifyIcon tray;

        // Состояние (меняется только в UI-потоке)
        private bool _running = true;
        private bool? _lastTunnelUp;          // null — ещё не было ни одной проверки
        private bool _pendingTargetStart;     // запустить Telegram, как только поднимется туннель
        private volatile VpnState _latestState;
        private DateTime _lastVpnLaunch = DateTime.MinValue;
        private DateTime _downSince = DateTime.MaxValue;   // с какого момента VPN-программа запущена, а туннеля нет
        private System.Windows.Forms.Timer _trayTimer;     // отложенное сворачивание в трей
        private bool _targetStartedOnce;                   // приложение уже запускалось (для задержки 10/5 сек)
        private DateTime _lastConnectAttempt = DateTime.MinValue;
        private int _connectInProgress;
        private bool _pollQueued;
        private string _lastReason = "";

        private readonly EventWaitHandle _showEvent;

        public MainForm(EventWaitHandle showEvent)
        {
            _showEvent = showEvent;
            _cfg = Config.Load();
            _log = new Logger();
            _vpn = new VpnMonitor(_cfg, _log);
            _target = new TargetController(_cfg, _log);
            _firewall = new FirewallBlocker(_log);

            BuildUi();
            _log.OnLog += AppendLog;
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);

            _log.Info(AppInfo.NameWithVersion + " запущен. Процесс VPN: " + _cfg.GetVpnProcName() + ", процесс приложения: " + _cfg.GetTargetProcName() +
                      ", режим проверки: " + _cfg.DetectionMode +
                      (ProcessLauncher.IsElevated() ? " (права администратора есть)" : " (БЕЗ прав администратора — Firewall недоступен)"));

            // Удаляем правила Firewall, которые могли остаться от старой версии или после аварийного завершения
            int removed = FirewallBlocker.RemoveRules();
            if (removed > 0) _log.Warn("Удалены оставшиеся правила блокировки Firewall (" + removed + ")");

            _log.Info("Сетевые адаптеры:");
            foreach (var a in VpnMonitor.DescribeAdapters()) _log.Info("   " + a);
            _log.Info("Интернет-трафик сейчас идёт через: " + VpnMonitor.BestInterfaceName() +
                      "; системный прокси: " + (VpnMonitor.GetSystemProxy() ?? "выключен"));

            if (!File.Exists(_cfg.TargetProcessPath))
                _log.Error("Не найден файл приложения: " + _cfg.TargetProcessPath + " — укажи путь в настройках");
            if (!File.Exists(_cfg.VpnProcessPath))
                _log.Error("Не найден файл VPN: " + _cfg.VpnProcessPath + " — укажи путь в настройках");

            ApplyTaskSetup();
            StartShowListener();

            _pendingTargetStart = _cfg.StartTargetOnLaunch;
            _vpn.OnPoll += OnPollFromMonitor;
            _vpn.Start();
        }

        // Вызывается из потока таймера — переносим в UI-поток, не накапливая очередь
        private void OnPollFromMonitor(VpnState st)
        {
            if (IsDisposed || !IsHandleCreated) return;
            _latestState = st;
            lock (this)
            {
                if (_pollQueued) return;
                _pollQueued = true;
            }
            try
            {
                BeginInvoke(new Action(delegate
                {
                    lock (this) { _pollQueued = false; }
                    HandleState(_latestState);
                }));
            }
            catch { lock (this) { _pollQueued = false; } }
        }

        private void HandleState(VpnState st)
        {
            if (!_running) return;

            bool up = st.TunnelUp;
            bool changed = !_lastTunnelUp.HasValue || _lastTunnelUp.Value != up;

            if (changed || st.Reason != _lastReason)
            {
                if (up) _log.Info("VPN АКТИВЕН — " + st.Reason);
                else _log.Warn("VPN НЕ АКТИВЕН — " + st.Reason);
                _lastReason = st.Reason;
            }

            if (!up && changed && _lastTunnelUp.HasValue && _lastTunnelUp.Value)
                OnVpnDropped();
            else if (up && changed)
                OnVpnRestored();

            if (!up)
            {
                // 1) Немедленно отключаем приложение — и продолжаем следить,
                //    чтобы его нельзя было открыть вручную, пока VPN не поднят.
                if (_cfg.UseProcessKill && _target.IsRunning())
                {
                    if (_target.KillTarget() > 0 && _cfg.AutoRestartTarget)
                        _pendingTargetStart = true;
                }
                // 2) Страховка через Firewall
                if (changed && _cfg.UseFirewallBlock && ProcessLauncher.IsElevated())
                    _firewall.Block(_cfg.TargetProcessPath);

                // 3) Запускаем Browsec, если он закрыт
                if (!st.ProcessRunning && _cfg.KeepVpnRunning &&
                    (DateTime.Now - _lastVpnLaunch).TotalSeconds > Math.Max(_cfg.VpnStartupWaitSec, 10))
                {
                    _lastVpnLaunch = DateTime.Now;
                    _log.Info("VPN не запущен — запускаю " + _cfg.VpnProcessPath);
                    _target.StartVpn();
                }

                // 4) Пытаемся нажать «Подключить» в Browsec
                if (st.ProcessRunning && _cfg.AutoConnectVpn)
                    TryAutoConnect();

                // 5) Browsec запущен, но туннель долго не поднимается — перезапускаем Browsec,
                //    чтобы сработало его собственное «Автоподключение VPN»
                if (st.ProcessRunning)
                {
                    if (_downSince == DateTime.MaxValue) _downSince = DateTime.Now;
                    double downSec = (DateTime.Now - _downSince).TotalSeconds;
                    double sinceLaunch = (DateTime.Now - _lastVpnLaunch).TotalSeconds;
                    if (_cfg.VpnRestartIfDownSec > 0 && downSec >= _cfg.VpnRestartIfDownSec &&
                        sinceLaunch >= Math.Max(_cfg.VpnRestartIfDownSec, _cfg.VpnStartupWaitSec))
                    {
                        _log.Warn("Туннель не поднят " + (int)downSec + " сек — перезапускаю " + _cfg.GetVpnProcName());
                        _target.KillVpn();
                        _lastVpnLaunch = DateTime.Now;
                        _downSince = DateTime.MaxValue;
                        _target.StartVpn();
                    }
                }
                else _downSince = DateTime.MaxValue;
            }
            else if (changed)
            {
                _downSince = DateTime.MaxValue;
                if (_firewall.IsBlocked || _lastTunnelUp.HasValue) _firewall.Unblock();
            }

            if (up && _pendingTargetStart && !_target.IsRunning())
            {
                _pendingTargetStart = false;
                if (_target.StartTarget())
                {
                    ScheduleTray(_targetStartedOnce ? _cfg.TrayDelayAfterRestoreSec : _cfg.TrayDelayFirstSec);
                    _targetStartedOnce = true;
                }
            }
            else if (up && _pendingTargetStart)
            {
                _pendingTargetStart = false; // уже запущен вручную
                ScheduleTray(_targetStartedOnce ? _cfg.TrayDelayAfterRestoreSec : _cfg.TrayDelayFirstSec);
                _targetStartedOnce = true;
            }

            _lastTunnelUp = up;
            UpdateStatus(st);
        }

        // ---------- Окно и трей ----------

        private void OnVpnDropped()
        {
            if (_trayTimer != null) _trayTimer.Stop();
            if (tray != null)
            {
                try { tray.ShowBalloonTip(5000, AppInfo.NameWithVersion, "Обрыв VPN! Приложение отключено.", ToolTipIcon.Warning); }
                catch { }
            }
            if (_cfg.ShowOnVpnDrop)
            {
                ShowFromTray();
                TopMost = true;   // остаётся поверх всех окон, пока VPN не восстановится
            }
        }

        private void OnVpnRestored()
        {
            if (TopMost) TopMost = false;
        }

        /// <summary>Свернуть окно в трей через N секунд (если включено в настройках).</summary>
        private void ScheduleTray(int seconds)
        {
            if (!_cfg.MinimizeToTray) return;
            if (_trayTimer == null)
            {
                _trayTimer = new System.Windows.Forms.Timer();
                _trayTimer.Tick += delegate
                {
                    _trayTimer.Stop();
                    // сворачиваем, только если VPN всё ещё в порядке
                    if (_running && _lastTunnelUp.HasValue && _lastTunnelUp.Value && Visible)
                    {
                        TopMost = false;
                        Hide();
                        _log.Info("Окно свёрнуто в трей (двойной щелчок по значку — открыть)");
                    }
                };
            }
            _trayTimer.Stop();
            _trayTimer.Interval = Math.Max(1, seconds) * 1000;
            _trayTimer.Start();
        }

        private void ApplyTaskSetup()
        {
            if (!ProcessLauncher.IsElevated()) return;
            string sig = "v2|" + Application.ExecutablePath + "|" + _cfg.NoUacLaunch + "|" + _cfg.AutostartAtLogon;
            if (sig == _cfg.TaskSignature) return; // задача уже настроена именно так
            if (TaskSetup.Apply(_cfg.NoUacLaunch, _cfg.NoUacLaunch && _cfg.AutostartAtLogon, _log))
            {
                _cfg.TaskSignature = sig;
                _cfg.Save();
            }
        }

        // Повторный запуск VpnGuard (двойной щелчок по exe) просто показывает это окно
        private void StartShowListener()
        {
            if (_showEvent == null) return;
            var t = new Thread(delegate()
            {
                while (true)
                {
                    try { _showEvent.WaitOne(); }
                    catch { return; }
                    if (IsDisposed) return;
                    try { BeginInvoke(new Action(ShowFromTray)); } catch { return; }
                }
            });
            t.IsBackground = true;
            t.Start();
        }

        private void ShowFromTray()
        {
            Show();
            if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal;
            TopMost = true;
            Activate();
            TopMost = false;
        }

        private void TryAutoConnect()
        {
            // Даём Browsec время запуститься и не нажимаем кнопку слишком часто
            if ((DateTime.Now - _lastVpnLaunch).TotalSeconds < _cfg.VpnStartupWaitSec) return;
            if ((DateTime.Now - _lastConnectAttempt).TotalSeconds < _cfg.AutoConnectRetrySec) return;
            if (Interlocked.Exchange(ref _connectInProgress, 1) == 1) return;
            _lastConnectAttempt = DateTime.Now;

            string proc = _cfg.GetVpnProcName();
            string[] names = _cfg.GetConnectButtonNames();
            var t = new Thread(delegate()
            {
                try
                {
                    string res;
                    bool ok = BrowsecAutomation.TryClickConnect(proc, names, out res);
                    if (ok) _log.Info("Автоподключение VPN: " + res);
                    else _log.Warn("Автоподключение VPN: " + res);
                }
                catch (Exception ex) { _log.Error("Автоподключение VPN: " + ex.Message); }
                finally { Interlocked.Exchange(ref _connectInProgress, 0); }
            });
            t.IsBackground = true;
            t.SetApartmentState(ApartmentState.STA);
            t.Start();
        }

        private void UpdateStatus(VpnState st)
        {
            bool targetUp = _target.IsRunning();

            if (!_running)
            {
                lblVpn.Text = "Мониторинг на паузе";
                lblVpn.ForeColor = Color.DarkOrange;
                lblTarget.Text = "Приложение: без контроля";
                lblTarget.ForeColor = Color.DarkOrange;
                return;
            }

            lblVpn.Text = st.TunnelUp ? "VPN: ПОДКЛЮЧЁН ✔" : "VPN: ОТКЛЮЧЁН ✘";
            lblVpn.ForeColor = st.TunnelUp ? Color.Green : Color.Red;

            if (!st.TunnelUp)
            {
                lblTarget.Text = targetUp ? "Приложение: останавливается..." : "Приложение: ЗАБЛОКИРОВАНО (VPN отключён) ✘";
                lblTarget.ForeColor = targetUp ? Color.DarkOrange : Color.Red;
            }
            else
            {
                lblTarget.Text = targetUp ? "Приложение: РАБОТАЕТ ✔" : "Приложение: не запущено";
                lblTarget.ForeColor = targetUp ? Color.Green : Color.DarkOrange;
            }
            if (tray != null)
            {
                string t = AppInfo.NameWithVersion + ": " + (st.TunnelUp ? "VPN подключён" : "VPN отключён");
                tray.Text = t.Length > 63 ? t.Substring(0, 63) : t;
            }
        }

        private void BuildUi()
        {
            Text = AppInfo.NameWithVersion + " — контроль VPN";
            Width = 720;
            Height = 480;
            StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(560, 380);
            Font = new Font("Segoe UI", 9.5f);
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }

            lblVpn = new Label();
            lblVpn.SetBounds(15, 15, 670, 28);
            lblVpn.Font = new Font("Segoe UI", 11f, FontStyle.Bold);
            lblVpn.Text = "VPN: проверка...";
            lblVpn.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;

            lblTarget = new Label();
            lblTarget.SetBounds(15, 50, 670, 28);
            lblTarget.Font = new Font("Segoe UI", 11f, FontStyle.Bold);
            lblTarget.Text = "Приложение: проверка...";
            lblTarget.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;

            lstLog = new ListBox();
            lstLog.SetBounds(15, 90, 670, 290);
            lstLog.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom;
            lstLog.HorizontalScrollbar = true;
            lstLog.IntegralHeight = false;

            btnSettings = new Button();
            btnSettings.SetBounds(15, 395, 140, 32);
            btnSettings.Text = "Настройки";
            btnSettings.Anchor = AnchorStyles.Left | AnchorStyles.Bottom;
            btnSettings.Click += delegate { OpenSettings(); };

            btnToggle = new Button();
            btnToggle.SetBounds(165, 395, 160, 32);
            btnToggle.Text = "Пауза";
            btnToggle.Anchor = AnchorStyles.Left | AnchorStyles.Bottom;
            btnToggle.Click += delegate { ToggleMonitoring(); };

            btnExit = new Button();
            btnExit.SetBounds(545, 395, 140, 32);
            btnExit.Text = "Выход";
            btnExit.Anchor = AnchorStyles.Right | AnchorStyles.Bottom;
            btnExit.Click += delegate { Close(); };

            Controls.Add(lblVpn);
            Controls.Add(lblTarget);
            Controls.Add(lstLog);
            Controls.Add(btnSettings);
            Controls.Add(btnToggle);
            Controls.Add(btnExit);

            // Значок в трее: при сворачивании окно прячется туда
            tray = new NotifyIcon();
            tray.Icon = SystemIcons.Shield;
            tray.Text = AppInfo.NameWithVersion;
            tray.Visible = true;
            tray.DoubleClick += delegate { ShowFromTray(); };
            var menu = new ContextMenuStrip();
            menu.Items.Add("Открыть", null, delegate { ShowFromTray(); });
            menu.Items.Add("Выход", null, delegate { Close(); });
            tray.ContextMenuStrip = menu;
        }

        protected override void OnResize(EventArgs e)
        {
            base.OnResize(e);
            if (WindowState == FormWindowState.Minimized && tray != null) Hide();
        }

        private void AppendLog(string line)
        {
            if (IsDisposed || !IsHandleCreated) return;
            if (InvokeRequired)
            {
                try { BeginInvoke(new Action<string>(AppendLog), line); } catch { }
                return;
            }
            lstLog.Items.Add(line);
            if (lstLog.Items.Count > 1000) lstLog.Items.RemoveAt(0);
            lstLog.TopIndex = lstLog.Items.Count - 1;
        }

        private void OpenSettings()
        {
            using (var sf = new SettingsForm(_cfg, _log))
            {
                if (sf.ShowDialog(this) == DialogResult.OK)
                {
                    _cfg.Save();
                    _log.Info("Настройки сохранены. Процесс приложения: " + _cfg.GetTargetProcName() +
                              ", процесс VPN: " + _cfg.GetVpnProcName());
                    ApplyTaskSetup();
                    MessageBox.Show(this, "Настройки сохранены.\nПерезапусти VpnGuard, чтобы применить все изменения.",
                        "VpnGuard", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
        }

        private void ToggleMonitoring()
        {
            _running = !_running;
            btnToggle.Text = _running ? "Пауза" : "Продолжить";
            if (_running)
            {
                _lastTunnelUp = null;
                _lastReason = "";
                _vpn.Start();
                _log.Info("Мониторинг возобновлён.");
            }
            else
            {
                _vpn.Stop();
                if (_firewall.IsBlocked) _firewall.Unblock();
                _log.Warn("Мониторинг приостановлен — приложение работает без контроля VPN!");
                UpdateStatus(new VpnState());
            }
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            _vpn.Stop();
            FirewallBlocker.RemoveRules();
            _log.Info("VpnGuard завершён, правила Firewall удалены.");
            if (tray != null) { tray.Visible = false; tray.Dispose(); tray = null; }
            base.OnFormClosing(e);
        }
    }
}
