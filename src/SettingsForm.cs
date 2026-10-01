using System;
using System.Drawing;
using System.Windows.Forms;

namespace VpnGuard
{
    public class SettingsForm : Form
    {
        private readonly Config _cfg;
        private readonly Logger _log;

        private TextBox tbVpnName, tbVpnPath, tbKeywords, tbButtons, tbTargetName, tbTargetPath, tbTargetArgs;
        private ComboBox cbMode;
        private NumericUpDown numPoll, numVpnWait, numVpnRestart;
        private CheckBox cbKeepVpn, cbAutoConnect, cbStartOnLaunch, cbAutoRestart, cbFirewall, cbKill, cbUnelevated, cbNoUac, cbAutostart, cbTray, cbShowOnDrop;

        private int _y = 12;
        private const int LX = 12, TX = 300, TW = 400;

        public SettingsForm(Config cfg, Logger log)
        {
            _cfg = cfg;
            _log = log;
            BuildUi();
            LoadValues();
        }

        private TextBox AddText(string label, bool browse)
        {
            Controls.Add(MakeLabel(label));
            var tb = new TextBox();
            tb.SetBounds(TX, _y, browse ? TW - 40 : TW, 24);
            Controls.Add(tb);
            if (browse)
            {
                var b = new Button();
                b.SetBounds(TX + TW - 36, _y - 1, 36, 26);
                b.Text = "...";
                b.Click += delegate
                {
                    using (var ofd = new OpenFileDialog())
                    {
                        ofd.Filter = "Программы (*.exe)|*.exe";
                        try { ofd.FileName = tb.Text; } catch { }
                        if (ofd.ShowDialog(this) == DialogResult.OK) tb.Text = ofd.FileName;
                    }
                };
                Controls.Add(b);
            }
            _y += 30;
            return tb;
        }

        private Label MakeLabel(string text)
        {
            var l = new Label();
            l.SetBounds(LX, _y + 3, TX - LX - 6, 22);
            l.Text = text;
            return l;
        }

        private NumericUpDown AddNum(string label, int min, int max, int inc)
        {
            Controls.Add(MakeLabel(label));
            var n = new NumericUpDown();
            n.SetBounds(TX, _y, 100, 24);
            n.Minimum = min; n.Maximum = max; n.Increment = inc;
            Controls.Add(n);
            _y += 30;
            return n;
        }

        private CheckBox AddCheck(string text)
        {
            var c = new CheckBox();
            c.SetBounds(TX, _y, TW, 22);
            c.Text = text;
            Controls.Add(c);
            _y += 24;
            return c;
        }

        private void AddHeader(string text)
        {
            var l = new Label();
            l.SetBounds(LX, _y + 4, TX + TW - LX, 20);
            l.Font = new Font(Font, FontStyle.Bold);
            l.Text = text;
            Controls.Add(l);
            _y += 26;
        }

        private void BuildUi()
        {
            Text = "Настройки " + AppInfo.NameWithVersion;
            StartPosition = FormStartPosition.CenterParent;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            Font = new Font("Segoe UI", 9f);
            AutoScroll = true;

            AddHeader("Ваш VPN");
            tbVpnPath = AddText("Путь к VPN .exe:", true);
            tbVpnName = AddText("Имя процесса (по пути):", false);
            tbVpnName.ReadOnly = true;
            tbVpnPath.TextChanged += delegate { tbVpnName.Text = ProcNameFromPath(tbVpnPath.Text, _cfg.VpnProcessName); };
            numVpnWait = AddNum("Ожидание старта VPN, сек:", 1, 120, 1);

            Controls.Add(MakeLabel("Как проверять туннель:"));
            cbMode = new ComboBox();
            cbMode.SetBounds(TX, _y, TW, 24);
            cbMode.DropDownStyle = ComboBoxStyle.DropDownList;
            cbMode.Items.AddRange(new object[] {
                "auto — адаптер VPN или системный прокси",
                "adapter — только адаптер VPN",
                "proxy — только системный прокси",
                "process — только процесс (ненадёжно)" });
            Controls.Add(cbMode);
            _y += 30;

            tbKeywords = AddText("Ключевые слова адаптера:", false);
            tbButtons = AddText("Кнопка «Подключить» в VPN:", false);
            cbKeepVpn = AddCheck("Запускать VPN-программу, если она закрыта");
            cbAutoConnect = AddCheck("Нажимать кнопку подключения в VPN (если она подписана)");
            numVpnRestart = AddNum("Перезапуск VPN без туннеля, сек (0 — выкл):", 0, 3600, 10);

            var bAdapters = new Button();
            bAdapters.SetBounds(TX, _y + 2, 195, 28);
            bAdapters.Text = "Сетевые адаптеры...";
            bAdapters.Click += delegate { ShowAdapters(); };
            Controls.Add(bAdapters);
            var bDump = new Button();
            bDump.SetBounds(TX + 205, _y + 2, 195, 28);
            bDump.Text = "Элементы окна VPN...";
            bDump.Click += delegate { ShowBrowsecTree(); };
            Controls.Add(bDump);
            _y += 38;

            AddHeader("Ваше приложение");
            tbTargetPath = AddText("Путь к .exe:", true);
            tbTargetName = AddText("Имя процесса (по пути):", false);
            tbTargetName.ReadOnly = true;
            tbTargetPath.TextChanged += delegate { tbTargetName.Text = ProcNameFromPath(tbTargetPath.Text, _cfg.TargetProcessName); };
            tbTargetArgs = AddText("Аргументы запуска:", false);
            cbStartOnLaunch = AddCheck("Запускать при старте VpnGuard (когда VPN активен)");
            cbAutoRestart = AddCheck("Перезапускать после восстановления VPN");

            AddHeader("Защита");
            numPoll = AddNum("Интервал опроса, мс:", 200, 10000, 100);
            cbKill = AddCheck("Завершать приложение при обрыве VPN");
            cbFirewall = AddCheck("Блокировать через Windows Firewall (страховка)");
            cbUnelevated = AddCheck("Запускать программы без прав администратора");

            AddHeader("Запуск и окно VpnGuard");
            cbNoUac = AddCheck("Запускать без окна подтверждения UAC (через Планировщик)");
            cbAutostart = AddCheck("Запускать при входе в Windows");
            cbNoUac.CheckedChanged += delegate { cbAutostart.Enabled = cbNoUac.Checked; };
            cbTray = AddCheck("После запуска приложения сворачивать в трей");
            cbShowOnDrop = AddCheck("При обрыве VPN показывать окно поверх всех окон");

            _y += 10;
            var btnOk = new Button();
            btnOk.SetBounds(TX + TW - 190, _y, 90, 30);
            btnOk.Text = "OK";
            btnOk.DialogResult = DialogResult.OK;
            btnOk.Click += delegate { SaveValues(); };
            var btnCancel = new Button();
            btnCancel.SetBounds(TX + TW - 90, _y, 90, 30);
            btnCancel.Text = "Отмена";
            btnCancel.DialogResult = DialogResult.Cancel;
            Controls.Add(btnOk);
            Controls.Add(btnCancel);
            AcceptButton = btnOk;
            CancelButton = btnCancel;

            ClientSize = new Size(TX + TW + 16, Math.Min(_y + 44, 860));
        }

        private static readonly string[] Modes = { "auto", "adapter", "proxy", "process" };

        private void LoadValues()
        {
            tbVpnName.Text = _cfg.VpnProcessName;
            tbVpnPath.Text = _cfg.VpnProcessPath;
            numVpnWait.Value = Clamp(_cfg.VpnStartupWaitSec, 1, 120);
            int mi = Array.IndexOf(Modes, (_cfg.DetectionMode ?? "auto").Trim().ToLowerInvariant());
            cbMode.SelectedIndex = mi < 0 ? 0 : mi;
            tbKeywords.Text = _cfg.VpnAdapterKeywords;
            tbButtons.Text = _cfg.ConnectButtonNames;
            cbKeepVpn.Checked = _cfg.KeepVpnRunning;
            cbAutoConnect.Checked = _cfg.AutoConnectVpn;
            numVpnRestart.Value = Clamp(_cfg.VpnRestartIfDownSec, 0, 3600);

            tbTargetName.Text = _cfg.TargetProcessName;
            tbTargetPath.Text = _cfg.TargetProcessPath;
            tbTargetArgs.Text = _cfg.TargetStartArgs;
            cbStartOnLaunch.Checked = _cfg.StartTargetOnLaunch;
            cbAutoRestart.Checked = _cfg.AutoRestartTarget;

            numPoll.Value = Clamp(_cfg.PollIntervalMs, 200, 10000);
            cbKill.Checked = _cfg.UseProcessKill;
            cbFirewall.Checked = _cfg.UseFirewallBlock;
            cbUnelevated.Checked = _cfg.LaunchUnelevated;
            cbNoUac.Checked = _cfg.NoUacLaunch;
            cbAutostart.Checked = _cfg.AutostartAtLogon;
            cbAutostart.Enabled = cbNoUac.Checked;
            cbTray.Checked = _cfg.MinimizeToTray;
            cbShowOnDrop.Checked = _cfg.ShowOnVpnDrop;
            tbVpnName.Text = ProcNameFromPath(tbVpnPath.Text, _cfg.VpnProcessName);
            tbTargetName.Text = ProcNameFromPath(tbTargetPath.Text, _cfg.TargetProcessName);
        }

        private static string ProcNameFromPath(string path, string fallback)
        {
            try
            {
                var p = (path ?? "").Trim().Trim('"');
                if (p.Length > 0)
                {
                    var n = System.IO.Path.GetFileNameWithoutExtension(p);
                    if (!string.IsNullOrEmpty(n)) return n;
                }
            }
            catch { }
            return StripExe(fallback);
        }

        private static int Clamp(int v, int min, int max) { return v < min ? min : (v > max ? max : v); }

        private static string StripExe(string name)
        {
            name = (name ?? "").Trim();
            if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) name = name.Substring(0, name.Length - 4);
            return name;
        }

        private void SaveValues()
        {
            _cfg.VpnProcessName = StripExe(tbVpnName.Text);
            _cfg.VpnProcessPath = tbVpnPath.Text.Trim().Trim('"');
            _cfg.VpnStartupWaitSec = (int)numVpnWait.Value;
            _cfg.DetectionMode = Modes[Math.Max(0, cbMode.SelectedIndex)];
            _cfg.VpnAdapterKeywords = tbKeywords.Text.Trim();
            _cfg.ConnectButtonNames = tbButtons.Text.Trim();
            _cfg.KeepVpnRunning = cbKeepVpn.Checked;
            _cfg.AutoConnectVpn = cbAutoConnect.Checked;
            _cfg.VpnRestartIfDownSec = (int)numVpnRestart.Value;

            _cfg.TargetProcessName = StripExe(tbTargetName.Text);
            _cfg.TargetProcessPath = tbTargetPath.Text.Trim().Trim('"');
            _cfg.TargetStartArgs = tbTargetArgs.Text.Trim();
            _cfg.StartTargetOnLaunch = cbStartOnLaunch.Checked;
            _cfg.AutoRestartTarget = cbAutoRestart.Checked;

            _cfg.PollIntervalMs = (int)numPoll.Value;
            _cfg.UseProcessKill = cbKill.Checked;
            _cfg.UseFirewallBlock = cbFirewall.Checked;
            _cfg.LaunchUnelevated = cbUnelevated.Checked;
            _cfg.NoUacLaunch = cbNoUac.Checked;
            _cfg.AutostartAtLogon = cbAutostart.Checked;
            _cfg.MinimizeToTray = cbTray.Checked;
            _cfg.ShowOnVpnDrop = cbShowOnDrop.Checked;
        }

        private void ShowAdapters()
        {
            var lines = VpnMonitor.DescribeAdapters();
            string proxy = VpnMonitor.GetSystemProxy();
            string text = "Статус | Имя | Описание | Тип | Адреса\r\n\r\n" + string.Join("\r\n", lines.ToArray()) +
                          "\r\n\r\nСистемный прокси: " + (proxy ?? "выключен") +
                          "\r\nИнтернет-трафик сейчас идёт через: " + VpnMonitor.BestInterfaceName() +
                          "\r\n\r\nПодсказка: посмотри список при ВЫКЛЮЧЕННОМ и ВКЛЮЧЁННОМ VPN. " +
                          "Адаптер, который появляется (Up) только при подключении, — это туннель. " +
                          "Впиши слово из его имени или описания в «Ключевые слова адаптера».";
            _log.Info("Сетевые адаптеры (системный прокси: " + (proxy ?? "выключен") + "):");
            foreach (var l in lines) _log.Info("   " + l);
            ShowText("Сетевые адаптеры", text);
        }

        private void ShowBrowsecTree()
        {
            Cursor = Cursors.WaitCursor;
            string text;
            try { text = BrowsecAutomation.Dump(StripExe(tbVpnName.Text)); }
            catch (Exception ex) { text = "Ошибка: " + ex.Message; }
            finally { Cursor = Cursors.Default; }
            text += "\r\n\r\nПодсказка: найди в списке текст кнопки/переключателя подключения " +
                    "и впиши его в поле «Кнопка «Подключить» в VPN» (несколько вариантов — через запятую).";
            ShowText("Элементы окна VPN", text);
        }

        private void ShowText(string title, string text)
        {
            using (var f = new Form())
            {
                f.Text = title;
                f.StartPosition = FormStartPosition.CenterParent;
                f.Size = new Size(900, 560);
                var tb = new TextBox();
                tb.Multiline = true;
                tb.ReadOnly = true;
                tb.ScrollBars = ScrollBars.Both;
                tb.WordWrap = false;
                tb.Dock = DockStyle.Fill;
                tb.Font = new Font("Consolas", 9f);
                tb.Text = text;
                f.Controls.Add(tb);
                f.ShowDialog(this);
            }
        }
    }
}
