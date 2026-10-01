using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace VpnGuard
{
    /// <summary>
    /// Запуск программ БЕЗ прав администратора из процесса, запущенного от администратора.
    /// VpnGuard должен быть админом (для Firewall), но Telegram, запущенный от админа,
    /// потом не открывается обычным ярлыком (Windows не даёт обычному процессу
    /// «достучаться» до повышенного экземпляра) — отсюда «Telegram не запускается».
    /// </summary>
    public static class ProcessLauncher
    {
        private const int ERROR_ELEVATION_REQUIRED = 740;

        public static bool IsElevated()
        {
            try
            {
                using (var id = WindowsIdentity.GetCurrent())
                    return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        /// <summary>Возвращает описание способа запуска или бросает исключение.</summary>
        public static string Start(string path, string args, bool unelevated)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                throw new FileNotFoundException("Файл не найден: " + path);

            string workDir = Path.GetDirectoryName(path) ?? "";
            args = args ?? "";

            if (unelevated && IsElevated())
            {
                int err;
                if (TryStartWithShellToken(path, args, workDir, out err))
                    return "без прав администратора";

                if (err == ERROR_ELEVATION_REQUIRED)
                {
                    // Программа сама требует админа — запускаем от нашего (уже повышенного)
                    // процесса, тогда Windows не спросит подтверждения UAC.
                    StartNormal(path, args, workDir);
                    return "с правами администратора (программа их требует)";
                }

                if (args.Length == 0)
                {
                    // Запасной вариант: explorer.exe всегда запускает программы без повышения.
                    var psi = new ProcessStartInfo("explorer.exe", "\"" + path + "\"");
                    psi.UseShellExecute = false;
                    Process.Start(psi);
                    return "через explorer.exe (код ошибки токена " + err + ")";
                }
            }

            StartNormal(path, args, workDir);
            return "обычный запуск";
        }

        private static void StartNormal(string path, string args, string workDir)
        {
            var psi = new ProcessStartInfo(path, args);
            psi.UseShellExecute = true;
            psi.WorkingDirectory = workDir;
            Process.Start(psi);
        }

        private static bool TryStartWithShellToken(string path, string args, string workDir, out int error)
        {
            error = 0;
            IntPtr hProc = IntPtr.Zero, hToken = IntPtr.Zero, hDup = IntPtr.Zero;
            try
            {
                IntPtr shell = GetShellWindow();
                if (shell == IntPtr.Zero) { error = -1; return false; }

                uint pid;
                GetWindowThreadProcessId(shell, out pid);
                if (pid == 0) { error = -2; return false; }

                hProc = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
                if (hProc == IntPtr.Zero) { error = Marshal.GetLastWin32Error(); return false; }

                if (!OpenProcessToken(hProc, TOKEN_DUPLICATE, out hToken))
                { error = Marshal.GetLastWin32Error(); return false; }

                const uint access = TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE |
                                    TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;
                if (!DuplicateTokenEx(hToken, access, IntPtr.Zero, SecurityImpersonation, TokenPrimary, out hDup))
                { error = Marshal.GetLastWin32Error(); return false; }

                var si = new STARTUPINFO();
                si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
                PROCESS_INFORMATION pi;
                var cmd = new StringBuilder("\"" + path + "\"" + (args.Length > 0 ? " " + args : ""));

                if (!CreateProcessWithTokenW(hDup, 0, path, cmd, 0, IntPtr.Zero, workDir, ref si, out pi))
                { error = Marshal.GetLastWin32Error(); return false; }

                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return true;
            }
            catch
            {
                error = -3;
                return false;
            }
            finally
            {
                if (hDup != IntPtr.Zero) CloseHandle(hDup);
                if (hToken != IntPtr.Zero) CloseHandle(hToken);
                if (hProc != IntPtr.Zero) CloseHandle(hProc);
            }
        }

        // ---------- WinAPI ----------
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        private const uint TOKEN_DUPLICATE = 0x0002;
        private const uint TOKEN_QUERY = 0x0008;
        private const uint TOKEN_ADJUST_DEFAULT = 0x0080;
        private const uint TOKEN_ADJUST_SESSIONID = 0x0100;
        private const int SecurityImpersonation = 2;
        private const int TokenPrimary = 1;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
            public short wShowWindow, cbReserved2;
            public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess, hThread;
            public int dwProcessId, dwThreadId;
        }

        [DllImport("user32.dll")] private static extern IntPtr GetShellWindow();
        [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr h);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DuplicateTokenEx(IntPtr existing, uint access, IntPtr attrs, int impLevel, int tokenType, out IntPtr newToken);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcessWithTokenW(IntPtr token, uint logonFlags, string app, StringBuilder cmdLine,
            uint flags, IntPtr env, string curDir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
    }
}
