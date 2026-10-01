using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Accessibility;

namespace VpnGuard
{
    /// <summary>
    /// Нажимает кнопку подключения в окне Browsec через Microsoft Active Accessibility
    /// (тот же механизм, что используют экранные дикторы). Браузер Chromium/Electron
    /// строит дерево доступности после первого запроса, поэтому есть повторы.
    /// </summary>
    public static class BrowsecAutomation
    {
        private class Node
        {
            public IAccessible Acc;
            public object ChildId;
            public string Name;
            public int Role;
            public int Depth;
        }

        private const int CHILDID_SELF = 0;
        private const uint OBJID_CLIENT = 0xFFFFFFFC;
        private static Guid IID_IAccessible = new Guid("618736E0-3C3D-11CF-810C-00AA00389B71");
        private const int MaxNodes = 4000;
        private const int MaxDepth = 40;

        /// <summary>
        /// Ищет в окнах процесса элемент с именем из списка (точное совпадение без учёта регистра)
        /// и «нажимает» его. Возвращает текст результата для лога.
        /// </summary>
        public static bool TryClickConnect(string processName, string[] buttonNames, out string result)
        {
            result = "";
            if (buttonNames == null || buttonNames.Length == 0) { result = "список имён кнопок пуст"; return false; }

            for (int attempt = 0; attempt < 3; attempt++)
            {
                var nodes = CollectNodes(processName);
                if (nodes == null) { result = "окно " + processName + " не найдено"; return false; }

                foreach (var n in nodes)
                {
                    if (string.IsNullOrEmpty(n.Name)) continue;
                    string nm = n.Name.Trim();
                    foreach (var b in buttonNames)
                    {
                        if (!string.Equals(nm, b, StringComparison.OrdinalIgnoreCase)) continue;
                        try
                        {
                            n.Acc.accDoDefaultAction(n.ChildId);
                            result = "нажат элемент «" + nm + "» (роль " + n.Role + ")";
                            return true;
                        }
                        catch (Exception ex)
                        {
                            result = "элемент «" + nm + "» найден, но нажать не удалось: " + ex.Message;
                        }
                    }
                }
                // дерево Chromium могло ещё не построиться — ждём и пробуем снова
                Thread.Sleep(700);
            }
            if (result.Length == 0)
                result = "кнопка подключения не найдена (см. «Элементы окна Browsec» в настройках)";
            return false;
        }

        /// <summary>Текстовый дамп дерева доступности окон процесса — для настройки имён кнопок.</summary>
        public static string Dump(string processName)
        {
            List<Node> nodes = null;
            for (int i = 0; i < 3; i++)
            {
                nodes = CollectNodes(processName);
                if (nodes == null) return "Окна процесса " + processName + " не найдены. Запусти Browsec и открой его окно.";
                if (nodes.Count > 5) break;
                Thread.Sleep(700);
            }
            var sb = new StringBuilder();
            sb.AppendLine("Элементы окна " + processName + " (роль 43 = кнопка, 44 = флажок/переключатель):");
            foreach (var n in nodes)
            {
                if (string.IsNullOrEmpty(n.Name)) continue;
                sb.Append(new string(' ', Math.Min(n.Depth, 20) * 2));
                sb.Append("[").Append(n.Role).Append("] ").AppendLine(n.Name.Replace("\r", " ").Replace("\n", " "));
            }
            return sb.ToString();
        }

        private static List<Node> CollectNodes(string processName)
        {
            var pids = new HashSet<uint>();
            try
            {
                foreach (var p in Process.GetProcessesByName(processName))
                {
                    pids.Add((uint)p.Id);
                    p.Dispose();
                }
            }
            catch { }
            if (pids.Count == 0) return null;

            var windows = new List<IntPtr>();
            EnumWindows(delegate(IntPtr h, IntPtr l)
            {
                uint pid;
                GetWindowThreadProcessId(h, out pid);
                if (pids.Contains(pid) && GetWindowTextLength(h) > 0) windows.Add(h);
                return true;
            }, IntPtr.Zero);
            if (windows.Count == 0) return null;

            // Видимые окна — первыми
            windows.Sort(delegate(IntPtr a, IntPtr b) { return IsWindowVisible(b).CompareTo(IsWindowVisible(a)); });

            var nodes = new List<Node>();
            foreach (var hwnd in windows)
            {
                object obj;
                var iid = IID_IAccessible;
                if (AccessibleObjectFromWindow(hwnd, OBJID_CLIENT, ref iid, out obj) != 0) continue;
                var acc = obj as IAccessible;
                if (acc == null) continue;
                Walk(acc, 0, nodes);
                if (nodes.Count >= MaxNodes) break;
            }
            return nodes;
        }

        private static void Walk(IAccessible acc, int depth, List<Node> nodes)
        {
            if (depth > MaxDepth || nodes.Count >= MaxNodes) return;

            int count = 0;
            try { count = acc.accChildCount; } catch { }
            if (count <= 0) return;

            var children = new object[count];
            int got;
            if (AccessibleChildren(acc, 0, count, children, out got) < 0) return;

            for (int i = 0; i < got && nodes.Count < MaxNodes; i++)
            {
                object ch = children[i];
                var childAcc = ch as IAccessible;
                if (childAcc != null)
                {
                    nodes.Add(MakeNode(childAcc, CHILDID_SELF, depth + 1));
                    Walk(childAcc, depth + 1, nodes);
                }
                else if (ch is int)
                {
                    nodes.Add(MakeNode(acc, ch, depth + 1));
                }
            }
        }

        private static Node MakeNode(IAccessible acc, object childId, int depth)
        {
            var n = new Node();
            n.Acc = acc;
            n.ChildId = childId;
            n.Depth = depth;
            try { n.Name = acc.get_accName(childId); } catch { n.Name = null; }
            try { n.Role = Convert.ToInt32(acc.get_accRole(childId)); } catch { n.Role = 0; }
            return n;
        }

        // ---------- WinAPI ----------
        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
        [DllImport("user32.dll")] private static extern bool EnumWindows(EnumWindowsProc cb, IntPtr lParam);
        [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
        [DllImport("user32.dll")] private static extern int GetWindowTextLength(IntPtr hWnd);
        [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("oleacc.dll")]
        private static extern int AccessibleObjectFromWindow(IntPtr hwnd, uint dwObjectID, ref Guid riid,
            [MarshalAs(UnmanagedType.IUnknown)] out object ppvObject);

        [DllImport("oleacc.dll")]
        private static extern int AccessibleChildren(IAccessible paccContainer, int iChildStart, int cChildren,
            [Out] object[] rgvarChildren, out int pcObtained);
    }
}
