using System.Reflection;
using System.Runtime.InteropServices;

[assembly: AssemblyTitle("VpnGuard")]
[assembly: AssemblyDescription("Разрешает работу приложения только при активном VPN-туннеле")]
[assembly: AssemblyProduct("VpnGuard")]
[assembly: AssemblyVersion("2.3.0.0")]
[assembly: AssemblyFileVersion("2.3.0.0")]
[assembly: ComVisible(false)]

namespace VpnGuard
{
    public static class AppInfo
    {
        public const string Name = "VpnGuard";
        public const string Version = "2.3";
        public const string NameWithVersion = Name + " v" + Version;
    }
}
