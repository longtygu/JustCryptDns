param([string]$ProcessName = 'JustCryptDns')
# Lists visible/hidden top-level windows of a process (development diagnostics).
Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices; using System.Collections.Generic;
public static class E {
  public delegate bool P(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] static extern bool EnumWindows(P cb, IntPtr l);
  [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
  [StructLayout(LayoutKind.Sequential)] public struct R { public int L,T,Rr,B; }
  [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out R r);
  public static List<string> List(uint target) {
    var o = new List<string>();
    EnumWindows((h, l) => { uint pid; GetWindowThreadProcessId(h, out pid); if (pid == target) {
      var t = new StringBuilder(256); GetWindowText(h, t, 256); var c = new StringBuilder(256); GetClassName(h, c, 256); R r; GetWindowRect(h, out r);
      o.Add(string.Format("{0} vis={1} cls={2} title='{3}' rect=({4},{5},{6},{7})", h, IsWindowVisible(h), c, t, r.L, r.T, r.Rr - r.L, r.B - r.T)); } return true; }, IntPtr.Zero);
    return o;
  }
}
"@
foreach ($p in Get-Process $ProcessName) { "PID $($p.Id)"; [E]::List([uint32]$p.Id) }
