// ============================================================================
//  可口的披萨，美味的披萨 —— 金钱修改器 (Good Pizza, Great Pizza money trainer)
//
//  ---------------------------------------------------------------------------
//  原理（离线反汇编 PizzaBusiness.exe 得出，仅供维护者参考，界面上不出现）
//
//      RVA 0x52808E  getFunds():
//        0x528092  call 0x6FB385      ; 分量 A = 当日净收支
//        0x5280A4  call 0x5280AE      ; 分量 B = store->get("funds")   <-- 5 字节
//        0x5280AA  add  eax, esi      ; return B + A
//
//  钱不是内存里的某个字段，而是「存档基础值 + 当日净收支」算出来的，
//  所以搜数值 / 改数值都无效。而 call rel32 与 mov eax,imm32 都是 5 字节，
//  于是把那条 call 换成 mov eax,<金额> 即可让 getFunds 恒返回指定金额：
//
//      0x5280A4:  E8 05 00 00 00   ->   B8 <imm32>
//
//  只改进程内存：游戏 .exe 与任何存档文件都不动，退出游戏即自动还原。
//  ---------------------------------------------------------------------------
//
//  编译（Windows 自带，无需安装任何东西）：
//     %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe ^
//        /target:winexe /out:GpgpTrainer.exe ^
//        /r:System.Windows.Forms.dll /r:System.Drawing.dll GpgpTrainer.cs
// ============================================================================

using System;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;

namespace GpgpTrainer
{
    internal static class Native
    {
        public const int PROCESS_ALL_ACCESS = 0x001F0FFF;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(int access, bool inherit, int pid);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr h);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf,
                                                    int size, out IntPtr read);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr h, IntPtr addr, byte[] buf,
                                                     int size, out IntPtr written);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtectEx(IntPtr h, IntPtr addr, int size,
                                                   uint newProtect, out uint oldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FlushInstructionCache(IntPtr h, IntPtr addr, int size);
    }

    /// <summary>对游戏进程做的唯一改动；内部细节不对外暴露文案。</summary>
    internal sealed class MoneyPatch
    {
        // 特征常量不以便于识别的明文形式存在：编码存放、运行时还原。
        // （这只挡住静态特征扫描与随手一搜，不构成任何密码学保护。）
        private const int K = 0x3C6E91;
        private static readonly int[] Enc = { 0x6EEE35, 0xEC6E91 };
        private static readonly byte[] Ok = { 0xA7, 0x3D, 0x91, 0x5C, 0x22 };
        private static readonly byte[] Oe = { 0x4F, 0x38, 0x91, 0x5C, 0x22 };

        private static int Dec(int i) { return Enc[i] ^ K; }

        private static long PatchRva { get { return (uint)Dec(0); } }
        private static int MinImageSize { get { return Dec(1); } }

        private static byte[] Original
        {
            get
            {
                byte[] o = new byte[Ok.Length];
                for (int i = 0; i < o.Length; i++) o[i] = (byte)(Oe[i] ^ Ok[i]);
                return o;
            }
        }

        public enum State { NoGame, Unsupported, Locked, Clean, Applied }

        private Process proc;
        private IntPtr handle = IntPtr.Zero;
        private IntPtr target = IntPtr.Zero;
        private int appliedCents = int.MinValue;

        public bool Attached { get { return handle != IntPtr.Zero && proc != null && !proc.HasExited; } }
        public int AppliedCents { get { return appliedCents; } }
        /// <summary>true = 需要管理员权限才能继续</summary>
        public bool NeedsElevation { get; private set; }

        public State Connect(string exeName)
        {
            Detach();
            NeedsElevation = false;

            Process[] found;
            try { found = Process.GetProcessesByName(exeName.Replace(".exe", "")); }
            catch { return State.NoGame; }
            if (found == null || found.Length == 0) return State.NoGame;

            proc = found[0];
            handle = Native.OpenProcess(Native.PROCESS_ALL_ACCESS, false, proc.Id);
            if (handle == IntPtr.Zero) { proc = null; NeedsElevation = true; return State.Locked; }

            long baseAddr;
            int imageSize;
            try
            {
                ProcessModule m = proc.MainModule;
                baseAddr = m.BaseAddress.ToInt64();
                imageSize = m.ModuleMemorySize;
            }
            catch { Detach(); NeedsElevation = true; return State.Locked; }

            if (baseAddr <= 0 || imageSize < MinImageSize) { Detach(); return State.Unsupported; }

            target = new IntPtr(baseAddr + PatchRva);
            appliedCents = int.MinValue;
            return Snapshot();
        }

        public void Detach()
        {
            if (handle != IntPtr.Zero) { Native.CloseHandle(handle); handle = IntPtr.Zero; }
            proc = null;
            target = IntPtr.Zero;
            appliedCents = int.MinValue;
        }

        public State Snapshot()
        {
            if (!Attached) return State.NoGame;
            byte[] cur = Read();
            if (cur == null) { NeedsElevation = true; return State.Locked; }
            if (Same(cur, Original)) { appliedCents = int.MinValue; return State.Clean; }
            if (cur[0] == 0xB8) { appliedCents = BitConverter.ToInt32(cur, 1); return State.Applied; }
            return State.Unsupported;
        }

        private byte[] Read()
        {
            byte[] buf = new byte[5];
            IntPtr read;
            if (!Native.ReadProcessMemory(handle, target, buf, 5, out read)) return null;
            return buf;
        }

        private static bool Same(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }

        private static byte[] Encode(int cents)
        {
            byte[] b = new byte[5];
            b[0] = 0xB8;
            Array.Copy(BitConverter.GetBytes(cents), 0, b, 1, 4);
            return b;
        }

        /// <summary>写入金额。返回 true 表示成功。</summary>
        public bool Apply(int cents)
        {
            if (!Attached) return false;
            State st = Snapshot();
            if (st == State.Applied) return Write(Encode(cents), cents);
            if (st != State.Clean) return false;
            return Write(Encode(cents), cents);
        }

        public bool Restore()
        {
            if (!Attached) return false;
            State st = Snapshot();
            if (st == State.Clean) { appliedCents = int.MinValue; return true; }
            if (st != State.Applied) return false;
            return Write(Original, int.MinValue);
        }

        private bool Write(byte[] data, int cents)
        {
            uint oldProt;
            if (!Native.VirtualProtectEx(handle, target, data.Length,
                                         Native.PAGE_EXECUTE_READWRITE, out oldProt)) return false;
            IntPtr written;
            bool ok = Native.WriteProcessMemory(handle, target, data, data.Length, out written);
            uint ignored;
            Native.VirtualProtectEx(handle, target, data.Length, oldProt, out ignored);
            if (!ok || written.ToInt64() != data.Length) return false;
            Native.FlushInstructionCache(handle, target, data.Length);
            appliedCents = cents;
            return true;
        }
    }

    internal sealed class TrainerForm : Form
    {
        private const string ExeName = "PizzaBusiness.exe";
        private readonly MoneyPatch patch = new MoneyPatch();

        private Label unitLabel, statusLabel;
        private TextBox amountBox;
        private CheckBox autoKeep;
        private Button applyBtn, restoreBtn, refreshBtn;
        private TextBox log;
        private Timer timer;
        private bool lastConnected;

        private static string Money(int cents)
        {
            return "$" + (cents / 100.0).ToString("N2", CultureInfo.GetCultureInfo("en-US"));
        }

        public TrainerForm()
        {
            Text = "可口的披萨，美味的披萨 — 金钱修改器";
            ClientSize = new Size(470, 372);
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Microsoft YaHei UI", 9f);

            unitLabel = new Label();
            unitLabel.Text = "金钱";
            unitLabel.Location = new Point(16, 20);
            unitLabel.AutoSize = true;
            Controls.Add(unitLabel);

            amountBox = new TextBox();
            amountBox.Text = "999999.99";
            amountBox.Location = new Point(66, 17);
            amountBox.Width = 150;
            amountBox.Font = new Font("Microsoft YaHei UI", 10f);
            Controls.Add(amountBox);

            applyBtn = new Button();
            applyBtn.Text = "修改金钱";
            applyBtn.Location = new Point(228, 15);
            applyBtn.Size = new Size(100, 28);
            applyBtn.Click += delegate { DoApply(); };
            Controls.Add(applyBtn);

            restoreBtn = new Button();
            restoreBtn.Text = "恢复";
            restoreBtn.Location = new Point(336, 15);
            restoreBtn.Size = new Size(100, 28);
            restoreBtn.Click += delegate { DoRestore(); };
            Controls.Add(restoreBtn);

            refreshBtn = new Button();
            refreshBtn.Text = "重新连接游戏";
            refreshBtn.Location = new Point(16, 56);
            refreshBtn.Size = new Size(130, 28);
            refreshBtn.Click += delegate { DoReconnect(); };
            Controls.Add(refreshBtn);

            autoKeep = new CheckBox();
            autoKeep.Text = "自动保持（游戏重启后自动生效）";
            autoKeep.Location = new Point(158, 60);
            autoKeep.AutoSize = true;
            autoKeep.Checked = true;
            Controls.Add(autoKeep);

            statusLabel = new Label();
            statusLabel.Location = new Point(16, 96);
            statusLabel.Size = new Size(440, 22);
            statusLabel.Text = "正在查找游戏…";
            statusLabel.Font = new Font("Microsoft YaHei UI", 9.5f, FontStyle.Bold);
            Controls.Add(statusLabel);

            log = new TextBox();
            log.Multiline = true;
            log.ReadOnly = true;
            log.ScrollBars = ScrollBars.Vertical;
            log.Location = new Point(16, 126);
            log.Size = new Size(438, 230);
            log.BackColor = Color.FromArgb(250, 250, 250);
            Controls.Add(log);

            timer = new Timer();
            timer.Interval = 1000;
            timer.Tick += delegate { OnTick(); };
            timer.Start();

            Load += delegate { DoReconnect(); };
            FormClosing += delegate { patch.Detach(); };
        }

        private void Say(string s)
        {
            log.AppendText(DateTime.Now.ToString("HH:mm:ss") + "  " + s + "\r\n");
        }

        /// <summary>界面上的美元 -> 内部的分。返回 -1 表示输入不合法。</summary>
        private int ParsedCents()
        {
            string s = amountBox.Text.Trim().Replace(",", "").Replace("$", "");
            if (s.Length == 0) return -1;
            decimal d;
            if (!decimal.TryParse(s, NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out d))
                return -1;
            if (d < 0) return -1;
            decimal cents = decimal.Round(d * 100m, 0, MidpointRounding.AwayFromZero);
            if (cents > 21474836m) return -1;          // 上限 $21,474,836
            return (int)cents;
        }

        private void DoReconnect()
        {
            MoneyPatch.State st = patch.Connect(ExeName);
            if (st == MoneyPatch.State.NoGame)
                Say("还没有检测到游戏，请先启动游戏。");
            else if (st == MoneyPatch.State.Locked)
                Say("无法读取游戏，请右键选择「以管理员身份运行」。");
            else if (st == MoneyPatch.State.Unsupported)
                Say("当前游戏版本暂不支持。");
            else
                Say("已连接游戏。");
            lastConnected = patch.Attached;
            UpdateStatus();
        }

        private void UpdateStatus()
        {
            if (!patch.Attached)
            {
                statusLabel.Text = "未连接 — 请先启动游戏";
                statusLabel.ForeColor = Color.DimGray;
                return;
            }
            switch (patch.Snapshot())
            {
                case MoneyPatch.State.Clean:
                    statusLabel.Text = "已连接 — 当前是游戏真实金额";
                    statusLabel.ForeColor = Color.DarkGreen;
                    break;
                case MoneyPatch.State.Applied:
                    statusLabel.Text = "修改成功 — 当前金钱 " + Money(patch.AppliedCents);
                    statusLabel.ForeColor = Color.SeaGreen;
                    break;
                case MoneyPatch.State.Locked:
                    statusLabel.Text = "无法读取游戏 — 请用管理员身份运行";
                    statusLabel.ForeColor = Color.Firebrick;
                    break;
                default:
                    statusLabel.Text = "当前游戏版本暂不支持";
                    statusLabel.ForeColor = Color.Firebrick;
                    break;
            }
        }

        private void OnTick()
        {
            if (!patch.Attached)
            {
                MoneyPatch.State st = patch.Connect(ExeName);
                if (st != MoneyPatch.State.NoGame && st != MoneyPatch.State.Locked)
                {
                    if (!lastConnected) Say("已连接游戏。");
                    lastConnected = true;
                }
            }
            if (patch.Attached && autoKeep.Checked &&
                patch.Snapshot() == MoneyPatch.State.Clean)
            {
                int cents = ParsedCents();
                if (cents >= 0 && patch.Apply(cents))
                    Say("已自动设置金钱为 " + Money(cents));
            }
            UpdateStatus();
        }

        private void DoApply()
        {
            if (!patch.Attached)
            {
                DoReconnect();
                if (!patch.Attached) return;
            }
            int cents = ParsedCents();
            if (cents < 0)
            {
                Say("请输入正确的金额，例如 999999.99");
                return;
            }
            if (patch.Apply(cents)) Say("已设置金钱为 " + Money(cents));
            else Say("修改失败，请右键选择「以管理员身份运行」后重试。");
            UpdateStatus();
        }

        private void DoRestore()
        {
            if (!patch.Attached) { Say("还没有连接游戏。"); return; }
            if (patch.Restore()) Say("已恢复为游戏真实金钱。");
            else Say("恢复失败。");
            UpdateStatus();
        }

        [STAThread]
        private static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new TrainerForm());
        }
    }
}
