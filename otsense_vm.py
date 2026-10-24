#!/usr/bin/env python3
"""
OT Sense VM launcher for Windows.

A Windows PC cannot do real ARP / MAC scanning from a normal program. This app runs the OT Sense sensor ISO (Linux) as a
virtual machine whose network card is bridged onto the Wi-Fi / Ethernet adapter you choose, so the sensor sees the same
network as the PC and can scan it properly. Works with Hyper-V (Windows Pro/Enterprise) or VirtualBox.

Put these files in ONE folder (central gives you both downloads):
    OTSense-VM.exe              this app
    otsense-sensor-<site>.iso   the sensor, already holding this site's settings and token
    vm.conf                     SITE=..., ISO=..., CENTRAL=...   (comes in the launcher zip)

Run:  python otsense_vm.py          (or double-click OTSense-VM.exe)
Test: python otsense_vm.py --selftest   (no GUI, no VM; checks the command builders)
"""
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser

APP_NAME = "OT Sense VM"
IS_WIN = os.name == "nt"
NO_WINDOW = 0x08000000 if IS_WIN else 0


def app_dir():
    return os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))


def slug(s):
    return re.sub(r"^-+|-+$", "", re.sub(r"[^a-z0-9]+", "-", str(s).lower()))[:40] or "site"


def psq(s):
    """PowerShell single-quoted string."""
    return "'" + str(s).replace("'", "''") + "'"


def is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run(cmd, timeout=120):
    """Run a command, return (returncode, text). Never raises."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, creationflags=NO_WINDOW,
                           encoding="utf-8", errors="replace")
        return p.returncode, ((p.stdout or "") + (p.stderr or "")).strip()
    except FileNotFoundError:
        return 127, "program not found: %s" % (cmd[0] if cmd else "")
    except subprocess.TimeoutExpired:
        return 124, "timed out"
    except Exception as e:  # pragma: no cover
        return 1, str(e)


def ps(script, timeout=180, runner=None):
    return (runner or run)(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                            "$ErrorActionPreference='Stop'; " + script], timeout)


# ---------------------------------------------------------------- settings / files
def read_kv(path):
    d = {}
    try:
        for line in open(path, encoding="utf-8-sig"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                d[k.strip().upper()] = v.strip().strip("'\"")
    except OSError:
        pass
    return d


def find_iso(folder, conf):
    want = conf.get("ISO", "")
    if want and os.path.isfile(os.path.join(folder, want)):
        return os.path.join(folder, want)
    try:
        isos = sorted(n for n in os.listdir(folder) if re.match(r"otsense-sensor.*\.iso$", n, re.I))
    except OSError:
        isos = []
    return os.path.join(folder, isos[0]) if isos else ""


SETTINGS_FILE = "vm-settings.json"


def load_settings(folder):
    try:
        return json.load(open(os.path.join(folder, SETTINGS_FILE)))
    except Exception:
        return {}


def save_settings(folder, d):
    try:
        json.dump(d, open(os.path.join(folder, SETTINGS_FILE), "w"), indent=1)
    except OSError:
        pass


# ---------------------------------------------------------------- Windows network adapters
def list_adapters(runner=None):
    """[{name, desc, mac, status, wifi}] - physical adapters, Wi-Fi first, connected first."""
    rc, out = ps("Get-NetAdapter -Physical | Select-Object Name,InterfaceDescription,MacAddress,Status,PhysicalMediaType | ConvertTo-Json -Compress",
                 60, runner)
    if rc != 0 or not out.strip():
        return []
    try:
        data = json.loads(out[out.index("["):] if "[" in out[:5] else out[out.index("{"):])
    except Exception:
        return []
    if isinstance(data, dict):
        data = [data]
    res = []
    for a in data:
        media = str(a.get("PhysicalMediaType") or "")
        name = str(a.get("Name") or "")
        res.append({"name": name, "desc": str(a.get("InterfaceDescription") or ""), "mac": str(a.get("MacAddress") or ""),
                    "status": str(a.get("Status") or ""),
                    "wifi": ("802.11" in media) or bool(re.search(r"wi-?fi|wireless|wlan", name + " " + str(a.get("InterfaceDescription")), re.I))})
    res.sort(key=lambda a: (a["status"] != "Up", not a["wifi"], a["name"]))
    return res


def arp_lookup(mac, runner=None):
    """IPv4 of a MAC from the Windows ARP table (the VM's address, when the VM tools do not report it)."""
    if not mac:
        return ""
    m = re.sub(r"[^0-9a-f]", "", mac.lower())
    rc, out = (runner or run)(["arp", "-a"], 20)
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and re.sub(r"[^0-9a-f]", "", parts[1].lower()) == m and re.match(r"\d+\.\d+\.\d+\.\d+$", parts[0]):
            return parts[0]
    return ""


# ---------------------------------------------------------------- back-ends
class Backend:
    key = ""
    title = ""

    def __init__(self, vmname, runner=None):
        self.vm = vmname
        self.runner = runner or run

    def available(self):  # -> (bool, why)
        raise NotImplementedError


class HyperV(Backend):
    key, title = "hyperv", "Hyper-V"

    def _ps(self, script, timeout=180):
        return ps(script, timeout, self.runner)

    def available(self):
        if not IS_WIN and self.runner is run:
            return False, "Windows only"
        rc, out = self._ps("if((Get-Command New-VM -ErrorAction SilentlyContinue) -and ((Get-Service vmms -ErrorAction SilentlyContinue).Status -eq 'Running')){'yes'}else{'no'}", 40)
        if rc == 0 and out.strip().endswith("yes"):
            return True, ""
        return False, "Hyper-V is not enabled (needs Windows Pro/Enterprise: Turn Windows features on > Hyper-V, then restart)"

    def switch_name(self, adapter):
        return "OTSense-" + slug(adapter)

    def ensure_and_start(self, iso, adapter):
        sw = self.switch_name(adapter)
        script = "; ".join([
            "$n=%s; $sw=%s; $iso=%s; $ad=%s" % (psq(self.vm), psq(sw), psq(iso), psq(adapter)),
            "if(-not (Get-VMSwitch -Name $sw -ErrorAction SilentlyContinue)){ New-VMSwitch -Name $sw -NetAdapterName $ad -AllowManagementOS $true | Out-Null }",
            "if(-not (Get-VM -Name $n -ErrorAction SilentlyContinue)){"
            " New-VM -Name $n -Generation 2 -MemoryStartupBytes 4GB -NoVHD -SwitchName $sw | Out-Null;"
            " Set-VMProcessor -VMName $n -Count 2; Set-VMMemory -VMName $n -DynamicMemoryEnabled $false;"
            " Set-VMFirmware -VMName $n -EnableSecureBoot Off;"
            " Add-VMDvdDrive -VMName $n -Path $iso | Out-Null;"
            " Set-VM -Name $n -AutomaticStartAction Nothing -AutomaticStopAction TurnOff }"
            " else { if((Get-VM -Name $n).State -ne 'Off'){ throw 'The VM is already running. Stop it first to change the adapter.' };"
            " Connect-VMNetworkAdapter -VMName $n -SwitchName $sw; Set-VMDvdDrive -VMName $n -Path $iso }",
            "Set-VMFirmware -VMName $n -FirstBootDevice (Get-VMDvdDrive -VMName $n)",
            "if((Get-VM -Name $n).State -eq 'Off'){ Start-VM -Name $n }",
        ])
        return self._ps(script, 300)

    def release_iso(self):
        return self._ps("if(Get-VM -Name %s -ErrorAction SilentlyContinue){ Set-VMDvdDrive -VMName %s -Path $null }" % (psq(self.vm), psq(self.vm)), 60)

    def state(self):
        rc, out = self._ps("$v=Get-VM -Name %s -ErrorAction SilentlyContinue; if($v){[string]$v.State}else{'none'}" % psq(self.vm), 30)
        s = out.strip().splitlines()[-1].strip().lower() if rc == 0 and out.strip() else "unknown"
        return {"running": "running", "off": "stopped", "none": "not created"}.get(s, s)

    def stop(self):
        return self._ps("Stop-VM -Name %s -TurnOff -Force" % psq(self.vm), 90)

    def remove(self, adapter=""):
        parts = ["$n=%s" % psq(self.vm), "if(Get-VM -Name $n -ErrorAction SilentlyContinue){ Stop-VM -Name $n -TurnOff -Force -ErrorAction SilentlyContinue; Remove-VM -Name $n -Force }"]
        if adapter:   # also give the Wi-Fi/Ethernet adapter back to Windows
            parts.append("$sw=%s; if(Get-VMSwitch -Name $sw -ErrorAction SilentlyContinue){ Remove-VMSwitch -Name $sw -Force }" % psq(self.switch_name(adapter)))
        return self._ps("; ".join(parts), 120)

    def mac_ip(self):
        rc, out = self._ps("$a=Get-VMNetworkAdapter -VMName %s; [pscustomobject]@{mac=[string]$a.MacAddress; ip=(@($a.IPAddresses) | Where-Object {$_ -match '^\\d+\\.\\d+\\.\\d+\\.\\d+$'} | Select-Object -First 1)} | ConvertTo-Json -Compress" % psq(self.vm), 30)
        try:
            d = json.loads(out[out.index("{"):])
            return str(d.get("mac") or ""), str(d.get("ip") or "")
        except Exception:
            return "", ""

    def console(self):
        try:
            subprocess.Popen(["vmconnect.exe", "localhost", self.vm], creationflags=NO_WINDOW)
            return True
        except Exception:
            return False


class VirtualBox(Backend):
    key, title = "virtualbox", "VirtualBox"

    def exe(self):
        cands = [os.path.join(os.environ.get("VBOX_MSI_INSTALL_PATH", ""), "VBoxManage.exe"),
                 r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe", "/usr/bin/VBoxManage", "VBoxManage"]
        for c in cands:
            if c and os.path.isfile(c):
                return c
        return "VBoxManage"

    def m(self, *args, timeout=120):
        return self.runner([self.exe()] + list(args), timeout)

    def available(self):
        rc, out = self.m("--version", timeout=30)
        return (True, "") if rc == 0 else (False, "VirtualBox is not installed")

    def bridged_name(self, adapter_desc, adapter_name=""):
        """VirtualBox names bridged interfaces like the adapter description; match as loosely as needed."""
        rc, out = self.m("list", "bridgedifs", timeout=30)
        names = re.findall(r"^Name:\s*(.+)$", out, re.M)
        names = [n.strip() for n in names]
        for want in (adapter_desc, adapter_name):
            if want:
                for n in names:
                    if n.lower() == want.lower():
                        return n
        for want in (adapter_desc, adapter_name):
            if want:
                for n in names:
                    if want.lower() in n.lower() or n.lower() in want.lower():
                        return n
        return ""

    def state(self):
        rc, out = self.m("showvminfo", self.vm, "--machinereadable", timeout=30)
        if rc != 0:
            return "not created"
        m = re.search(r'^VMState="?([a-z]+)', out, re.M)
        s = m.group(1) if m else "unknown"
        return {"running": "running", "poweroff": "stopped", "aborted": "stopped", "saved": "stopped"}.get(s, s)

    def ensure_and_start(self, iso, adapter_desc, adapter_name=""):
        bridged = self.bridged_name(adapter_desc, adapter_name)
        if not bridged:
            return 1, "VirtualBox cannot bridge to this adapter (not in its list). Pick another adapter."
        exists = self.state() != "not created"
        if exists and self.state() == "running":
            return 1, "The VM is already running. Stop it first to change the adapter."
        steps = []
        if not exists:
            steps += [["createvm", "--name", self.vm, "--ostype", "Debian_64", "--register"],
                      ["modifyvm", self.vm, "--memory", "4096", "--cpus", "2", "--ioapic", "on", "--graphicscontroller", "vmsvga", "--vram", "16"],
                      ["storagectl", self.vm, "--name", "SATA", "--add", "sata", "--controller", "IntelAhci"]]
        steps += [["modifyvm", self.vm, "--nic1", "bridged", "--bridgeadapter1", bridged, "--nicpromisc1", "allow-all", "--boot1", "dvd"],
                  ["storageattach", self.vm, "--storagectl", "SATA", "--port", "0", "--device", "0", "--type", "dvddrive", "--medium", iso],
                  ["startvm", self.vm, "--type", "headless"]]
        for s in steps:
            rc, out = self.m(*s, timeout=180)
            if rc != 0:
                return rc, "VBoxManage %s failed: %s" % (s[0], out)
        return 0, "started"

    def release_iso(self):
        if self.state() == "not created":
            return 0, ""
        return self.m("storageattach", self.vm, "--storagectl", "SATA", "--port", "0", "--device", "0", "--type", "dvddrive", "--medium", "emptydrive", timeout=60)

    def stop(self):
        return self.m("controlvm", self.vm, "poweroff", timeout=60)

    def remove(self, adapter=""):
        self.m("controlvm", self.vm, "poweroff", timeout=30)
        time.sleep(1)
        return self.m("unregistervm", self.vm, "--delete", timeout=60)

    def mac_ip(self):
        rc, out = self.m("showvminfo", self.vm, "--machinereadable", timeout=30)
        m = re.search(r'^macaddress1="?([0-9A-Fa-f]{12})', out, re.M)
        return (m.group(1) if m else ""), ""

    def console(self):
        return False


# ---------------------------------------------------------------- connection test
def test_central(url, timeout=12):
    if not url:
        return False, "no central address in vm.conf"
    try:
        r = urllib.request.urlopen(url.rstrip("/") + "/health", timeout=timeout)
        return True, "central answered (%s)" % r.status
    except Exception as e:
        return False, "cannot reach central: %s" % getattr(e, "reason", e)


# ---------------------------------------------------------------- scan mode inside the ISO (its 64 KB settings slot)
SLOT_MAGIC = b"OTSENSE_SLOT_V1\n"
SLOT_SIZE = 65536


def find_slot(iso_path):
    """Offset of the settings slot inside the ISO (reads the file once, 8 MB at a time). None if not found."""
    ch = 8 * 1024 * 1024
    with open(iso_path, "rb") as f:
        pos, tail = 0, b""
        while True:
            data = f.read(ch)
            if not data:
                return None
            buf = tail + data
            i = buf.find(SLOT_MAGIC)
            if i >= 0:
                return pos - len(tail) + i
            tail = buf[-(len(SLOT_MAGIC) - 1):]
            pos += len(data)


def read_slot(iso_path, offset=None):
    """(offset, settings dict) of the sensor ISO, or (None, {})."""
    try:
        off = offset if offset is not None else find_slot(iso_path)
        if off is None:
            return None, {}
        with open(iso_path, "rb") as f:
            f.seek(off)
            raw = f.read(SLOT_SIZE)
        if raw[:16] != SLOT_MAGIC:
            return None, {}
        n = int.from_bytes(raw[16:20], "big")
        return off, json.loads(raw[20:20 + n].decode("utf-8"))
    except Exception:
        return None, {}


def patch_scan(iso_path, mode, offset=None):
    """Set passive/active inside the ISO's settings slot (the VM must be stopped and the ISO released). -> (ok, message)"""
    if mode not in ("passive", "active"):
        return False, "bad mode"
    off, d = read_slot(iso_path, offset)
    if off is None:
        return False, "this ISO has no settings slot"
    if d.get("scan") == mode:
        return True, "already %s" % mode
    d["scan"] = mode
    blob = json.dumps(d, separators=(",", ":")).encode("utf-8")
    if len(blob) > SLOT_SIZE - 20:
        return False, "settings too large"
    try:
        with open(iso_path, "r+b") as f:
            f.seek(off + 16)
            f.write(len(blob).to_bytes(4, "big") + blob + b"\x00" * (SLOT_SIZE - 20 - len(blob)))
        return True, "changed to %s" % mode
    except OSError as e:
        return False, "cannot change the ISO (is the VM still using it?): %s" % e


# ---------------------------------------------------------------- one-click helpers for non-IT users
def enable_hyperv(runner=None):
    """Turn the Hyper-V Windows feature on (needs one restart). Windows Home cannot."""
    return ps("$e=(Get-WindowsEdition -Online).Edition; if($e -match 'Core|Home'){ throw 'This is Windows Home: it has no Hyper-V. Install VirtualBox instead.' };"
              " Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All -NoRestart | Out-Null; 'ok'", 600, runner)


def install_virtualbox(runner=None):
    """Install VirtualBox with winget (built into Windows 10/11). rc 127 = winget missing."""
    return (runner or run)(["winget", "install", "-e", "--id", "Oracle.VirtualBox", "--silent",
                            "--accept-package-agreements", "--accept-source-agreements"], 1500)


TASK_NAME = "OTSense-VM"


def signin_task_cmd(exe, enable=True):
    if enable:
        return ["schtasks", "/Create", "/TN", TASK_NAME, "/TR", '"%s" --autostart' % exe, "/SC", "ONLOGON", "/RL", "HIGHEST", "/F"]
    return ["schtasks", "/Delete", "/TN", TASK_NAME, "/F"]


def restart_pc_cmd():
    return ["shutdown", "/r", "/t", "30", "/c", "OT Sense: restarting to finish turning on Hyper-V"]


# ---------------------------------------------------------------- self test (no GUI, no VM)
def selftest():
    import tempfile
    calls = []

    def fake(cmd, timeout=0):
        calls.append(cmd)
        joined = " ".join(cmd)
        if "list" in cmd and "bridgedifs" in cmd:
            return 0, "Name:            Intel(R) Wi-Fi 6 AX201 160MHz\nGUID: x\n\nName:            Realtek PCIe GbE\n"
        if "showvminfo" in cmd:
            return 1, "not found"
        if "--version" in cmd:
            return 0, "7.0.18"
        if "Get-NetAdapter" in joined:
            return 0, json.dumps([{"Name": "Ethernet", "InterfaceDescription": "Realtek PCIe GbE", "MacAddress": "AA-BB", "Status": "Disconnected", "PhysicalMediaType": "802.3"},
                                  {"Name": "Wi-Fi", "InterfaceDescription": "Intel(R) Wi-Fi 6 AX201 160MHz", "MacAddress": "CC-DD", "Status": "Up", "PhysicalMediaType": "Native 802.11"}])
        if cmd[0] == "arp":
            return 0, "  192.168.1.77        08-00-27-aa-bb-cc     dynamic\n"
        return 0, "ok"
    ad = list_adapters(fake)
    assert ad[0]["name"] == "Wi-Fi" and ad[0]["wifi"] and ad[1]["name"] == "Ethernet", ad
    vb = VirtualBox("OTSense-test", fake)
    assert vb.available()[0]
    assert vb.bridged_name("Intel(R) Wi-Fi 6 AX201 160MHz") == "Intel(R) Wi-Fi 6 AX201 160MHz"
    assert vb.bridged_name("Wi-Fi") == "Intel(R) Wi-Fi 6 AX201 160MHz" and vb.bridged_name("x", "Realtek PCIe GbE") == "Realtek PCIe GbE"
    rc, _ = vb.ensure_and_start(r"C:\x\a.iso", "Intel(R) Wi-Fi 6 AX201 160MHz")
    flat = [" ".join(c[1:]) for c in calls if c and "VBoxManage" in c[0]]
    assert rc == 0 and any(c.startswith("createvm") for c in flat) and any("--nic1 bridged" in c and "allow-all" in c for c in flat) and flat[-1].startswith("startvm"), flat
    calls[:] = []
    hv = HyperV("OTSense-test", fake)
    rc, _ = hv.ensure_and_start(r"C:\x\it's.iso", "Wi-Fi")
    script = calls[-1][-1]
    assert "New-VMSwitch -Name $sw -NetAdapterName $ad" in script and "it''s.iso" in script and "Start-VM" in script, script
    hv.release_iso()
    assert "Set-VMDvdDrive" in calls[-1][-1] and "$null" in calls[-1][-1]
    assert arp_lookup("08:00:27:AA:BB:CC", fake) == "192.168.1.77"
    assert slug("Plant Pune #1") == "plant-pune-1"
    # scan mode inside a (small, fake) ISO
    tmp = os.path.join(tempfile.mkdtemp(), "t.iso")
    j = json.dumps({"v": 1, "site": "S", "scan": "passive", "token": "t"}).encode()
    slot = SLOT_MAGIC + len(j).to_bytes(4, "big") + j
    slot += b"\x00" * (SLOT_SIZE - len(slot))
    junk = bytes(range(256)) * 40000
    open(tmp, "wb").write(junk + slot + junk)
    off, d = read_slot(tmp)
    assert off == len(junk) and d["scan"] == "passive", (off, d)
    assert patch_scan(tmp, "active")[0] and read_slot(tmp)[1]["scan"] == "active" and read_slot(tmp)[1]["token"] == "t"
    data = open(tmp, "rb").read()
    assert data[:len(junk)] == junk and data[len(junk) + SLOT_SIZE:] == junk and len(data) == 2 * len(junk) + SLOT_SIZE
    assert patch_scan(tmp, "active")[1] == "already active" and not patch_scan(tmp, "weird")[0]
    # one-click helpers
    calls[:] = []
    enable_hyperv(fake)
    assert "Microsoft-Hyper-V-All" in calls[-1][-1] and "-NoRestart" in calls[-1][-1] and "Home" in calls[-1][-1]
    install_virtualbox(fake)
    assert calls[-1][:4] == ["winget", "install", "-e", "--id"] and "Oracle.VirtualBox" in calls[-1]
    assert signin_task_cmd(r"C:\OT\OTSense-VM.exe")[1] == "/Create" and "ONLOGON" in signin_task_cmd("x") and signin_task_cmd("x", False)[1] == "/Delete"
    print("selftest OK")


# ---------------------------------------------------------------- GUI
def gui():
    import tkinter as tk
    from tkinter import messagebox, ttk

    folder = app_dir()
    exe_path = sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__)
    conf = read_kv(os.path.join(folder, "vm.conf"))
    site = conf.get("SITE", "")
    st = load_settings(folder)
    S = {"iso": find_iso(folder, conf), "adapters": [], "ip": "", "busy": False, "deadline": 0, "slot": None, "booted": False}
    vmname = "OTSense-" + slug(site or "sensor")
    backends = {"hyperv": HyperV(vmname), "virtualbox": VirtualBox(vmname)}
    avail = {}
    auto_flag = "--autostart" in sys.argv

    root = tk.Tk()
    root.title("%s - %s" % (APP_NAME, site or "sensor"))
    root.geometry("780x700")
    BG, PANEL, FG, MUT, ACC, RED = "#0d1520", "#142033", "#e6edf5", "#8fa3b8", "#1f8a5b", "#b3402f"
    root.configure(bg=BG)
    sty = ttk.Style(root)
    try:
        sty.theme_use("clam")
    except Exception:
        pass
    sty.configure(".", background=BG, foreground=FG, fieldbackground="#101b29")
    sty.configure("TLabel", background=BG, foreground=FG)
    sty.configure("M.TLabel", foreground=MUT)
    sty.configure("H.TLabel", font=("Segoe UI", 15, "bold"))
    sty.configure("TButton", padding=6)
    sty.configure("TRadiobutton", background=BG, foreground=FG)
    sty.configure("TCheckbutton", background=BG, foreground=FG)
    sty.configure("Go.TButton", background=ACC, foreground="white", font=("Segoe UI", 13, "bold"), padding=12)
    sty.configure("Stop.TButton", background=RED, foreground="white", font=("Segoe UI", 13, "bold"), padding=12)

    v_backend, v_adapter, v_state, v_ip, v_central = (tk.StringVar() for _ in range(5))
    v_mode = tk.StringVar(value=st.get("mode") or conf.get("SCAN") or "active")
    v_minutes = tk.StringVar(value=str(st.get("minutes", 0)))
    v_open = tk.BooleanVar(value=bool(st.get("auto_open")))
    v_signin = tk.BooleanVar(value=bool(st.get("signin")))
    pad = {"padx": 14, "pady": 4}

    top = ttk.Frame(root)
    top.pack(fill="x", padx=14, pady=(12, 0))
    ttk.Label(top, text="OT Sense sensor", style="H.TLabel").pack(side="left")
    pill = tk.Label(top, text="  STOPPED  ", bg="#33445a", fg="#ffffff", font=("Segoe UI", 11, "bold"), padx=8, pady=3)
    pill.pack(side="right")
    ttk.Label(root, text="Site: %s    (runs the Linux sensor inside your PC, so it can see real MAC addresses and ARP)" % (site or "(vm.conf missing)"),
              style="M.TLabel", wraplength=740).pack(anchor="w", padx=14)

    f1 = ttk.LabelFrame(root, text=" 1. Network - choose your Wi-Fi (or cable) ")
    f1.pack(fill="x", **pad)
    cb_ad = ttk.Combobox(f1, textvariable=v_adapter, state="readonly", width=78)
    cb_ad.pack(side="left", padx=8, pady=8)
    b_ref = ttk.Button(f1, text="Refresh")
    b_ref.pack(side="left", padx=4)

    f2 = ttk.LabelFrame(root, text=" 2. Scanning ")
    f2.pack(fill="x", **pad)
    ttk.Radiobutton(f2, text="Passive - only listen, send nothing", variable=v_mode, value="passive").pack(anchor="w", padx=8, pady=(6, 0))
    ttk.Radiobutton(f2, text="Active - also ask every device on the network (finds MAC addresses and vendors)", variable=v_mode, value="active").pack(anchor="w", padx=8)
    r2 = ttk.Frame(f2)
    r2.pack(anchor="w", padx=8, pady=6)
    ttk.Label(r2, text="Stop automatically after").pack(side="left")
    ttk.Spinbox(r2, from_=0, to=1440, width=6, textvariable=v_minutes).pack(side="left", padx=6)
    ttk.Label(r2, text="minutes   (0 = keep running until I press Stop)", style="M.TLabel").pack(side="left")
    ttk.Label(f2, text="Central can also set Passive/Active for the whole site (Sites tab); that takes priority once the sensor has connected.",
              style="M.TLabel", wraplength=720).pack(anchor="w", padx=8, pady=(0, 6))

    bt = ttk.Frame(root)
    bt.pack(fill="x", **pad)
    b_start = ttk.Button(bt, text="\u25B6   START", style="Go.TButton")
    b_stop = ttk.Button(bt, text="\u25A0   STOP", style="Stop.TButton")
    b_start.pack(side="left", padx=(0, 10), ipadx=20)
    b_stop.pack(side="left", ipadx=20)

    fix = ttk.Frame(root)         # shown only when no VM software is ready
    fix_msg = ttk.Label(fix, text="", style="M.TLabel", wraplength=740)
    fix_msg.pack(anchor="w")
    fx = ttk.Frame(fix)
    fx.pack(anchor="w", pady=4)
    b_hv = ttk.Button(fx, text="Turn on Hyper-V (one restart)")
    b_vb = ttk.Button(fx, text="Install VirtualBox (free, automatic)")
    b_hv.pack(side="left", padx=(0, 8))
    b_vb.pack(side="left")

    g = ttk.Frame(root)
    g.pack(fill="x", **pad)
    ttk.Label(g, text="VM software", style="M.TLabel").grid(row=0, column=0, sticky="w")
    cb_back = ttk.Combobox(g, textvariable=v_backend, state="readonly", width=60)
    cb_back.grid(row=0, column=1, sticky="w", padx=10, pady=2)
    ttk.Label(g, text="VM state", style="M.TLabel").grid(row=1, column=0, sticky="w")
    ttk.Label(g, textvariable=v_state).grid(row=1, column=1, sticky="w", padx=10)
    ttk.Label(g, text="Sensor address", style="M.TLabel").grid(row=2, column=0, sticky="w")
    ttk.Label(g, textvariable=v_ip).grid(row=2, column=1, sticky="w", padx=10)
    ttk.Label(g, text="Central", style="M.TLabel").grid(row=3, column=0, sticky="w")
    ttk.Label(g, textvariable=v_central, wraplength=560).grid(row=3, column=1, sticky="w", padx=10)

    b2 = ttk.Frame(root)
    b2.pack(fill="x", **pad)
    b_page = ttk.Button(b2, text="Open sensor page")
    b_test = ttk.Button(b2, text="Test connection to central")
    b_cons = ttk.Button(b2, text="Show VM screen")
    b_rem = ttk.Button(b2, text="Remove VM")
    for b in (b_page, b_test, b_cons, b_rem):
        b.pack(side="left", padx=(0, 6))
    ttk.Checkbutton(root, text="Start the sensor as soon as this window opens", variable=v_open).pack(anchor="w", padx=14)
    ttk.Checkbutton(root, text="Start automatically when I sign in to Windows", variable=v_signin).pack(anchor="w", padx=14)

    logbox = tk.Text(root, height=9, bg="#0a111b", fg="#b8c7d6", insertbackground="#fff", relief="flat", wrap="word")
    logbox.pack(fill="both", expand=True, padx=14, pady=(8, 12))
    logbox.configure(state="disabled")

    def log(msg):
        def w():
            logbox.configure(state="normal")
            logbox.insert("end", time.strftime("%H:%M:%S  ") + str(msg) + "\n")
            logbox.see("end")
            logbox.configure(state="disabled")
        root.after(0, w)

    def ui(fn, *a):
        root.after(0, lambda: fn(*a))

    def cur_backend():
        sel = v_backend.get()
        for be in backends.values():
            if sel.startswith(be.title):
                return be
        return None

    def cur_adapter():
        sel = v_adapter.get()
        for a in S["adapters"]:
            if sel.startswith(a["name"] + "  "):
                return a
        return None

    def worker(fn):
        def go():
            if S["busy"]:
                return
            S["busy"] = True
            try:
                fn()
            except Exception as e:
                log("Error: %s" % e)
            finally:
                S["busy"] = False
        threading.Thread(target=go, daemon=True).start()

    def save():
        try:
            mins = max(0, int(float(v_minutes.get() or 0)))
        except ValueError:
            mins = 0
        be, ad = cur_backend(), cur_adapter()
        st.update({"mode": v_mode.get(), "minutes": mins, "auto_open": bool(v_open.get()), "signin": bool(v_signin.get())})
        if be:
            st["backend"] = be.key
        if ad:
            st["adapter"] = ad["name"]
        save_settings(folder, st)
        return mins

    def show_fix():
        hv_ok, hv_why = backends["hyperv"].available()
        vb_ok, _ = backends["virtualbox"].available()
        if hv_ok or vb_ok:
            ui(fix.pack_forget)
            return
        ui(fix_msg.configure, text="This PC needs VM software to run the sensor. Press ONE of the buttons below (VirtualBox works on every Windows; Hyper-V only on Windows Pro/Enterprise).")
        ui(lambda: fix.pack(fill="x", padx=14, pady=4, before=g))

    def detect():
        labels = []
        for k, be in backends.items():
            ok, why = be.available()
            avail[k] = ok
            labels.append(be.title + ("" if ok else "  (not available)"))
        pref = backends.get(st.get("backend", ""), backends["hyperv"]).title
        pick = next((l for l in labels if l.startswith(pref) and "not available" not in l), None) or next((l for l in labels if "not available" not in l), labels[0])

        def done():
            cb_back["values"] = labels
            v_backend.set(pick)
            log("Using %s." % pick.split("  ")[0] if "not available" not in pick else "No VM software is ready yet - use the button that appeared.")
        ui(done)
        show_fix()

    def load_adapters():
        ad = list_adapters()
        S["adapters"] = ad
        labels = ["%s  -  %s%s%s" % (a["name"], a["desc"], "  [Wi-Fi]" if a["wifi"] else "", "" if a["status"] == "Up" else "  (%s)" % a["status"]) for a in ad]

        def done():
            cb_ad["values"] = labels
            want = st.get("adapter", "")
            v_adapter.set(next((l for l in labels if want and l.startswith(want + "  ")), labels[0] if labels else ""))
            if not labels:
                log("No network adapter found.")
        ui(done)

    def start(auto=False):
        be, ad = cur_backend(), cur_adapter()
        if not be or not avail.get(be.key):
            show_fix()
            return messagebox.showwarning(APP_NAME, "No VM software is ready yet. Press 'Turn on Hyper-V' or 'Install VirtualBox' first.")
        if not ad:
            return messagebox.showwarning(APP_NAME, "Choose the network (your Wi-Fi or cable) the sensor should scan.")
        if not S["iso"] or not os.path.isfile(S["iso"]):
            return messagebox.showwarning(APP_NAME, "The sensor file (.iso) is not next to this app. Extract the WHOLE zip into one folder and open the app from there.")
        if be.key == "hyperv" and not is_admin():
            return messagebox.showwarning(APP_NAME, "Hyper-V needs administrator rights. Close this window, right-click the app and choose 'Run as administrator'.")
        if ad["wifi"] and be.key == "hyperv" and not st.get("wifi_ok") and not auto:
            if not messagebox.askokcancel(APP_NAME, "Hyper-V will create a virtual switch on your Wi-Fi adapter. Windows keeps working, but Wi-Fi drops for a few seconds, "
                                          "and some routers refuse extra devices on Wi-Fi. VirtualBox is often smoother over Wi-Fi.\n\nContinue?"):
                return
            st["wifi_ok"] = True
        mins = save()
        mode = v_mode.get()

        def job():
            if be.state() == "running":
                log("The sensor is already running. Press STOP first to change the network or scanning.")
                return
            be.release_iso()
            ok, msg = patch_scan(S["iso"], mode, S["slot"])
            log("Scanning: %s (%s)." % (mode, msg) if ok else "Could not set the scanning mode (%s). Starting with the mode stored in the ISO." % msg)
            log("Starting the sensor VM on %s ..." % ad["name"])
            if be.key == "hyperv":
                rc, out = be.ensure_and_start(S["iso"], ad["name"])
            else:
                rc, out = be.ensure_and_start(S["iso"], ad["desc"], ad["name"])
            if rc == 0:
                S["deadline"] = time.time() + mins * 60 if mins else 0
                log("Started. The sensor needs 1-3 minutes to boot, then the site turns green in central." + (" It stops by itself in %d minutes." % mins if mins else ""))
            else:
                log("FAILED: " + out)
        worker(job)

    def stop():
        be = cur_backend()
        if not be:
            return

        def job():
            S["deadline"] = 0
            rc, out = be.stop()
            log("Stopped." if rc == 0 else "Stop: " + out)
        worker(job)

    def remove():
        be, ad = cur_backend(), cur_adapter()
        if not be or not messagebox.askyesno(APP_NAME, "Delete the sensor VM from this PC?\n(The sensor file stays. Hyper-V: the virtual switch on the adapter is removed too.)"):
            return

        def job():
            rc, out = be.remove(ad["name"] if ad else "")
            log("VM removed." if rc == 0 else "Remove: " + out)
        worker(job)

    def do_hyperv():
        def job():
            log("Turning on Hyper-V (this takes a minute) ...")
            rc, out = enable_hyperv()
            if rc != 0:
                log("Could not turn on Hyper-V: " + out)
                return
            log("Hyper-V is switched on. Windows must restart once to finish.")
            if messagebox.askyesno(APP_NAME, "Hyper-V is switched on.\n\nRestart the PC now to finish? (Save your work first. Open this app again after the restart.)"):
                run(restart_pc_cmd(), 20)
        worker(job)

    def do_vbox():
        def job():
            log("Installing VirtualBox (about 100 MB, a few minutes; accept the Windows prompts) ...")
            rc, out = install_virtualbox()
            if rc == 127:
                log("Windows could not install it automatically. Opening the download page: install VirtualBox, then open this app again.")
                webbrowser.open("https://www.virtualbox.org/wiki/Downloads")
                return
            log("VirtualBox installed." if rc == 0 else "VirtualBox install said: " + out[-300:])
            detect()
        worker(job)

    def open_page():
        if S["ip"]:
            webbrowser.open("http://%s" % S["ip"])
        else:
            messagebox.showinfo(APP_NAME, "The sensor address is not known yet (it appears 1-3 minutes after START). You can also see the site in central > Sites.")

    def show_console():
        be = cur_backend()
        if not be or not be.console():
            messagebox.showinfo(APP_NAME, "The VM screen is only available with Hyper-V. With VirtualBox the VM runs in the background.")

    def test_c():
        def job():
            ok, msg = test_central(conf.get("CENTRAL", ""))
            ui(v_central.set, ("OK - " if ok else "FAILED - ") + msg)
            log("Central: " + msg)
        worker(job)

    def signin_changed():
        save()

        def job():
            rc, out = run(signin_task_cmd(exe_path, bool(v_signin.get())), 30)
            log(("Will start automatically when you sign in to Windows." if v_signin.get() else "Automatic start at sign-in is off.") if rc == 0 else "Sign-in task: " + out)
        threading.Thread(target=job, daemon=True).start()

    def poll():
        while True:
            try:
                be = cur_backend()
                if be and avail.get(be.key):
                    s = be.state()
                    ip = ""
                    if s == "running":
                        mac, ip = be.mac_ip()
                        ip = ip or arp_lookup(mac)
                        if S["deadline"] and time.time() >= S["deadline"]:
                            S["deadline"] = 0
                            log("The time you set is over - stopping the sensor.")
                            be.stop()
                    S["ip"] = ip
                    ui(v_state.set, s)
                    ui(v_ip.set, ip or ("(waiting for an address...)" if s == "running" else "-"))
                    ui(lambda: pill.configure(text="  RUNNING  " if s == "running" else "  STOPPED  ", bg=ACC if s == "running" else "#33445a"))
            except Exception:
                pass
            time.sleep(4)

    def on_close():
        be = cur_backend()
        running = False
        try:
            running = bool(be and avail.get(be.key) and be.state() == "running")
        except Exception:
            pass
        save()
        if running:
            a = messagebox.askyesnocancel(APP_NAME, "The sensor is running.\n\nYes = keep it running in the background and close this window\nNo = stop the sensor and close\nCancel = stay")
            if a is None:
                return
            if a is False:
                be.stop()
        root.destroy()

    b_start.configure(command=start)
    b_stop.configure(command=stop)
    b_rem.configure(command=remove)
    b_page.configure(command=open_page)
    b_cons.configure(command=show_console)
    b_test.configure(command=test_c)
    b_hv.configure(command=do_hyperv)
    b_vb.configure(command=do_vbox)
    b_ref.configure(command=lambda: threading.Thread(target=load_adapters, daemon=True).start())
    root.protocol("WM_DELETE_WINDOW", on_close)
    for var in (v_signin,):
        var.trace_add("write", lambda *a: signin_changed())

    v_state.set("checking...")
    v_ip.set("-")
    v_central.set("not tested")
    if not conf:
        log("vm.conf not found next to this app - re-download the zip from central and extract ALL of it into one folder.")
    if S["iso"]:
        off, d = read_slot(S["iso"])
        S["slot"] = off
        if d.get("scan") in ("passive", "active") and not st.get("mode"):
            v_mode.set(d["scan"])
    log("Folder: %s" % folder)

    def boot():
        detect()
        load_adapters()
        if conf.get("CENTRAL"):
            ok, msg = test_central(conf.get("CENTRAL"))
            ui(v_central.set, ("OK - " if ok else "FAILED - ") + msg)
        threading.Thread(target=poll, daemon=True).start()
        time.sleep(1.5)
        if auto_flag or st.get("auto_open"):
            ui(lambda: start(True))
    threading.Thread(target=boot, daemon=True).start()
    root.mainloop()


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        gui()
        
