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


# ---------------------------------------------------------------- self test (no GUI, no VM)
def selftest():
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
    assert arp_lookup("08:00:27:AA:BB:CC", fake) == "192.168.1.77"
    assert slug("Plant Pune #1") == "plant-pune-1"
    print("selftest OK")


# ---------------------------------------------------------------- GUI
def gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    folder = app_dir()
    conf = read_kv(os.path.join(folder, "vm.conf"))
    site = conf.get("SITE", "")
    st = load_settings(folder)
    st_lock = threading.Lock()
    S = {"iso": find_iso(folder, conf), "adapters": [], "ip": "", "mac": "", "busy": False}
    vmname = "OTSense-" + slug(site or "sensor")
    backends = {"hyperv": HyperV(vmname), "virtualbox": VirtualBox(vmname)}
    avail = {}

    root = tk.Tk()
    root.title("%s - %s" % (APP_NAME, site or "sensor"))
    root.geometry("760x640")
    BG, FG, MUT, ACC = "#0d1520", "#e6edf5", "#8fa3b8", "#1f6f7a"
    root.configure(bg=BG)
    sty = ttk.Style(root)
    try:
        sty.theme_use("clam")
    except Exception:
        pass
    sty.configure(".", background=BG, foreground=FG, fieldbackground="#101b29")
    sty.configure("TLabel", background=BG, foreground=FG)
    sty.configure("M.TLabel", foreground=MUT)
    sty.configure("H.TLabel", font=("Segoe UI", 14, "bold"))
    sty.configure("TButton", padding=6)
    sty.configure("P.TButton", background=ACC, foreground="white")

    v_backend, v_adapter, v_state, v_ip, v_central, v_iso = (tk.StringVar() for _ in range(6))
    pad = {"padx": 12, "pady": 4}

    ttk.Label(root, text="OT Sense sensor VM", style="H.TLabel").pack(anchor="w", padx=12, pady=(12, 0))
    ttk.Label(root, text="Site: %s" % (site or "(vm.conf missing)"), style="M.TLabel").pack(anchor="w", padx=12)
    ttk.Label(root, text="Runs the Linux sensor in a virtual machine on this PC, bridged to the network adapter you choose, so it can scan with real ARP.",
              style="M.TLabel", wraplength=720).pack(anchor="w", **pad)

    f = ttk.Frame(root)
    f.pack(fill="x", **pad)
    ttk.Label(f, text="VM software").grid(row=0, column=0, sticky="w")
    cb_back = ttk.Combobox(f, textvariable=v_backend, state="readonly", width=48)
    cb_back.grid(row=0, column=1, sticky="we", padx=8, pady=3)
    ttk.Label(f, text="Network adapter").grid(row=1, column=0, sticky="w")
    cb_ad = ttk.Combobox(f, textvariable=v_adapter, state="readonly", width=48)
    cb_ad.grid(row=1, column=1, sticky="we", padx=8, pady=3)
    b_ref = ttk.Button(f, text="Refresh")
    b_ref.grid(row=1, column=2)
    ttk.Label(f, text="Sensor ISO").grid(row=2, column=0, sticky="w")
    ttk.Label(f, textvariable=v_iso, style="M.TLabel", wraplength=480).grid(row=2, column=1, sticky="w", padx=8)
    b_iso = ttk.Button(f, text="Choose...")
    b_iso.grid(row=2, column=2)
    f.columnconfigure(1, weight=1)

    g = ttk.Frame(root)
    g.pack(fill="x", **pad)
    for i, (lab, var) in enumerate((("VM state", v_state), ("Sensor address", v_ip), ("Central", v_central))):
        ttk.Label(g, text=lab, style="M.TLabel").grid(row=i, column=0, sticky="w")
        ttk.Label(g, textvariable=var).grid(row=i, column=1, sticky="w", padx=10)

    bt = ttk.Frame(root)
    bt.pack(fill="x", **pad)
    b_start = ttk.Button(bt, text="Start", style="P.TButton")
    b_stop = ttk.Button(bt, text="Stop")
    b_page = ttk.Button(bt, text="Open sensor page")
    b_cons = ttk.Button(bt, text="Show VM screen")
    b_test = ttk.Button(bt, text="Test connection to central")
    b_rem = ttk.Button(bt, text="Remove VM")
    for b in (b_start, b_stop, b_page, b_cons, b_test, b_rem):
        b.pack(side="left", padx=3)

    logbox = tk.Text(root, height=14, bg="#0a111b", fg="#b8c7d6", insertbackground="#fff", relief="flat", wrap="word")
    logbox.pack(fill="both", expand=True, padx=12, pady=(6, 12))
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
        for k, be in backends.items():
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

    def detect():
        labels = []
        for k, be in backends.items():
            ok, why = be.available()
            avail[k] = ok
            labels.append(be.title + ("" if ok else "  (not available: %s)" % why))
        pref = st.get("backend", "")
        pick = next((l for l in labels if (l.startswith(backends.get(pref, backends["hyperv"]).title) and "not available" not in l)), None) \
            or next((l for l in labels if "not available" not in l), labels[0])

        def done():
            cb_back["values"] = labels
            v_backend.set(pick)
            if not any(avail.values()):
                log("Neither Hyper-V nor VirtualBox is available. Install VirtualBox (free, works on every Windows edition) from https://www.virtualbox.org/ - or enable Hyper-V on Windows Pro.")
                if messagebox.askyesno(APP_NAME, "Neither Hyper-V nor VirtualBox was found.\n\nOpen the VirtualBox download page?"):
                    webbrowser.open("https://www.virtualbox.org/wiki/Downloads")
            else:
                log("Using %s." % pick.split("  ")[0])
        ui(done)

    def load_adapters():
        ad = list_adapters()
        S["adapters"] = ad
        labels = ["%s  -  %s%s%s" % (a["name"], a["desc"], "  [Wi-Fi]" if a["wifi"] else "", "" if a["status"] == "Up" else "  (%s)" % a["status"]) for a in ad]

        def done():
            cb_ad["values"] = labels
            want = st.get("adapter", "")
            pick = next((l for l in labels if l.startswith(want + "  ")), labels[0] if labels else "")
            v_adapter.set(pick)
            if not labels:
                log("No network adapter found.")
        ui(done)

    def start():
        be, ad = cur_backend(), cur_adapter()
        if not be or not avail.get(be.key):
            return messagebox.showwarning(APP_NAME, "Choose an available VM software first.")
        if not ad:
            return messagebox.showwarning(APP_NAME, "Choose the network adapter the sensor should scan (your Wi-Fi or Ethernet).")
        if not S["iso"] or not os.path.isfile(S["iso"]):
            return messagebox.showwarning(APP_NAME, "Sensor ISO not found. Put otsense-sensor-<site>.iso next to this app, or press Choose.")
        if be.key == "hyperv" and not is_admin():
            return messagebox.showwarning(APP_NAME, "Hyper-V needs administrator rights. Close this window, right-click the app and choose Run as administrator.")
        if ad["wifi"] and be.key == "hyperv" and not messagebox.askokcancel(
                APP_NAME, "Hyper-V will create a virtual switch on your Wi-Fi adapter. Windows keeps working, but the Wi-Fi connection drops for a few seconds, "
                          "and some routers refuse extra devices on Wi-Fi. VirtualBox is often smoother over Wi-Fi.\n\nContinue?"):
            return
        st.update({"backend": be.key, "adapter": ad["name"]})
        save_settings(folder, st)

        def job():
            log("Starting the sensor VM on %s ..." % ad["name"])
            if be.key == "hyperv":
                rc, out = be.ensure_and_start(S["iso"], ad["name"])
            else:
                rc, out = be.ensure_and_start(S["iso"], ad["desc"], ad["name"])
            log(("Started. The sensor takes 1-3 minutes to boot and appear in central." if rc == 0 else "FAILED: " + out))
        worker(job)

    def stop():
        be = cur_backend()
        if not be:
            return

        def job():
            rc, out = be.stop()
            log("Stopped." if rc == 0 else "Stop: " + out)
        worker(job)

    def remove():
        be, ad = cur_backend(), cur_adapter()
        if not be or not messagebox.askyesno(APP_NAME, "Delete the sensor VM from this PC?\n(The ISO stays. Hyper-V: the virtual switch on the adapter is removed too.)"):
            return

        def job():
            rc, out = be.remove(ad["name"] if ad else "")
            log("VM removed." if rc == 0 else "Remove: " + out)
        worker(job)

    def open_page():
        if S["ip"]:
            webbrowser.open("http://%s" % S["ip"])
        else:
            messagebox.showinfo(APP_NAME, "The sensor address is not known yet (it appears 1-3 minutes after Start). You can also see it in your router or in central > Sites.")

    def show_console():
        be = cur_backend()
        if not be or not be.console():
            messagebox.showinfo(APP_NAME, "The VM screen is only available with Hyper-V. With VirtualBox the VM runs in the background (open VirtualBox to see it).")

    def test_c():
        def job():
            ok, msg = test_central(conf.get("CENTRAL", ""))
            ui(v_central.set, ("OK - " if ok else "FAILED - ") + msg)
            log("Central: " + msg)
        worker(job)

    def choose_iso():
        p = filedialog.askopenfilename(title="Choose the sensor ISO", filetypes=[("ISO image", "*.iso")], initialdir=folder)
        if p:
            S["iso"] = p
            v_iso.set(p)

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
                    S["ip"] = ip
                    ui(v_state.set, s)
                    ui(v_ip.set, ip or ("(waiting for an address...)" if s == "running" else "-"))
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
        if running:
            a = messagebox.askyesnocancel(APP_NAME, "The sensor VM is running.\n\nYes = keep it running in the background and close this window\nNo = stop the VM and close\nCancel = stay")
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
    b_iso.configure(command=choose_iso)
    b_ref.configure(command=lambda: threading.Thread(target=load_adapters, daemon=True).start())
    root.protocol("WM_DELETE_WINDOW", on_close)

    v_iso.set(S["iso"] or "(not found - press Choose)")
    v_state.set("checking...")
    v_ip.set("-")
    v_central.set("not tested")
    if not conf:
        log("vm.conf not found next to this app - the site name and central address are unknown. Re-download the launcher from central.")
    log("Folder: %s" % folder)

    def boot():
        detect()
        load_adapters()
        if conf.get("CENTRAL"):
            ok, msg = test_central(conf.get("CENTRAL"))
            ui(v_central.set, ("OK - " if ok else "FAILED - ") + msg)
        poll()
    threading.Thread(target=boot, daemon=True).start()
    root.mainloop()


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        gui()
