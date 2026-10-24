#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OTSense - passive OT/IT asset discovery, deep packet inspection and threat detection.

An open, single-file take on what Armis / Claroty / Nozomi do: listen passively on a SPAN/TAP
port (or read a pcap), build an asset inventory (IP, MAC, vendor, model, firmware, role,
protocols) and flag risky OT behaviour (writes, stops, program downloads, scans, ARP spoofing).

Zero required dependencies (Python 3.8+). Optional: scapy for live capture on Windows/macOS.

  python otsense.py pcap capture.pcap -o out          # analyse a pcap / pcapng file
  sudo python otsense.py live -i eth0 -t 300 -o out   # live capture from a SPAN-fed NIC
  python otsense.py web --port 8080                   # dashboard with pcap upload + live capture
  python otsense.py sample sample_ot.pcap             # make a synthetic OT pcap to test with
  python otsense.py nmap 192.168.10.0/24              # (optional) safe ARP-ping discovery via nmap
  python otsense.py ifaces                            # list capture interfaces

Use only on networks you own or are authorised to monitor.
"""
import argparse
import base64
import collections
import csv
import datetime
import gzip
import hashlib
import hmac
import io
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import struct
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.request
from functools import lru_cache

VERSION = "1.3"

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# ----------------------------------------------------------------------------------------------
# small helpers
# ----------------------------------------------------------------------------------------------


def mac_str(b):
    return ":".join("%02x" % x for x in b)


def u16(b, o):
    return (b[o] << 8) | b[o + 1]


def u32(b, o):
    return (b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]


def txt(b):
    return bytes(b).decode("latin-1", "replace").strip("\x00 \r\n\t")


def iso(ts):
    if ts is None:
        return None
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


@lru_cache(maxsize=65536)
def ip_obj(ip):
    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        return None


def ip_is_global(ip):
    o = ip_obj(ip)
    return bool(o and o.is_global and not o.is_multicast)


def ip_is_mcast(ip):
    o = ip_obj(ip)
    return bool(o and (o.is_multicast or ip == "255.255.255.255"))


def ascii_runs(data, minlen=5):
    return re.findall(rb"[\x20-\x7e]{%d,}" % minlen, data)


# ----------------------------------------------------------------------------------------------
# MAC vendor lookup (small ICS-focused table; load a full list with --oui)
# ----------------------------------------------------------------------------------------------

OUI = {
    # ICS / OT vendors
    "000e8c": "Siemens", "001b1b": "Siemens", "001c06": "Siemens", "080006": "Siemens", "286336": "Siemens",
    "ac6417": "Siemens",
    "0000bc": "Rockwell Automation / Allen-Bradley", "001d9c": "Rockwell Automation / Allen-Bradley",
    "5c8816": "Rockwell Automation / Allen-Bradley", "e49069": "Rockwell Automation / Allen-Bradley",
    "0080f4": "Schneider Electric (Telemecanique)", "000054": "Schneider Electric",
    "00000a": "Omron", "0090e8": "Moxa", "008063": "Hirschmann (Belden)",
    "00a045": "Phoenix Contact", "000105": "Beckhoff Automation", "0030de": "WAGO", "006065": "B&R Automation",
    "000064": "Yokogawa",
    # IT / virtualisation
    "00000c": "Cisco", "005056": "VMware", "000c29": "VMware", "000569": "VMware", "00155d": "Microsoft (Hyper-V)",
    "d4bed9": "Dell", "001b21": "Intel", "b827eb": "Raspberry Pi Foundation", "dca632": "Raspberry Pi Trading",
    "001cb3": "Apple",
}
OT_VENDOR_HINTS = ("siemens", "rockwell", "allen-bradley", "schneider", "omron", "moxa", "hirschmann",
                   "phoenix", "beckhoff", "wago", "b&r", "yokogawa", "abb", "honeywell", "emerson", "mitsubishi",
                   "ge ", "festo", "hms")


def load_oui_file(path):
    """Load an nmap-mac-prefixes or Wireshark 'manuf' file."""
    n = 0
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(r"^([0-9A-Fa-f]{6})\s+(.+)$", line)
                if m:
                    OUI.setdefault(m.group(1).lower(), m.group(2).strip())
                    n += 1
                    continue
                m = re.match(r"^([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})\s+(\S+)(?:\s+(.+))?$", line)
                if m:
                    OUI.setdefault(m.group(1).replace(":", "").lower(), (m.group(3) or m.group(2)).strip())
                    n += 1
    except OSError:
        pass
    return n


for _p in ("/usr/share/nmap/nmap-mac-prefixes", "/usr/share/wireshark/manuf", "/usr/share/ieee-data/oui.txt"):
    if os.path.exists(_p):
        load_oui_file(_p)


@lru_cache(maxsize=65536)
def mac_vendor(mac):
    if not mac:
        return None
    m = mac.lower().replace(":", "").replace("-", "")
    if len(m) < 6:
        return None
    if int(m[:2], 16) & 2:
        return "Locally administered / random"
    return OUI.get(m[:6])


# ----------------------------------------------------------------------------------------------
# pcap / pcapng reader (pure python)
# ----------------------------------------------------------------------------------------------


def read_pcap(path):
    """Yield (timestamp, linktype, bytes) from a pcap or pcapng file."""
    with open(path, "rb") as f:
        head = f.read(4)
        if len(head) < 4:
            return
        if head == b"\x0a\x0d\x0d\x0a":
            f.seek(0)
            for item in _read_pcapng(f):
                yield item
            return
        magics = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
                  b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}
        if head not in magics:
            raise ValueError("not a pcap/pcapng file")
        end, res = magics[head]
        rest = f.read(20)
        link = struct.unpack(end + "I", rest[16:20])[0] & 0x0FFFFFFF
        while True:
            h = f.read(16)
            if len(h) < 16:
                break
            sec, frac, incl, _orig = struct.unpack(end + "IIII", h)
            data = f.read(incl)
            if len(data) < incl:
                break
            yield sec + frac * res, link, data


def _read_pcapng(f):
    end = "<"
    ifaces = []  # (linktype, tsresol)
    while True:
        h = f.read(8)
        if len(h) < 8:
            break
        if h[:4] == b"\x0a\x0d\x0d\x0a":  # section header block
            bom = f.read(4)
            end = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(end + "I", h[4:8])[0]
            f.read(max(0, blen - 12))
            ifaces = []
            continue
        btype, blen = struct.unpack(end + "II", h)
        if blen < 12:
            break
        body = f.read(blen - 8)
        if len(body) < blen - 8:
            break
        body = body[:-4]
        if btype == 1 and len(body) >= 8:  # interface description
            link = struct.unpack(end + "H", body[:2])[0]
            tsres = 1e-6
            o = 8
            while o + 4 <= len(body):
                code, ln = struct.unpack(end + "HH", body[o:o + 4])
                if code == 0:
                    break
                val = body[o + 4:o + 4 + ln]
                if code == 9 and ln >= 1:
                    v = val[0]
                    tsres = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                o += 4 + ((ln + 3) & ~3)
            ifaces.append((link, tsres))
        elif btype == 6 and len(body) >= 20:  # enhanced packet
            ifid, th, tl, cap, _orig = struct.unpack(end + "IIIII", body[:20])
            link, tsres = ifaces[ifid] if ifid < len(ifaces) else (1, 1e-6)
            yield ((th << 32) | tl) * tsres, link, body[20:20 + cap]
        elif btype == 3 and len(body) >= 4:  # simple packet
            link = ifaces[0][0] if ifaces else 1
            yield 0.0, link, body[4:]


# ----------------------------------------------------------------------------------------------
# frame parsing (L2 / L3 / L4) - manual, fast, no scapy
# ----------------------------------------------------------------------------------------------


def parse_l2(link, d):
    """-> (smac, dmac, vlan, ethertype, payload) or None"""
    if link == 1:
        if len(d) < 14:
            return None
        dmac, smac, et = mac_str(d[0:6]), mac_str(d[6:12]), u16(d, 12)
        off, vlan = 14, None
        while et in (0x8100, 0x88A8, 0x9100) and len(d) >= off + 4:
            vlan = u16(d, off) & 0x0FFF
            et = u16(d, off + 2)
            off += 4
        if et < 0x600:
            return None
        return smac, dmac, vlan, et, d[off:]
    if link == 113 and len(d) >= 16:  # Linux cooked v1
        alen = u16(d, 4)
        smac = mac_str(d[6:12]) if alen == 6 else None
        return smac, None, None, u16(d, 14), d[16:]
    if link == 276 and len(d) >= 20:  # Linux cooked v2
        alen = d[11]
        smac = mac_str(d[12:18]) if alen == 6 else None
        return smac, None, None, u16(d, 0), d[20:]
    if link == 0 and len(d) >= 4:  # BSD loopback
        fam = struct.unpack("<I", d[:4])[0]
        return None, None, None, (0x0800 if fam == 2 else 0x86DD), d[4:]
    if link in (101, 12, 14) and d:
        v = d[0] >> 4
        return None, None, None, (0x0800 if v == 4 else 0x86DD if v == 6 else 0), d
    return None


def parse_ip(et, p):
    """-> (src, dst, proto, ttl, l4payload, fragoffset) or None"""
    if et == 0x0800:
        if len(p) < 20 or (p[0] >> 4) != 4:
            return None
        ihl = (p[0] & 15) * 4
        tot = u16(p, 2)
        if ihl < 20 or tot < ihl:
            return None
        frag = ((p[6] & 0x1F) << 8) | p[7]
        end = tot if tot <= len(p) else len(p)
        return socket.inet_ntoa(p[12:16]), socket.inet_ntoa(p[16:20]), p[9], p[8], p[ihl:end], frag
    if et == 0x86DD:
        if len(p) < 40:
            return None
        nh, hl, plen, o, frag = p[6], p[7], u16(p, 4), 40, 0
        while nh in (0, 43, 60, 44) and len(p) >= o + 8:
            if nh == 44:
                frag = 1
                nh = p[o]
                o += 8
                continue
            n2 = p[o]
            o += (p[o + 1] + 1) * 8
            nh = n2
        return (socket.inet_ntop(socket.AF_INET6, p[8:24]), socket.inet_ntop(socket.AF_INET6, p[24:40]),
                nh, hl, p[o:40 + plen], frag)
    return None


# ----------------------------------------------------------------------------------------------
# DPI: protocol parsers. Each returns an "event" dict or None.
#   cat: read | write | control | stop | program | upload | discover | session | response | info
# ----------------------------------------------------------------------------------------------


def EV(proto, ot=False, cat="info", func=None, info=None, side="server", cleartext=False, dir=None, detail=None):
    return {"proto": proto, "ot": ot, "cat": cat, "func": func, "info": info or {}, "side": side,
            "cleartext": cleartext, "dir": dir, "detail": detail}


# ---- Modbus/TCP -------------------------------------------------------------------------------
MODBUS_FC = {1: "Read Coils", 2: "Read Discrete Inputs", 3: "Read Holding Registers", 4: "Read Input Registers",
             5: "Write Single Coil", 6: "Write Single Register", 7: "Read Exception Status", 8: "Diagnostics",
             11: "Get Comm Event Counter", 12: "Get Comm Event Log", 15: "Write Multiple Coils",
             16: "Write Multiple Registers", 17: "Report Server ID", 20: "Read File Record",
             21: "Write File Record", 22: "Mask Write Register", 23: "Read/Write Multiple Registers",
             24: "Read FIFO Queue", 43: "Read Device Identification"}
MODBUS_WRITE = {5, 6, 15, 16, 21, 22, 23}
MODBUS_OBJ = {0: "vendor", 1: "product_code", 2: "firmware", 4: "product_name", 5: "model", 6: "app_name"}


def p_modbus(pl, to_server):
    if len(pl) < 8:
        return None
    pid, ln = u16(pl, 2), u16(pl, 4)
    if pid != 0 or ln < 2 or ln > len(pl) - 6:
        return None
    unit, fc = pl[6], pl[7]
    base = fc & 0x7F
    name = MODBUS_FC.get(base, "Function %d" % base)
    cat = "read"
    if base in MODBUS_WRITE:
        cat = "write"
    elif base == 8:
        sub = u16(pl, 8) if len(pl) >= 10 else 0
        cat = "control" if sub in (1, 4) else "read"
        name += " (sub %d)" % sub
    elif base in (43, 17):
        cat = "discover"
    info = {"modbus_units": [unit]}
    if not to_server:
        if fc & 0x80:
            name += " [exception]"
        cat = "response"
        if base == 43 and len(pl) >= 15 and pl[8] == 0x0E:
            o, n = 14, pl[13]
            for _ in range(n):
                if o + 2 > len(pl):
                    break
                oid, ol = pl[o], pl[o + 1]
                val = txt(pl[o + 2:o + 2 + ol])
                if oid in MODBUS_OBJ and val:
                    info[MODBUS_OBJ[oid]] = val
                o += 2 + ol
        elif base == 17 and len(pl) > 10:
            info["server_id"] = txt(pl[10:]).strip()[:40]
    return EV("Modbus/TCP", True, cat, name, info, "server")


# ---- Siemens S7comm / ISO-TSAP / MMS ----------------------------------------------------------
S7_JOB = {0x00: ("CPU services", "read"), 0x04: ("Read Var", "read"), 0x05: ("Write Var", "write"),
          0x1A: ("Request Download", "program"), 0x1B: ("Download Block", "program"),
          0x1C: ("Download Ended", "program"), 0x1D: ("Start Upload", "upload"), 0x1E: ("Upload", "upload"),
          0x1F: ("End Upload", "upload"), 0x28: ("PLC Control", "control"), 0x29: ("PLC Stop", "stop"),
          0xF0: ("Setup Communication", "session")}
S7_GROUP = {1: "Programmer", 2: "Cyclic data", 3: "Block functions", 4: "CPU functions", 5: "Security",
            6: "PBC", 7: "Time"}


def p_iso_tsap(pl, to_server):
    if len(pl) < 7 or pl[0] != 3 or pl[1] != 0:
        return None
    li, typ = pl[4], pl[5]
    if typ in (0xE0, 0xD0):  # connection request / confirm
        info, tsaps = {}, []
        o, end = 11, min(len(pl), 5 + li)
        while o + 2 <= end:
            code, ln = pl[o], pl[o + 1]
            val = pl[o + 2:o + 2 + ln]
            if code in (0xC1, 0xC2):
                tsaps.append(ln)
            if code == 0xC2 and ln == 2 and to_server:
                info["rack_slot"] = "%d/%d" % (val[1] >> 5, val[1] & 0x1F)
            o += 2 + ln
        label = "S7comm" if tsaps and all(x == 2 for x in tsaps) else "IEC 61850 MMS"
        return EV(label, True, "session", "COTP Connect " + ("Request" if typ == 0xE0 else "Confirm"), info, "server")
    if typ != 0xF0:
        return EV("ISO-TSAP", True, "session", "COTP 0x%02x" % typ)
    s7o = 5 + li
    if len(pl) <= s7o:
        return EV("ISO-TSAP", True, "session")
    b = pl[s7o]
    if b == 0x72:
        return EV("S7CommPlus", True, "session", "S7CommPlus (S7-1200/1500)", {"s7_family": "S7-1200/1500 (S7CommPlus)"})
    if b != 0x32:
        return EV("IEC 61850 MMS", True, "read", "MMS PDU")
    s = pl[s7o:]
    if len(s) < 10:
        return EV("S7comm", True, "session")
    ros = s[1]
    plen = u16(s, 6)
    hl = 12 if ros in (2, 3) else 10
    par = s[hl:hl + plen]
    info = {}
    name, cat = "ROSCTR %d" % ros, "read"
    if ros == 1 and par:
        name, cat = S7_JOB.get(par[0], ("Job 0x%02x" % par[0], "read"))
    elif ros == 7 and len(par) >= 8:
        grp, sub = par[5] & 0x0F, par[6]
        name, cat = "Userdata: " + S7_GROUP.get(grp, "group %d" % grp), "read"
        if grp == 4 and sub == 1:
            name, cat = "Read SZL (system info)", "discover"
        elif grp == 3:
            name, cat = "Block functions (list/get blocks)", "discover"
        elif grp == 7 and sub == 4:
            name, cat = "Set clock", "control"
    elif ros in (2, 3):
        name, cat = "Response", "response"
    if not to_server:
        cat = "response"
        m = re.search(rb"6ES7[ \-0-9A-Za-z]{6,22}", pl)
        if m:
            info["order_number"] = txt(m.group(0))
            info["vendor"] = "Siemens"
        m = re.search(rb"CPU ?[0-9]{3,4}[A-Za-z0-9/\- ]{0,16}", pl)
        if m:
            info["model"] = txt(m.group(0))
            info["vendor"] = "Siemens"
        m = re.search(rb"S C-[A-Z0-9]{6,12}", pl)
        if m:
            info["serial"] = txt(m.group(0))
        if info:
            m = re.search(rb"V ?[0-9]+\.[0-9]+(?:\.[0-9]+)?", pl)
            if m:
                info["firmware"] = txt(m.group(0))
    return EV("S7comm", True, cat, name, info, "server")


# ---- DNP3 --------------------------------------------------------------------------------------
DNP3_FC = {0: "Confirm", 1: "Read", 2: "Write", 3: "Select", 4: "Operate", 5: "Direct Operate",
           6: "Direct Operate (no ack)", 7: "Freeze", 8: "Freeze (no ack)", 9: "Freeze Clear", 13: "Cold Restart",
           14: "Warm Restart", 15: "Initialize Data", 16: "Initialize Application", 17: "Start Application",
           18: "Stop Application", 19: "Save Configuration", 20: "Enable Unsolicited", 21: "Disable Unsolicited",
           22: "Assign Class", 23: "Delay Measurement", 24: "Record Current Time", 25: "Open File",
           26: "Close File", 27: "Delete File", 28: "Get File Info", 29: "Authenticate Request",
           129: "Response", 130: "Unsolicited Response"}


def p_dnp3(pl, to_server):
    if len(pl) < 10 or pl[0] != 0x05 or pl[1] != 0x64:
        return None
    dst, src = struct.unpack("<HH", pl[4:8])
    info = {"dnp3_address": [str(dst if to_server else src)]}
    if len(pl) < 13:
        return EV("DNP3", True, "session", "Link layer", info, "server")
    fc = pl[12]
    name = DNP3_FC.get(fc, "Function %d" % fc)
    cat = "read"
    if fc in (2, 3, 4, 5, 6, 22, 27):
        cat = "write"
    elif fc in (13, 14, 15, 16, 17, 21):
        cat = "control"
    elif fc == 18:
        cat = "stop"
    elif fc in (129, 130):
        cat = "response"
    return EV("DNP3", True, cat, name, info, "server")


# ---- EtherNet/IP + CIP -------------------------------------------------------------------------
ENIP_CMD = {0x04: "ListServices", 0x63: "ListIdentity", 0x64: "ListInterfaces", 0x65: "RegisterSession",
            0x66: "UnRegisterSession", 0x6F: "SendRRData", 0x70: "SendUnitData"}
ENIP_VENDOR = {1: "Rockwell Automation / Allen-Bradley", 26: "Festo", 40: "WAGO", 47: "Omron", 90: "HMS Industrial"}
ENIP_DEVTYPE = {0x02: "AC Drive", 0x07: "Discrete I/O", 0x0C: "Communications Adapter", 0x0E: "PLC",
                0x2B: "Generic Device"}
CIP_SVC = {0x01: ("Get Attributes All", "read"), 0x02: ("Set Attributes All", "write"), 0x05: ("Reset", "control"),
           0x06: ("Start", "control"), 0x07: ("Stop", "stop"), 0x08: ("Create", "write"), 0x09: ("Delete", "write"),
           0x0E: ("Get Attribute Single", "read"), 0x10: ("Set Attribute Single", "write"),
           0x4C: ("Read Tag", "read"), 0x4D: ("Write Tag", "write"), 0x4E: ("Forward Close", "session"),
           0x52: ("Unconnected Send", "session"), 0x54: ("Forward Open", "session")}


def p_enip(pl, to_server):
    if len(pl) < 24:
        return None
    cmd = pl[0] | (pl[1] << 8)
    ln = pl[2] | (pl[3] << 8)
    if cmd not in ENIP_CMD or ln > len(pl) - 24:
        return None
    name, cat, info = ENIP_CMD[cmd], "session", {}
    if cmd == 0x63:
        cat = "discover" if to_server else "response"
        if not to_server and len(pl) >= 63 and (pl[26] | (pl[27] << 8)) == 0x0C:
            vid = pl[48] | (pl[49] << 8)
            dt = pl[50] | (pl[51] << 8)
            pc = pl[52] | (pl[53] << 8)
            sn = struct.unpack("<I", pl[58:62])[0]
            nl = pl[62]
            info = {"vendor": ENIP_VENDOR.get(vid, "CIP vendor id %d" % vid),
                    "device_type": ENIP_DEVTYPE.get(dt, "CIP device type 0x%02x" % dt),
                    "product_code": str(pc), "firmware": "%d.%d" % (pl[54], pl[55]),
                    "serial": "%08x" % sn, "product_name": txt(pl[63:63 + nl]),
                    "model": txt(pl[63:63 + nl])}
    elif cmd in (0x6F, 0x70) and len(pl) >= 40:
        try:
            o = 30
            cnt = pl[o] | (pl[o + 1] << 8)
            o += 2
            for _ in range(min(cnt, 4)):
                it = pl[o] | (pl[o + 1] << 8)
                il = pl[o + 2] | (pl[o + 3] << 8)
                d = pl[o + 4:o + 4 + il]
                o += 4 + il
                svc = None
                if it == 0xB2 and d:
                    svc = d[0]
                elif it == 0xB1 and len(d) > 2:
                    svc = d[2]
                if svc is not None:
                    base = svc & 0x7F
                    nm, ct = CIP_SVC.get(base, ("CIP service 0x%02x" % base, "read"))
                    name = nm
                    cat = "response" if (svc & 0x80) else ct
                    break
        except IndexError:
            pass
    return EV("EtherNet/IP", True, cat, name, info, "server")


def p_enip_io(pl, to_server):
    if len(pl) < 6:
        return None
    return EV("EtherNet/IP I/O", True, "info", "Implicit I/O (cyclic)")


# ---- BACnet/IP ---------------------------------------------------------------------------------
BAC_CONF = {7: "AtomicWriteFile", 12: "ReadProperty", 14: "ReadPropertyMultiple", 15: "WriteProperty",
            16: "WritePropertyMultiple", 17: "DeviceCommunicationControl", 20: "ReinitializeDevice",
            5: "SubscribeCOV", 10: "CreateObject", 11: "DeleteObject", 26: "ReadRange"}
BAC_UNCONF = {0: "I-Am", 1: "I-Have", 2: "UnconfirmedCOVNotification", 6: "TimeSynchronization", 7: "Who-Has",
              8: "Who-Is", 9: "UTCTimeSynchronization"}


def p_bacnet(pl, to_server):
    if len(pl) < 6 or pl[0] != 0x81:
        return None
    func = pl[1]
    o = 10 if func == 0x04 else 4
    if func not in (0x0A, 0x0B, 0x04, 0x09, 0x05, 0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x08):
        return None
    if len(pl) <= o + 2 or pl[o] != 1:
        return EV("BACnet/IP", True, "session", "BVLC 0x%02x" % func)
    ctrl = pl[o + 1]
    o += 2
    if ctrl & 0x20:
        o += 2
        o += 1 + pl[o]
        o += 1
    if ctrl & 0x08:
        o += 2
        o += 1 + pl[o]
    if ctrl & 0x80 or o >= len(pl):
        return EV("BACnet/IP", True, "session", "Network layer message")
    t = pl[o] >> 4
    info, name, cat = {}, "APDU type %d" % t, "read"
    if t == 0 and o + 3 < len(pl):
        svc = pl[o + 3]
        name = BAC_CONF.get(svc, "Confirmed service %d" % svc)
        if svc in (15, 16, 7, 10, 11):
            cat = "write"
        elif svc in (17, 20):
            cat = "control"
    elif t == 1 and o + 1 < len(pl):
        svc = pl[o + 1]
        name = BAC_UNCONF.get(svc, "Unconfirmed service %d" % svc)
        if svc == 8 or svc == 7:
            cat = "discover"
        elif svc == 0:
            cat = "response"
            seg = pl[o + 2:]
            if seg and seg[0] == 0xC4 and len(seg) >= 5:
                obj = u32(seg, 1)
                if (obj >> 22) == 8:
                    info["bacnet_instance"] = str(obj & 0x3FFFFF)
                i = seg.find(b"\x91", 5)
                if i != -1 and i + 2 < len(seg):
                    tag = seg[i + 2]
                    if tag == 0x21 and i + 3 < len(seg):
                        info["bacnet_vendor_id"] = str(seg[i + 3])
                    elif tag == 0x22 and i + 4 < len(seg):
                        info["bacnet_vendor_id"] = str(u16(seg, i + 3))
        elif svc in (6, 9):
            cat = "control"
    elif t in (2, 3, 4, 5, 6, 7):
        cat = "response"
        name = ["", "", "SimpleACK", "ComplexACK", "SegmentACK", "Error", "Reject", "Abort"][t]
    return EV("BACnet/IP", True, cat, name, info, "server", dir=(cat != "response"))


# ---- OPC UA ------------------------------------------------------------------------------------
def p_opcua(pl, to_server):
    if len(pl) < 8 or pl[:3] not in (b"HEL", b"ACK", b"OPN", b"MSG", b"CLO", b"ERR", b"RHE") or pl[3] not in (0x46, 0x43, 0x41):
        return None
    t = pl[:3].decode()
    names = {"HEL": "Hello", "ACK": "Acknowledge", "OPN": "OpenSecureChannel", "MSG": "Service message",
             "CLO": "CloseSecureChannel", "ERR": "Error"}
    info = {}
    if t == "HEL" and len(pl) >= 32:
        ul = struct.unpack("<I", pl[28:32])[0]
        if 0 < ul < 512:
            info["opcua_endpoint"] = txt(pl[32:32 + ul])
    return EV("OPC UA", True, "session" if t != "MSG" else "read", names.get(t, t), info, "server")


# ---- IEC 60870-5-104 ---------------------------------------------------------------------------
IEC_TYPES = {1: "M_SP_NA_1 single-point", 3: "M_DP_NA_1 double-point", 9: "M_ME_NA_1 measured", 11: "M_ME_NB_1 measured",
             13: "M_ME_NC_1 measured", 30: "M_SP_TB_1", 36: "M_ME_TF_1", 45: "C_SC_NA_1 single command",
             46: "C_DC_NA_1 double command", 47: "C_RC_NA_1 regulating step", 48: "C_SE_NA_1 setpoint",
             49: "C_SE_NB_1 setpoint", 50: "C_SE_NC_1 setpoint", 51: "C_BO_NA_1 bitstring", 100: "C_IC_NA_1 interrogation",
             101: "C_CI_NA_1 counter interrogation", 102: "C_RD_NA_1 read", 103: "C_CS_NA_1 clock sync",
             105: "C_RP_NA_1 reset process", 110: "P_ME_NA_1 parameter", 111: "P_ME_NB_1 parameter",
             112: "P_ME_NC_1 parameter"}


def p_iec104(pl, to_server):
    if len(pl) < 6 or pl[0] != 0x68 or pl[1] > len(pl) - 2 or pl[1] < 4:
        return None
    c = pl[2]
    if c & 3 == 3:
        u = {0x07: "STARTDT act", 0x0B: "STARTDT con", 0x13: "STOPDT act", 0x23: "STOPDT con",
             0x43: "TESTFR act", 0x83: "TESTFR con"}.get(c, "U-frame")
        return EV("IEC 60870-5-104", True, "stop" if c == 0x13 else "session", u)
    if c & 3 == 1:
        return EV("IEC 60870-5-104", True, "session", "S-frame")
    if len(pl) < 12:
        return EV("IEC 60870-5-104", True, "read", "I-frame")
    tid, cot = pl[6], pl[8] & 0x3F
    info = {"iec104_asdu": [str(pl[10] | (pl[11] << 8))]}
    name = IEC_TYPES.get(tid, "TypeID %d" % tid)
    cat = "read"
    if 45 <= tid <= 51 or 58 <= tid <= 64 or tid in (110, 111, 112, 113):
        cat = "write"
    elif tid == 105:
        cat = "control"
    elif tid in (100, 101, 102):
        cat = "discover"
    if not to_server or cot in (7, 10):
        cat = "response" if cat in ("write", "discover") else cat
    return EV("IEC 60870-5-104", True, cat, name, info, "server")


# ---- L2 protocols: LLDP, PROFINET DCP, GOOSE ---------------------------------------------------
LLDP_CAPS = ["other", "repeater", "bridge", "wlan-ap", "router", "telephone", "docsis", "station"]
PN_VENDOR = {0x002A: "Siemens", 0x0019: "Phoenix Contact", 0x0011: "Hilscher"}


def p_lldp(pl):
    o, info = 0, {}
    while o + 2 <= len(pl):
        h = u16(pl, o)
        t, ln = h >> 9, h & 0x1FF
        v = pl[o + 2:o + 2 + ln]
        o += 2 + ln
        if t == 0:
            break
        if t == 5:
            info["lldp_sysname"] = txt(v)
        elif t == 6:
            info["lldp_sysdesc"] = txt(v)
        elif t == 2 and len(v) > 1:
            info["lldp_port"] = txt(v[1:])
        elif t == 7 and len(v) >= 4:
            en = u16(v, 2)
            info["lldp_caps"] = [LLDP_CAPS[i] for i in range(8) if en & (1 << i)]
        elif t == 8 and len(v) >= 6 and v[1] == 1:
            info["lldp_mgmt_ip"] = socket.inet_ntoa(v[2:6])
    return EV("LLDP", False, "info", "LLDP advertisement", info, "src")


def p_dcp(pl):
    if len(pl) < 4:
        return None
    fid = u16(pl, 0)
    if fid not in (0xFEFC, 0xFEFD, 0xFEFE, 0xFEFF) or len(pl) < 12:
        return EV("PROFINET IO", True, "info", "RT cyclic frame 0x%04x" % fid, side="src")
    svc, typ = pl[2], pl[3]
    dlen = u16(pl, 10)
    info, o, end = {}, 12, min(len(pl), 12 + dlen)
    while o + 4 <= end:
        opt, sub, bl = pl[o], pl[o + 1], u16(pl, o + 2)
        v = pl[o + 4:o + 4 + bl]
        if opt == 2 and sub == 1:
            info["dcp_vendor"] = txt(v[2:])
        elif opt == 2 and sub == 2:
            info["dcp_name"] = txt(v[2:])
        elif opt == 2 and sub == 3 and len(v) >= 6:
            vid = u16(v, 2)
            info["profinet_vendor_id"] = "0x%04x" % vid
            info["profinet_device_id"] = "0x%04x" % u16(v, 4)
            if vid in PN_VENDOR:
                info["vendor"] = PN_VENDOR[vid]
        elif opt == 1 and sub == 2 and len(v) >= 14:
            info["dcp_ip"] = socket.inet_ntoa(v[2:6])
        o += 4 + bl + (bl & 1)
    if svc == 5:
        name, cat = ("Identify Request", "discover") if typ == 0 else ("Identify Response", "response")
    elif svc == 4:
        name, cat = "Set (rename / reconfigure device)", "write"
    else:
        name, cat = "DCP service %d" % svc, "read"
    return EV("PROFINET DCP", True, cat, name, info, "src")


def p_goose(pl, kind):
    runs = ascii_runs(pl, 6)
    cb = next((txt(r) for r in runs if b"LLN0" in r or b"/" in r), None)
    return EV("IEC 61850 " + kind, True, "info", kind + " publish", {"goose_ref": cb} if cb else {}, "src")


# ---- IT protocols ------------------------------------------------------------------------------
def dns_name(pl, o):
    labels, end, jumped, hops = [], None, False, 0
    while True:
        if o >= len(pl):
            return None, None
        ln = pl[o]
        if ln == 0:
            o += 1
            break
        if ln & 0xC0 == 0xC0:
            if o + 1 >= len(pl):
                return None, None
            if not jumped:
                end = o + 2
            jumped = True
            o = ((ln & 0x3F) << 8) | pl[o + 1]
            hops += 1
            if hops > 10:
                return None, None
            continue
        o += 1
        labels.append(pl[o:o + ln].decode("latin-1", "replace"))
        o += ln
    return ".".join(labels), (end if jumped else o)


def p_dns(pl, mdns=False):
    if len(pl) < 12:
        return None
    flags, qd, an = u16(pl, 2), u16(pl, 4), u16(pl, 6)
    if qd > 5 or an > 50 or (flags >> 11) & 0xF > 5:
        return None
    qr = flags >> 15
    o, qn = 12, []
    for _ in range(qd):
        nm, o = dns_name(pl, o)
        if nm is None:
            return None
        qn.append(nm)
        o += 4
    proto = "mDNS" if mdns else "DNS"
    info = {}
    if qr == 0:
        if qn:
            info["dns_queries"] = qn[:5]
        return EV(proto, False, "info", "Query", info, "src", dir=True)
    if mdns and an:
        nm, o2 = dns_name(pl, o)
        if nm and nm.endswith(".local"):
            info["hostname"] = nm
    return EV(proto, False, "info", "Response", info, "src", dir=False)


def p_dhcp(pl):
    if len(pl) < 241 or pl[236:240] != b"\x63\x82\x53\x63":
        return None
    op = pl[0]
    opts, i = {}, 240
    while i < len(pl):
        c = pl[i]
        if c == 255:
            break
        if c == 0:
            i += 1
            continue
        if i + 1 >= len(pl):
            break
        ln = pl[i + 1]
        opts[c] = pl[i + 2:i + 2 + ln]
        i += 2 + ln
    mt = opts.get(53, b"\0")[0]
    info = {}
    if 12 in opts:
        info["hostname"] = txt(opts[12])
    if 60 in opts:
        info["dhcp_vendor_class"] = txt(opts[60])
    if 55 in opts:
        info["dhcp_fingerprint"] = ",".join(str(x) for x in opts[55])
    names = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"}
    ev = EV("DHCP", False, "info", names.get(mt, "msg %d" % mt), info, "src", dir=(op == 1))
    if op == 2 and mt in (2, 5):
        ev["cat"] = "dhcp_server"
    return ev


HTTP_START = (b"GET ", b"POST", b"PUT ", b"HEAD", b"HTTP", b"DELE", b"OPTI", b"PATC")


def p_http(pl):
    if pl[:4] not in HTTP_START:
        return None
    head = pl[:1500].split(b"\r\n\r\n")[0].decode("latin-1")
    lines = head.split("\r\n")
    hdr = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(":")
        hdr[k.strip().lower()] = v.strip()
    info, req = {}, not lines[0].startswith("HTTP/")
    if req:
        if "user-agent" in hdr:
            info["user_agents"] = [hdr["user-agent"][:120]]
        if "host" in hdr:
            info["http_hosts"] = [hdr["host"][:80]]
    elif "server" in hdr:
        info["http_server"] = hdr["server"][:100]
    return EV("HTTP", False, "info", lines[0][:60], info, "src", cleartext=True, dir=req)


def p_ssh(pl):
    if not pl.startswith(b"SSH-"):
        return None
    return EV("SSH", False, "info", "banner", {"ssh_banner": txt(pl.split(b"\n")[0])[:80]}, "src")


def p_tls(pl):
    if len(pl) < 6 or pl[0] not in (0x14, 0x15, 0x16, 0x17) or pl[1] != 3 or pl[2] > 4:
        return None
    info, d = {}, None
    if pl[0] == 0x16 and len(pl) > 43 and pl[5] == 1:
        d = True
        try:
            o = 43
            o += 1 + pl[o]
            o += 2 + u16(pl, o)
            o += 1 + pl[o]
            end = o + 2 + u16(pl, o)
            o += 2
            while o + 4 <= min(end, len(pl)):
                et, el = u16(pl, o), u16(pl, o + 2)
                o += 4
                if et == 0 and el >= 5:
                    nl = u16(pl, o + 3)
                    info["tls_sni"] = [pl[o + 5:o + 5 + nl].decode("latin-1", "replace")]
                    break
                o += el
        except IndexError:
            pass
    return EV("TLS", False, "info", "ClientHello" if d else "record", info, "src", dir=d)


# ---- port tables -------------------------------------------------------------------------------
TCP_DPI = {502: p_modbus, 102: p_iso_tsap, 20000: p_dnp3, 44818: p_enip, 4840: p_opcua, 2404: p_iec104}
UDP_DPI = {47808: p_bacnet, 44818: p_enip, 2222: p_enip_io, 20000: p_dnp3}
TCP_OT_ONLY = {9600: "OMRON FINS", 5006: "MELSEC/SLMP", 5007: "MELSEC/SLMP", 1962: "PCWorx", 2455: "CODESYS",
               1740: "CODESYS", 1741: "CODESYS", 1911: "Niagara Fox", 4911: "Niagara Fox", 5094: "HART-IP",
               18245: "GE-SRTP", 18246: "GE-SRTP", 20547: "ProConOS", 789: "Red Lion Crimson",
               34962: "PROFINET IO", 34963: "PROFINET IO", 34964: "PROFINET IO"}
UDP_OT_ONLY = {9600: "OMRON FINS", 5006: "MELSEC/SLMP", 5007: "MELSEC/SLMP", 1911: "Niagara Fox", 5094: "HART-IP",
               34962: "PROFINET IO", 34963: "PROFINET IO", 34964: "PROFINET IO"}
TCP_IT = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 88: "Kerberos", 110: "POP3",
          135: "MS-RPC", 139: "NetBIOS-SSN", 143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 636: "LDAPS",
          1433: "MSSQL", 1883: "MQTT", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
          8080: "HTTP-alt", 8443: "HTTPS-alt", 8883: "MQTT-TLS"}
UDP_IT = {53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 123: "NTP", 137: "NBNS", 138: "NetBIOS-DGM", 161: "SNMP",
          162: "SNMP-trap", 500: "IKE", 514: "Syslog", 1812: "RADIUS", 1900: "SSDP", 3702: "WS-Discovery",
          5353: "mDNS", 5355: "LLMNR"}
CLEARTEXT = {"Telnet", "FTP", "TFTP", "VNC", "MQTT", "POP3", "IMAP"}
TCP_OT_NAMES = {502: "Modbus/TCP", 102: "S7comm", 20000: "DNP3", 44818: "EtherNet/IP", 4840: "OPC UA",
                2404: "IEC 60870-5-104"}
UDP_OT_NAMES = {47808: "BACnet/IP", 44818: "EtherNet/IP", 2222: "EtherNet/IP I/O", 20000: "DNP3"}
KNOWN_TCP = set(TCP_DPI) | set(TCP_OT_ONLY) | set(TCP_IT)
KNOWN_UDP = set(UDP_DPI) | set(UDP_OT_ONLY) | set(UDP_IT)


def port_label(l4, port):
    """-> (label, is_ot) from port tables only"""
    if l4 == "tcp":
        if port in TCP_OT_NAMES:
            return TCP_OT_NAMES[port], True
        if port in TCP_OT_ONLY:
            return TCP_OT_ONLY[port], True
        if port in TCP_IT:
            return TCP_IT[port], False
    else:
        if port in UDP_OT_NAMES:
            return UDP_OT_NAMES[port], True
        if port in UDP_OT_ONLY:
            return UDP_OT_ONLY[port], True
        if port in UDP_IT:
            return UDP_IT[port], False
    return None, False


# ----------------------------------------------------------------------------------------------
# Asset inventory + detection engine
# ----------------------------------------------------------------------------------------------

L2_NAMES = {0x88CC: "LLDP", 0x8892: "PROFINET", 0x88B8: "IEC 61850 GOOSE", 0x88BA: "IEC 61850 SV",
            0x88A4: "EtherCAT", 0x88F7: "PTP"}
MITRE = {"OT_STOP": "T0816", "OT_PROGRAM": "T0843", "OT_CONTROL": "T0858", "OT_WRITE": "T0855", "OT_UPLOAD": "T0845",
         "OT_DISCOVERY": "T0846", "PORT_SCAN": "T0846", "HOST_SWEEP": "T0846", "ARP_SWEEP": "T0846",
         "ARP_SPOOF": "T0830", "OT_EXTERNAL": "T0883"}
CAT_ALERT = {"stop": ("OT_STOP", "critical", "Controller STOP / shutdown command"),
             "program": ("OT_PROGRAM", "high", "Program / firmware download to controller"),
             "control": ("OT_CONTROL", "high", "Controller control / restart command"),
             "write": ("OT_WRITE", "medium", "Process write / command"),
             "upload": ("OT_UPLOAD", "medium", "Program upload from controller"),
             "discover": ("OT_DISCOVERY", "low", "OT device discovery / enumeration")}
SEV_WEIGHT = {"critical": 40, "high": 25, "medium": 12, "low": 4, "info": 1}
PORTSCAN_T, HOSTSWEEP_T, ARPSWEEP_T = 20, 20, 25
SERVER_SVC = {"DNS", "DHCP", "LDAP", "LDAPS", "Kerberos", "SMB", "HTTP", "HTTPS", "HTTP-alt", "HTTPS-alt", "MSSQL",
              "MySQL", "PostgreSQL", "SMTP", "NTP", "Syslog", "RDP", "SSH", "FTP", "Telnet", "MQTT", "RADIUS", "SNMP"}


def _strip(k):
    return k[3:] if k.startswith("ip:") else k[4:] if k.startswith("mac:") else k


class Asset:
    def __init__(self, key, ip=None, mac=None):
        self.key, self.ip, self.mac = key, ip, mac
        self.alive = False
        self.macs = collections.Counter()
        self.arp_macs = collections.Counter()
        self.first = self.last = None
        self.tx_pkts = self.rx_pkts = self.tx_bytes = self.rx_bytes = 0
        self.server = collections.Counter()
        self.client = collections.Counter()
        self.ot = set()          # OT protocols this asset serves
        self.ot_client = set()   # OT protocols this asset initiates
        self.listen = set()
        self.peers = set()
        self.ot_servers = set()  # distinct OT servers contacted
        self.props = {}
        self.tags = collections.defaultdict(set)
        self.ttl_max = 0
        self.writes = 0
        self.vlans = set()
        self.flags = set()

    def touch(self, ts):
        if self.first is None or ts < self.first:
            self.first = ts
        if self.last is None or ts > self.last:
            self.last = ts

    def apply(self, info):
        for k, v in info.items():
            if isinstance(v, (list, set, tuple)):
                s = self.tags[k]
                if len(s) < 40:
                    s.update(str(x) for x in v)
            elif v:
                self.props[k] = v


class Analyzer:
    def __init__(self, baseline=None, debug=False):
        self.lock = threading.RLock()
        self.debug = debug
        self.baseline = baseline
        self.exclude = None  # (ip, tcp_port): sensor's own push traffic to central, never analysed
        self.act_seq = 0  # activity journal: monotonically increasing id, survives reset()
        self.act_boot = "%x" % int(time.time())
        self.reset()

    def reset(self):
        with self.lock:
            self.assets = {}
            self.flows = {}
            self.alerts = {}
            self.arp_table = {}
            self.mac_ips = collections.defaultdict(set)
            self.arp_targets = collections.defaultdict(set)
            self.scan_ports = collections.defaultdict(dict)
            self.scan_hosts = collections.defaultdict(dict)
            self.icmp_sweep = collections.defaultdict(set)
            self.dhcp_servers = set()
            self.proto_pkts = collections.Counter()
            self.proto_bytes = collections.Counter()
            self.proto_ot = {}
            self.recent = collections.deque(maxlen=600)
            self.act = {}  # activity journal, aggregated per push window (see _act / drain_activities)
            self.act_dropped = 0
            self.pkts = self.bytes = self.errors = self.skipped = 0
            self.t0 = self.t1 = None
            self.source = ""
            self.busy = False
            self._snap = None
            self._snap_n = -1

    # ---------------------------------------------------------------- ingest
    def feed_pcap(self, path, name=None, progress=None):
        self.source = name or os.path.basename(path)
        self.busy = True
        try:
            for ts, link, data in read_pcap(path):
                self.process_raw(ts, data, link)
                if progress and self.pkts % 50000 == 0:
                    progress(self.pkts)
        finally:
            self.busy = False

    def process_raw(self, ts, data, link=1):
        with self.lock:
            try:
                self._process(ts, data, link)
            except Exception:
                self.errors += 1
                if self.debug:
                    traceback.print_exc()

    # ---------------------------------------------------------------- helpers
    def asset(self, key, ts, ip=None, mac=None, alive=True):
        a = self.assets.get(key)
        if a is None:
            a = self.assets[key] = Asset(key, ip, mac)
        if alive:
            a.alive = True
            a.touch(ts)
        return a

    ACT_MAX_KEYS = 20000

    @staticmethod
    def _detail(ev):
        """Short human-readable summary of what a parser extracted from the packet."""
        if not ev:
            return ""
        parts = []
        if ev.get("detail"):
            parts.append(str(ev["detail"]))
        for k, v in (ev.get("info") or {}).items():
            if isinstance(v, (list, tuple, set)):
                v = ", ".join(str(x) for x in list(v)[:3])
            elif isinstance(v, dict):
                v = ", ".join("%s=%s" % (a, b) for a, b in list(v.items())[:3])
            if v not in (None, ""):
                parts.append("%s=%s" % (k, v))
            if len(parts) >= 4:
                break
        return "; ".join(parts)[:200]

    def _act(self, ts, src, dst, proto, func, cat, port, l4, ot, n, smac="", dmac="", vlan=0, detail=""):
        """Record one packet-level activity. Identical activities (same src, dst, protocol, port, function)
        are merged within a push window into one row with a packet count, so a PLC polled 50x/s is one row."""
        k = (src, dst, proto, l4, port, func, cat)
        r = self.act.get(k)
        if r is None:
            if len(self.act) >= self.ACT_MAX_KEYS:
                self.act_dropped += 1
                return
            r = self.act[k] = {"first": ts, "last": ts, "src": src, "dst": dst, "src_mac": smac or "", "dst_mac": dmac or "",
                               "vlan": vlan or 0, "proto": proto, "l4": l4, "port": port, "func": func or "", "cat": cat or "info",
                               "ot": bool(ot), "pkts": 0, "bytes": 0, "detail": ""}
        r["pkts"] += 1
        r["bytes"] += n
        r["last"] = ts
        if detail:
            r["detail"] = detail

    def drain_activities(self):
        """Hand over everything journalled since the last call (sensor push thread)."""
        with self.lock:
            rows = sorted(self.act.values(), key=lambda r: r["first"])
            self.act = {}
            out = []
            for r in rows:
                self.act_seq += 1
                r["boot"], r["seq"] = self.act_boot, self.act_seq
                r["first"], r["last"] = iso(r["first"]), iso(r["last"])
                out.append(r)
            return out

    def count_proto(self, label, n, ot=False):
        self.proto_pkts[label] += 1
        self.proto_bytes[label] += n
        if ot:
            self.proto_ot[label] = True

    def alert(self, kind, sev, src, dst, title, ts, proto="", detail="", key=None, count=None, once=False):
        k = (kind, src, dst, proto, key)
        a = self.alerts.get(k)
        if a is None:
            a = self.alerts[k] = {"kind": kind, "severity": sev, "title": title, "src": src, "dst": dst,
                                  "proto": proto, "detail": detail, "count": 0, "first": ts, "last": ts,
                                  "mitre": MITRE.get(kind, "")}
        elif once:
            return
        if count is None:
            a["count"] += 1
        else:
            a["count"] = count
        a["last"] = ts

    # ---------------------------------------------------------------- main decode
    def _process(self, ts, data, link):
        r = parse_l2(link, data)
        n = len(data)
        self.pkts += 1
        self.bytes += n
        if self.t0 is None or ts < self.t0:
            self.t0 = ts
        if self.t1 is None or ts > self.t1:
            self.t1 = ts
        if not r:
            self.skipped += 1
            return
        smac, dmac, vlan, et, pay = r
        bcast = bool(dmac) and bool(int(dmac[:2], 16) & 1)
        if et == 0x0806:
            return self._arp(ts, pay, n)
        if et in (0x0800, 0x86DD):
            return self._ip(ts, smac, dmac, vlan, et, pay, n, bcast)
        return self._l2(ts, smac, dmac, vlan, et, pay, n)

    def _arp(self, ts, pay, n):
        if len(pay) < 28 or pay[4] != 6 or pay[5] != 4:
            return
        op = u16(pay, 6)
        sha, spa, tpa = mac_str(pay[8:14]), socket.inet_ntoa(pay[14:18]), socket.inet_ntoa(pay[24:28])
        self.count_proto("ARP", n)
        self._act(ts, spa, tpa, "ARP", {1: "Request (who-has)", 2: "Reply (is-at)"}.get(op, "op %d" % op),
                  "discover" if op == 1 else "info", 0, "l2", False, n, sha, "",
                  detail=("who has %s? tell %s" % (tpa, spa)) if op == 1 else ("%s is at %s" % (spa, sha)))
        if spa != "0.0.0.0":
            a = self.asset("ip:" + spa, ts, ip=spa)
            a.tx_pkts += 1
            a.tx_bytes += n
            a.arp_macs[sha] += 1
            prev = self.arp_table.get(spa)
            if prev and prev != sha:
                a.flags.add("mac_conflict")
                self.alert("ARP_SPOOF", "high", sha, spa, "IP address claimed by a different MAC (possible ARP spoofing / IP conflict)",
                           ts, "ARP", "%s moved from %s to %s" % (spa, prev, sha), key=(prev, sha))
            self.arp_table[spa] = sha
            self.mac_ips[sha].add(spa)
        if op == 1:
            self.arp_targets[sha].add(tpa)
            if len(self.arp_targets[sha]) >= ARPSWEEP_T:
                self.alert("ARP_SWEEP", "medium", sha, "broadcast", "ARP sweep (host discovery of many addresses)", ts,
                           "ARP", "", count=len(self.arp_targets[sha]))

    def _l2(self, ts, smac, dmac, vlan, et, pay, n):
        label = L2_NAMES.get(et)
        if label is None or not smac:
            self.count_proto("L2 0x%04x" % et, n)
            if smac:
                self._act(ts, smac, "multicast" if (not dmac or int(dmac[:2], 16) & 1) else dmac, "L2 0x%04x" % et, "frame",
                          "info", 0, "l2", False, n, smac, dmac, vlan)
            return
        if et == 0x88CC:
            ev = p_lldp(pay)
        elif et == 0x8892:
            ev = p_dcp(pay)
        elif et == 0x88B8:
            ev = p_goose(pay, "GOOSE")
        elif et == 0x88BA:
            ev = p_goose(pay, "SV")
        else:
            ev = EV(label, True, "info", side="src")
        if ev is None:
            return
        self.count_proto(ev["proto"], n, ev["ot"])
        a = self.asset("mac:" + smac, ts, mac=smac)
        a.mac = smac
        a.tx_pkts += 1
        a.tx_bytes += n
        if vlan:
            a.vlans.add(vlan)
        a.apply(ev["info"])
        if ev["ot"]:
            if ev["cat"] == "discover":
                a.ot_client.add(ev["proto"])
            else:
                a.ot.add(ev["proto"])
        dst = "multicast" if (not dmac or int(dmac[:2], 16) & 1) else dmac
        self._act(ts, smac, dst, ev["proto"], ev["func"] or ev["cat"], ev["cat"], 0, "l2", ev["ot"], n, smac, dmac, vlan,
                  self._detail(ev))
        fk = ("mac:" + smac, "mac:" + dmac if dst != "multicast" else "multicast", "l2", ev["proto"])
        fl = self.flows.get(fk)
        if fl is None:
            fl = self.flows[fk] = {"proto": ev["proto"], "ot": ev["ot"], "pkts": 0, "bytes": 0, "first": ts, "last": ts,
                                   "funcs": collections.Counter(), "port": 0, "l4": "l2"}
        fl["pkts"] += 1
        fl["bytes"] += n
        fl["last"] = ts
        if ev["func"]:
            fl["funcs"][ev["func"]] += 1
        if ev["cat"] in CAT_ALERT:
            kind, sev, ttl = CAT_ALERT[ev["cat"]]
            self.alert(kind, sev, smac, dst, "%s: %s" % (ttl, ev["func"]), ts, ev["proto"], ev["func"] or "",
                       key=ev["func"])

    def _ip(self, ts, smac, dmac, vlan, et, pay, n, bcast):
        p = parse_ip(et, pay)
        if not p:
            return
        src, dst, proto, ttl, l4, frag = p
        # --- source asset (sources are proven alive)
        if src not in ("0.0.0.0", "::") and not ip_is_mcast(src):
            a = self.asset("ip:" + src, ts, ip=src)
            if smac:
                a.macs[smac] += 1
                self.mac_ips[smac].add(src)
        elif smac:
            a = self.asset("mac:" + smac, ts, mac=smac)
        else:
            return
        a.tx_pkts += 1
        a.tx_bytes += n
        if ttl > a.ttl_max:
            a.ttl_max = ttl
        if vlan:
            a.vlans.add(vlan)
        d = None
        if not bcast and not ip_is_mcast(dst):
            d = self.asset("ip:" + dst, ts, ip=dst, alive=False)
            d.rx_pkts += 1
            d.rx_bytes += n
        # --- L4
        sport = dport = flags = 0
        payload = b""
        if proto == 6 and len(l4) >= 20 and frag == 0:
            sport, dport = u16(l4, 0), u16(l4, 2)
            flags = l4[13]
            payload = l4[(l4[12] >> 4) * 4:]
            l4n = "tcp"
        elif proto == 17 and len(l4) >= 8 and frag == 0:
            sport, dport = u16(l4, 0), u16(l4, 2)
            ul = u16(l4, 4)
            payload = l4[8:ul] if 8 <= ul <= len(l4) else l4[8:]
            l4n = "udp"
        elif proto in (1, 58):
            self.count_proto("ICMP", n)
            ic = l4[0] if l4 else -1
            fn = ({8: "Echo request", 0: "Echo reply", 3: "Destination unreachable", 11: "Time exceeded", 5: "Redirect"}
                  if proto == 1 else {128: "Echo request", 129: "Echo reply", 135: "Neighbor solicitation",
                                      136: "Neighbor advertisement", 133: "Router solicitation", 134: "Router advertisement",
                                      1: "Destination unreachable"}).get(ic, "type %d" % ic)
            self._act(ts, src, dst, "ICMP", fn, "discover" if "request" in fn or "solicitation" in fn else "info", 0, "icmp",
                      False, n, smac, dmac, vlan)
            if l4 and ((proto == 1 and l4[0] == 8) or (proto == 58 and l4[0] == 128)):
                s = self.icmp_sweep[src]
                s.add(dst)
                if len(s) >= HOSTSWEEP_T:
                    self.alert("HOST_SWEEP", "medium", src, "multiple hosts", "ICMP ping sweep", ts, "ICMP", "", count=len(s))
            return
        else:
            self.count_proto("IP proto %d" % proto, n)
            self._act(ts, src, dst, "IP proto %d" % proto, "packet", "info", 0, "ip", False, n, smac, dmac, vlan)
            return
        if d is None:
            # broadcast / multicast destination: still run DPI for discovery + DHCP
            pass
        if self.exclude and l4n == "tcp" and ((dst == self.exclude[0] and dport == self.exclude[1]) or
                                              (src == self.exclude[0] and sport == self.exclude[1])):
            return
        if l4n == "tcp" and (flags & 0x12) == 0x02:
            self._scan_syn(ts, src, dst, dport)
        ev, to_server = (None, None)
        if payload:
            ev, to_server = self._dpi(l4n, sport, dport, payload)
        if to_server is None:
            to_server = self._orient(l4n, sport, dport, flags)
        port = dport if to_server else sport
        plabel, pot = port_label(l4n, port)
        label = ev["proto"] if ev else (plabel or l4n.upper())
        is_ot = bool(ev["ot"]) if ev else pot
        self.count_proto(label, n, is_ot)
        if d is None:
            if ev and ev["info"]:
                a.apply(ev["info"])
            if ev and ev["cat"] != "response":
                self.recent.append((ts, src, "broadcast", label, ev["func"], ev["cat"], port, is_ot))
            self._act(ts, src, "broadcast", label, (ev["func"] or ev["cat"]) if ev else "datagram", ev["cat"] if ev else "session",
                      port, l4n, is_ot, n, smac, dmac, vlan, self._detail(ev))
            if ev and ev["cat"] == "dhcp_server":
                self._dhcp_server(ts, src)
            if ev and ev["cat"] in CAT_ALERT and to_server:
                kind, sev, ttl_ = CAT_ALERT[ev["cat"]]
                self.alert(kind, sev, src, "broadcast", "%s: %s" % (ttl_, ev["func"]), ts, label, ev["func"] or "", key=ev["func"])
            return
        if l4n == "tcp" and not payload and (flags & 0x17) == 0x02:
            self._act(ts, src, dst, label, "Connection attempt (SYN)", "session", port, l4n, is_ot, n, smac, dmac, vlan)
            return  # bare SYN: only a connection attempt (scans are detected separately), not a service or a flow
        cli, srv = (a, d) if to_server else (d, a)
        cli_ip, srv_ip = (src, dst) if to_server else (dst, src)
        if plabel or ev:
            cli.client[label] += 1
            srv.server[label] += 1
            if is_ot:
                srv.ot.add(label)
                cli.ot_client.add(label)
                cli.ot_servers.add(srv_ip)
        cli.peers.add(srv_ip)
        srv.peers.add(cli_ip)
        if l4n == "tcp" and (flags & 0x12) == 0x12:
            a.listen.add(("tcp", sport))
        elif l4n == "udp" and not to_server and (plabel or ev):
            a.listen.add(("udp", sport))
        # --- flow table
        fk = ("ip:" + cli_ip, "ip:" + srv_ip, l4n, port)
        fl = self.flows.get(fk)
        if fl is None:
            fl = self.flows[fk] = {"proto": label, "ot": is_ot, "pkts": 0, "bytes": 0, "first": ts, "last": ts,
                                   "funcs": collections.Counter(), "port": port, "l4": l4n}
        fl["pkts"] += 1
        fl["bytes"] += n
        fl["last"] = ts
        if ev:
            fl["proto"] = label
            fl["ot"] = fl["ot"] or is_ot
            if ev["func"] and ev["cat"] != "response":
                fl["funcs"][ev["func"]] += 1
        if ev and ev["cat"] != "response":
            self.recent.append((ts, cli_ip, srv_ip, label, ev["func"], ev["cat"], port, is_ot))
        elif not ev and fl["pkts"] == 1:
            self.recent.append((ts, cli_ip, srv_ip, label, "new connection", "session", port, is_ot))
        if ev:
            self._act(ts, src, dst, label, ev["func"] or ev["cat"], ev["cat"], port, l4n, is_ot, n, smac, dmac, vlan,
                      self._detail(ev))
        elif payload or fl["pkts"] == 1:
            self._act(ts, src, dst, label, "data" if payload else "new connection", "session", port, l4n, is_ot, n,
                      smac, dmac, vlan)
        if not ev:
            if plabel in CLEARTEXT and payload and to_server:
                self.alert("CLEARTEXT", "low", cli_ip, srv_ip, "Clear-text protocol in use (%s)" % plabel, ts, plabel)
            return
        # --- apply learned info and run detections
        target = srv if ev["side"] == "server" else a
        target.apply(ev["info"])
        if ev["cat"] == "dhcp_server":
            self._dhcp_server(ts, src)
        if ev["cleartext"] or plabel in CLEARTEXT:
            if label in CLEARTEXT or (label == "HTTP" and to_server):
                self.alert("CLEARTEXT", "low", cli_ip, srv_ip, "Clear-text protocol in use (%s)" % label, ts, label)
        if ev["ot"] and ev["cat"] in CAT_ALERT and to_server:
            kind, sev, ttl_ = CAT_ALERT[ev["cat"]]
            if ev["cat"] == "write":
                cli.writes += 1
            self.alert(kind, sev, cli_ip, srv_ip, "%s: %s" % (ttl_, ev["func"]), ts, label, ev["func"] or "",
                       key=ev["func"])

    def _dhcp_server(self, ts, ip):
        self.dhcp_servers.add(ip)
        if len(self.dhcp_servers) > 1:
            self.alert("ROGUE_DHCP", "medium", ", ".join(sorted(self.dhcp_servers)), "broadcast",
                       "More than one DHCP server answering on this network", ts, "DHCP", "", count=len(self.dhcp_servers))

    def _scan_syn(self, ts, src, dst, dport):
        s = self.scan_ports[src].setdefault(dst, set())
        s.add(dport)
        if len(s) >= PORTSCAN_T:
            self.alert("PORT_SCAN", "medium", src, dst, "TCP port scan", ts, "TCP", "", count=len(s))
        h = self.scan_hosts[src].setdefault(dport, set())
        h.add(dst)
        if len(h) >= HOSTSWEEP_T:
            self.alert("HOST_SWEEP", "medium", src, "multiple hosts", "TCP host sweep on port %d" % dport, ts, "TCP",
                       "", key=dport, count=len(h))

    def _dpi(self, l4, sport, dport, pl):
        table = TCP_DPI if l4 == "tcp" else UDP_DPI
        for port, srv in ((dport, True), (sport, False)):
            fn = table.get(port)
            if fn:
                try:
                    ev = fn(pl, srv)
                except Exception:
                    ev = None
                if ev:
                    return ev, (ev["dir"] if ev["dir"] is not None else srv)
        if l4 == "udp":
            for port in (dport, sport):
                ev = None
                if port == 53:
                    ev = p_dns(pl)
                elif port == 5353:
                    ev = p_dns(pl, True)
                elif port in (67, 68):
                    ev = p_dhcp(pl)
                if ev:
                    return ev, ev["dir"] if ev["dir"] is not None else (port == dport)
        for port, srv in ((dport, True), (sport, False)):
            lab = (TCP_OT_ONLY if l4 == "tcp" else UDP_OT_ONLY).get(port)
            if lab:
                return EV(lab, True, "info"), srv
        if l4 == "tcp":
            for fn in (p_http, p_ssh, p_tls):
                try:
                    ev = fn(pl)
                except Exception:
                    ev = None
                if ev:
                    return ev, ev["dir"]
        return None, None

    @staticmethod
    def _orient(l4, sport, dport, flags):
        known = KNOWN_TCP if l4 == "tcp" else KNOWN_UDP
        if dport in known:
            return True
        if sport in known:
            return False
        if l4 == "tcp":
            f = flags & 0x12
            if f == 0x02:
                return True
            if f == 0x12:
                return False
        return dport <= sport

    # ---------------------------------------------------------------- nmap import
    def import_nmap_xml(self, xml_text, now=None):
        import xml.etree.ElementTree as ET
        now = now or time.time()
        root = ET.fromstring(xml_text)
        n = 0
        with self.lock:
            for h in root.iter("host"):
                st = h.find("status")
                if st is not None and st.get("state") != "up":
                    continue
                ip = mac = vend = None
                for ad in h.findall("address"):
                    if ad.get("addrtype") == "ipv4":
                        ip = ad.get("addr")
                    elif ad.get("addrtype") == "mac":
                        mac, vend = ad.get("addr", "").lower(), ad.get("vendor")
                if not ip:
                    continue
                a = self.asset("ip:" + ip, now, ip=ip)
                a.flags.add("nmap")
                if mac:
                    a.arp_macs[mac] += 5
                    self.mac_ips[mac].add(ip)
                    if vend:
                        OUI.setdefault(mac.replace(":", "")[:6], vend)
                        mac_vendor.cache_clear()
                for hn in h.iter("hostname"):
                    if hn.get("name"):
                        a.tags["nmap_hostnames"].add(hn.get("name"))
                for pt in h.iter("port"):
                    stt = pt.find("state")
                    if stt is not None and stt.get("state") == "open":
                        a.listen.add((pt.get("protocol", "tcp"), int(pt.get("portid"))))
                        sv = pt.find("service")
                        if sv is not None and sv.get("product"):
                            a.tags["nmap_services"].add("%s/%s %s %s" % (pt.get("protocol"), pt.get("portid"),
                                                                       sv.get("product"), sv.get("version", "")))
                    for sc in pt.findall("script"):
                        a.props["nmap_" + sc.get("id", "script").replace("-", "_")] = (sc.get("output") or "")[:300]
                n += 1
            self._snap = None
        return n

    # ---------------------------------------------------------------- snapshot
    def snapshot(self):
        with self.lock:
            if self._snap is not None and self._snap_n == self.pkts and not self.busy:
                return self._snap
            snap = self._build()
            self._snap, self._snap_n = snap, self.pkts
            return snap

    def _choose_mac(self, a):
        if a.arp_macs:
            return a.arp_macs.most_common(1)[0][0]
        for mac, _ in a.macs.most_common():
            if len(self.mac_ips[mac]) < 4:
                return mac
        return None

    def _build(self):
        router_macs = {m for m, ips in self.mac_ips.items() if len(ips) >= 4}
        alive = {k: a for k, a in self.assets.items() if a.alive}
        # --- merge MAC-only assets (LLDP/DCP/DHCP) into IP assets
        mac_of = {k: (a.mac if a.key.startswith("mac:") else self._choose_mac(a)) for k, a in alive.items()}
        by_mac = {}
        for k, m in mac_of.items():
            if m and k.startswith("ip:") and m not in router_macs:
                by_mac.setdefault(m, k)
        idmap, merged_into = {}, {}
        for k, a in alive.items():
            if k.startswith("mac:"):
                tgt = by_mac.get(a.mac)
                if tgt is None and a.props.get("lldp_mgmt_ip"):
                    t2 = "ip:" + a.props["lldp_mgmt_ip"]
                    tgt = t2 if t2 in alive else None
                if tgt is None and a.props.get("dcp_ip"):
                    t2 = "ip:" + a.props["dcp_ip"]
                    tgt = t2 if t2 in alive else None
                if tgt:
                    merged_into.setdefault(tgt, []).append(a)
                    idmap[k] = tgt
        # --- alerts that need the final picture: OT devices talking to the internet, baseline
        for (cli, srv, l4, port), fl in list(self.flows.items()):
            if cli.startswith("ip:") and srv.startswith("ip:"):
                c, s = cli[3:], srv[3:]
                if ip_is_global(c) != ip_is_global(s):
                    inner = self.assets.get(srv if ip_is_global(c) else cli)
                    outer = c if ip_is_global(c) else s
                    if inner and inner.alive and inner.ot:
                        self.alert("OT_EXTERNAL", "high", inner.ip, outer, "OT controller communicating with an internet address",
                                   fl["last"], fl["proto"], "", key=(l4, port), count=fl["pkts"])
                    elif inner and inner.alive and inner.ot_client:
                        self.alert("OT_EXTERNAL", "medium", inner.ip, outer, "OT engineering / HMI station communicating with an internet address",
                                   fl["last"], fl["proto"], "", key=(l4, port), count=fl["pkts"])
        if self.baseline:
            self._baseline_alerts(alive)
        # --- per asset dicts
        views = {}
        for k, a in alive.items():
            if k in idmap:
                continue
            views[k] = self._asset_view(a, mac_of[k], router_macs, merged_into.get(k, []))
        def disp(key):
            key = idmap.get(key, key)
            return key
        alert_by_ip = collections.defaultdict(list)
        for al in self.alerts.values():
            for ip in (al["src"], al["dst"]):
                alert_by_ip[ip].append(al)
        for k, v in views.items():
            ips = [v["ip"]] if v["ip"] else []
            if v["mac"]:
                ips.append(v["mac"])
            seen, score, fac = set(), 0, []
            for ip in ips:
                for al in alert_by_ip.get(ip, []):
                    if id(al) in seen:
                        continue
                    seen.add(id(al))
                    score += SEV_WEIGHT[al["severity"]]
                    fac.append("%s: %s" % (al["severity"], al["title"][:70]))
            v["risk"] = min(100, score)
            v["risk_factors"] = fac[:8]
        # --- flows
        flows = []
        for (cli, srv, l4, port), fl in self.flows.items():
            ck, sk = disp(cli), disp(srv)
            if ck not in views and sk not in views:
                continue
            flows.append({"client": _strip(cli), "server": _strip(srv),
                          "client_id": ck, "server_id": sk, "proto": fl["proto"], "l4": l4, "port": port,
                          "ot": fl["ot"], "packets": fl["pkts"], "bytes": fl["bytes"],
                          "first": iso(fl["first"]), "last": iso(fl["last"]),
                          "functions": dict(fl["funcs"].most_common(12))})
        flows.sort(key=lambda f: (not f["ot"], -f["packets"]))
        alerts = []
        for i, al in enumerate(sorted(self.alerts.values(), key=lambda x: (-SEV_ORDER[x["severity"]], x["first"])), 1):
            alerts.append({"id": i, "uid": hashlib.sha1("|".join([al["kind"], str(al["src"]), str(al["dst"]), al["proto"], al["title"]]).encode()).hexdigest()[:16],
                           "severity": al["severity"], "kind": al["kind"], "title": al["title"], "src": al["src"],
                           "dst": al["dst"], "proto": al["proto"], "detail": al["detail"], "count": al["count"],
                           "first": iso(al["first"]), "last": iso(al["last"]), "mitre": al["mitre"]})
        assets = sorted(views.values(), key=lambda v: (v["ip"] is None, self._ipkey(v["ip"]), v["mac"] or ""))
        types = collections.Counter(v["device_type"] for v in assets)
        protos = [{"protocol": p, "packets": c, "bytes": self.proto_bytes[p], "ot": bool(self.proto_ot.get(p))}
                  for p, c in self.proto_pkts.most_common()]
        sev = collections.Counter(a["severity"] for a in alerts)
        dur = (self.t1 - self.t0) if self.t0 is not None else 0
        return {
            "meta": {"tool": "OTSense " + VERSION, "generated": iso(time.time()), "source": self.source,
                     "packets": self.pkts, "bytes": self.bytes, "duration_s": round(dur, 1),
                     "first_packet": iso(self.t0), "last_packet": iso(self.t1), "parse_errors": self.errors,
                     "skipped_frames": self.skipped, "busy": self.busy},
            "summary": {"assets": len(assets), "ot_assets": sum(1 for a in assets if a["is_ot"]),
                        "flows": len(flows), "ot_flows": sum(1 for f in flows if f["ot"]), "alerts": len(alerts),
                        "alerts_by_severity": dict(sev), "device_types": dict(types.most_common()),
                        "ot_protocols": sorted({p["protocol"] for p in protos if p["ot"]})},
            "assets": assets, "flows": flows, "alerts": alerts, "protocols": protos,
        }

    @staticmethod
    def _ipkey(ip):
        o = ip_obj(ip) if ip else None
        return (o.version, int(o)) if o else (0, 0)

    def _baseline_alerts(self, alive):
        b = self.baseline
        known = set(b.get("assets", []))
        for k, a in alive.items():
            if k.startswith("ip:") and a.ip not in known:
                self.alert("NEW_ASSET", "medium", a.ip, "", "New device not present in baseline", a.first or 0, "", "", once=True)
        kf = set(b.get("flows", []))
        for (cli, srv, l4, port), fl in self.flows.items():
            if fl["ot"] and "%s>%s|%s|%s" % (cli, srv, fl["proto"], port) not in kf:
                self.alert("NEW_FLOW", "medium", cli[3:] if cli.startswith("ip:") else cli,
                           srv[3:] if srv.startswith("ip:") else srv, "New OT communication not present in baseline", fl["first"],
                           fl["proto"], "", key=port, once=True)

    def baseline_dict(self):
        snap = self.snapshot()
        return {"created": iso(time.time()),
                "assets": [a["ip"] for a in snap["assets"] if a["ip"]],
                "flows": ["ip:%s>ip:%s|%s|%s" % (f["client"], f["server"], f["proto"], f["port"]) for f in snap["flows"] if f["ot"]]}

    # ---------------------------------------------------------------- per-asset view
    def _asset_view(self, a, mac, router_macs, merged):
        server, client = collections.Counter(a.server), collections.Counter(a.client)
        ot, otc = set(a.ot), set(a.ot_client)
        props, tags = dict(a.props), {k: set(v) for k, v in a.tags.items()}
        l2 = set()
        first, last = a.first, a.last
        tx_p, tx_b = a.tx_pkts, a.tx_bytes
        vlans = set(a.vlans)
        for m in merged:
            ot |= m.ot
            otc |= m.ot_client
            for k, v in m.props.items():
                props.setdefault(k, v)
            for k, v in m.tags.items():
                tags.setdefault(k, set()).update(v)
            tx_p += m.tx_pkts
            tx_b += m.tx_bytes
            vlans |= m.vlans
            first = min(first, m.first) if first else m.first
            last = max(last, m.last) if last else m.last
            l2 |= {p for p in (m.ot | m.ot_client)}
        mvendor = mac_vendor(mac) if mac else None
        vendor = props.get("vendor") or mvendor
        model = (props.get("model") or props.get("product_name") or props.get("order_number") or props.get("lldp_sysdesc")
                 or (("product code " + props["product_code"]) if props.get("product_code") else None))
        caps = set(tags.get("lldp_caps", []))
        is_router = bool(mac and mac in router_macs and a.arp_macs and a.arp_macs.most_common(1)[0][0] == mac)
        ip = a.ip
        ext = bool(ip and ip_is_global(ip))
        dtype, sub = self._classify(a, ot, otc, server, client, caps, is_router, ext, props)
        is_ot = bool(ot or otc)
        if vendor and not is_ot and any(h in vendor.lower() for h in OT_VENDOR_HINTS):
            sub = (sub + " - " if sub else "") + "ICS vendor hardware"
        os_guess = self._os_guess(a, props, tags)
        listen = sorted("%s/%d" % x for x in a.listen)
        zone = "L2-only" if not ip else ("External" if ext else self._zone(ip))
        purdue = {"PLC / RTU / Controller": "L1 Control", "PROFINET / IEC 61850 Device": "L1 Control",
                  "BACnet Device": "L1 Control", "HMI / Engineering Workstation": "L2 Supervisory",
                  "SCADA Master / Server": "L2 Supervisory", "OPC UA Server": "L2-L3",
                  "IT Server": "L3-L4 Operations/Enterprise", "External Host": "L5 Internet",
                  "Network Switch": "Network", "Router / Gateway": "Network"}.get(dtype, "-")
        peers = sorted(a.peers, key=lambda x: self._ipkey(x))
        extra_tags = {k: sorted(v)[:12] for k, v in tags.items()}
        flags = sorted(a.flags)
        if a.writes:
            flags.append("issues_writes")
        return {
            "id": a.key, "ip": ip, "mac": mac, "vendor": vendor, "mac_vendor": mvendor,
            "hostnames": sorted({props.get("hostname"), props.get("dcp_name"), props.get("lldp_sysname"),
                                 *tags.get("nmap_hostnames", [])} - {None})[:5],
            "device_type": dtype, "subtype": sub, "model": model, "firmware": props.get("firmware"),
            "serial": props.get("serial"), "os_guess": os_guess, "zone": zone, "purdue_guess": purdue,
            "vlans": sorted(vlans), "is_ot": is_ot, "external": ext,
            "first_seen": iso(first), "last_seen": iso(last),
            "tx_packets": tx_p, "rx_packets": a.rx_pkts, "tx_bytes": tx_b, "rx_bytes": a.rx_bytes,
            "serves": dict(server.most_common(12)), "uses": dict(client.most_common(12)),
            "ot_protocols": sorted(ot | otc), "listening_ports": listen, "peer_count": len(peers),
            "peers": peers[:40], "writes_sent": a.writes, "properties": {k: v for k, v in sorted(props.items())},
            "tags": extra_tags, "flags": flags, "risk": 0, "risk_factors": [],
        }

    @staticmethod
    def _zone(ip):
        o = ip_obj(ip)
        if o is None:
            return "?"
        if o.version == 4:
            return str(ipaddress.ip_network("%s/24" % ip, strict=False))
        return str(ipaddress.ip_network("%s/64" % ip, strict=False))

    @staticmethod
    def _classify(a, ot, otc, server, client, caps, is_router, ext, props):
        if ext:
            return "External Host", ", ".join(sorted(set(server) | set(ot))[:4])
        if is_router or "router" in caps:
            return "Router / Gateway", ""
        if "bridge" in caps:
            return "Network Switch", props.get("lldp_sysdesc", "")[:60]
        if ot:
            core = ot - {"PROFINET IO", "PROFINET DCP", "IEC 61850 GOOSE", "IEC 61850 SV", "EtherNet/IP I/O"}
            if core <= {"BACnet/IP"} and "BACnet/IP" in core:
                return "BACnet Device", "BACnet instance %s" % props.get("bacnet_instance", "?")
            if core == {"OPC UA"}:
                return "OPC UA Server", props.get("opcua_endpoint", "")
            if not core:
                return "PROFINET / IEC 61850 Device", ", ".join(sorted(ot))
            sub = ", ".join(sorted(core))
            return "PLC / RTU / Controller", sub
        if otc:
            return ("SCADA Master / Server", "OT client of %d devices" % len(a.ot_servers)) if len(a.ot_servers) >= 3 \
                else ("HMI / Engineering Workstation", "talks to %d OT device(s)" % len(a.ot_servers))
        svc = sorted(p for p in server if p in SERVER_SVC)
        if svc:
            return "IT Server", ", ".join(svc[:4])
        if ext:
            return "External Host", ""
        if client:
            return "Workstation / Endpoint", ""
        return "Unclassified", ""

    @staticmethod
    def _os_guess(a, props, tags):
        vc = (props.get("dhcp_vendor_class") or "").lower()
        ua = " ".join(tags.get("user_agents", [])).lower()
        if "msft" in vc or "windows" in ua:
            return "Windows (DHCP/User-Agent)"
        if "android" in vc or "android" in ua:
            return "Android"
        if "linux" in ua or "dhcpcd" in vc or "udhcp" in vc:
            return "Linux / embedded"
        if "mac os" in ua or "iphone" in ua:
            return "Apple"
        t = a.ttl_max
        if not t or (a.ip and ip_is_global(a.ip)):
            return None
        if t <= 64:
            return "Linux / embedded / network device (TTL<=64)"
        if t <= 128:
            return "Windows (TTL<=128)"
        return "Network gear / RTOS (TTL<=255)"


# ----------------------------------------------------------------------------------------------
# Reports: JSON / CSV / HTML dashboard / terminal summary
# ----------------------------------------------------------------------------------------------

DASH_HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OTSense</title>
<style>
:root{--bg:#0e1319;--card:#161d26;--line:#263142;--txt:#e7edf4;--mut:#8996a8;--acc:#4da3ff;--ot:#ff9f43;
--critical:#ff4d4f;--high:#ff7a45;--medium:#f5b02e;--low:#4ecb71;--info:#69b1ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.45 system-ui,Segoe UI,Roboto,sans-serif}
header{display:flex;align-items:center;gap:14px;padding:12px 18px;border-bottom:1px solid var(--line);flex-wrap:wrap}
h1{font-size:18px;margin:0}h1 span{color:var(--acc)}.mut{color:var(--mut)}
nav{display:flex;gap:4px;padding:0 18px;border-bottom:1px solid var(--line);overflow-x:auto}
nav button{background:none;border:0;color:var(--mut);padding:10px 14px;cursor:pointer;font:inherit;border-bottom:2px solid transparent;white-space:nowrap}
nav button.on{color:var(--txt);border-color:var(--acc)}
main{padding:16px 18px;max-width:1500px;margin:auto}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:16px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.tile b{display:block;font-size:24px}.tile small{color:var(--mut)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;margin-bottom:14px}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:14px}
h2{font-size:14px;margin:0 0 10px;color:var(--mut);text-transform:uppercase;letter-spacing:.06em}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600;cursor:pointer;white-space:nowrap;user-select:none;position:sticky;top:0;background:var(--card)}
tr.row:hover{background:#1c2633;cursor:pointer}
.wrap{overflow:auto;max-height:70vh}
.badge{display:inline-block;padding:1px 7px;border-radius:9px;font-size:12px;margin:1px 2px 1px 0;background:#223044;color:#c9d6e6}
.badge.ot{background:#4a3414;color:var(--ot)}
.sev{padding:1px 8px;border-radius:4px;font-size:12px;font-weight:600;color:#0e1319}
.sev.critical{background:var(--critical)}.sev.high{background:var(--high)}.sev.medium{background:var(--medium)}.sev.low{background:var(--low)}.sev.info{background:var(--info)}
.bar{height:8px;background:#223044;border-radius:4px;min-width:60px}.bar i{display:block;height:100%;border-radius:4px;background:var(--acc)}
.bar.ot i{background:var(--ot)}
input,select{background:#0e1319;color:var(--txt);border:1px solid var(--line);border-radius:6px;padding:6px 9px;font:inherit}
button.btn{background:var(--acc);color:#04121f;border:0;border-radius:6px;padding:7px 13px;font:inherit;font-weight:600;cursor:pointer}
button.btn.sec{background:#223044;color:var(--txt)}button.btn:disabled{opacity:.5}
.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
#drawer{position:fixed;right:0;top:0;bottom:0;width:min(520px,100%);background:#121921;border-left:1px solid var(--line);padding:16px;overflow:auto;transform:translateX(105%);transition:.2s;z-index:5}
#drawer.open{transform:none}#drawer h3{margin:0 0 4px}
.kv{display:grid;grid-template-columns:150px 1fr;gap:3px 10px;margin:10px 0}.kv div:nth-child(odd){color:var(--mut)}
canvas{width:100%;height:560px;background:#0b1016;border:1px solid var(--line);border-radius:10px;display:block}
#tip{position:fixed;pointer-events:none;background:#000c;padding:4px 8px;border-radius:5px;font-size:12px;display:none;z-index:9}
.legend span{margin-right:12px;font-size:12px}.legend i{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:4px}
code{background:#223044;padding:0 4px;border-radius:3px}
</style></head><body>
<header><h1><span>OT</span>Sense</h1><span class="mut" id="meta"></span><span style="flex:1"></span>
<div id="live" class="toolbar" style="display:none;margin:0">
<input type="file" id="file" accept=".pcap,.pcapng,.cap"><label class="mut"><input type="checkbox" id="reset" checked> replace</label>
<button class="btn" id="up">Analyse pcap</button>
<select id="iface"></select><input id="bpf" placeholder="BPF filter (optional)" size="16">
<button class="btn sec" id="start">Start live</button><button class="btn sec" id="stop">Stop</button><button class="btn sec" id="clear">Clear</button>
</div></header>
<nav id="nav"></nav>
<main id="main"></main>
<div id="drawer"></div><div id="tip"></div>
<script id="data" type="application/json">/*__DATA__*/null</script>
<script>
var LIVE=/*__LIVE__*/false, D=null, tab='overview', Q='', S={assets:['ip',1],alerts:['sev',1],flows:['packets',-1]};
var $=function(i){return document.getElementById(i)};
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
function fb(n){if(n<1024)return n+' B';var u=['KB','MB','GB'];var i=-1;do{n/=1024;i++}while(n>=1024&&i<2);return n.toFixed(1)+' '+u[i]}
var SEV={critical:4,high:3,medium:2,low:1,info:0};
var TYPECOL={'PLC / RTU / Controller':'#ff9f43','HMI / Engineering Workstation':'#4da3ff','SCADA Master / Server':'#9b7bff','IT Server':'#52c7b8','Router / Gateway':'#8996a8','Network Switch':'#8996a8','BACnet Device':'#f5b02e','OPC UA Server':'#e879f9','PROFINET / IEC 61850 Device':'#ff9f43','External Host':'#ff4d4f','Workstation / Endpoint':'#69b1ff','Unclassified':'#5b6778'};
function col(t){return TYPECOL[t]||'#5b6778'}
function ipn(s){if(!s)return 1e15;var p=s.split('.');return p.length==4?((+p[0]*256+ +p[1])*256+ +p[2])*256+ +p[3]:2e15}
function badges(a,ot){return (a||[]).map(function(x){return '<span class="badge'+(ot&&ot.indexOf(x)>=0?' ot':'')+'">'+esc(x)+'</span>'}).join('')}
function setData(d){D=d;render()}
function load(){var el=$('data').textContent.trim();if(el&&el!=='null'){try{setData(JSON.parse(el))}catch(e){}}
 if(LIVE){$('live').style.display='flex';poll();setInterval(poll,2500);ifaces()}}
function poll(){fetch('/api/state').then(function(r){return r.json()}).then(function(d){if(!D||d.meta.packets!==D.meta.packets||d.meta.busy!==D.meta.busy)setData(d)}).catch(function(){})}
function ifaces(){fetch('/api/ifaces').then(function(r){return r.json()}).then(function(l){$('iface').innerHTML=l.map(function(i){return '<option value="'+esc(i.name)+'">'+esc(i.name+(i.ip?' ('+i.ip+')':''))+'</option>'}).join('')})}
function post(u,b,h){return fetch(u,{method:'POST',body:b,headers:h||{}}).then(function(r){return r.json()})}
document.addEventListener('DOMContentLoaded',function(){
 $('up').onclick=function(){var f=$('file').files[0];if(!f){alert('Choose a .pcap/.pcapng file');return}
  $('up').disabled=true;$('up').textContent='Uploading...';
  fetch('/api/upload?reset='+($('reset').checked?1:0)+'&name='+encodeURIComponent(f.name),{method:'POST',body:f}).then(function(r){return r.json()}).then(function(){$('up').disabled=false;$('up').textContent='Analyse pcap';poll()}).catch(function(e){alert(e);$('up').disabled=false;$('up').textContent='Analyse pcap'})};
 $('start').onclick=function(){post('/api/live/start',JSON.stringify({iface:$('iface').value,bpf:$('bpf').value}),{'Content-Type':'application/json'}).then(function(r){if(r.error)alert(r.error);poll()})};
 $('stop').onclick=function(){post('/api/live/stop','{}').then(poll)};
 $('clear').onclick=function(){post('/api/reset','{}').then(poll)};
 load()});
var TABS=[['overview','Overview'],['assets','Assets'],['alerts','Alerts'],['flows','Communications'],['map','Network map']];
function render(){if(!D)return;var m=D.meta;
 $('meta').textContent=(m.source?m.source+' | ':'')+m.packets.toLocaleString()+' packets | '+fb(m.bytes)+' | '+m.duration_s+' s'+(m.busy?' | working...':'');
 $('nav').innerHTML=TABS.map(function(t){var n=t[0]=='assets'?D.assets.length:t[0]=='alerts'?D.alerts.length:t[0]=='flows'?D.flows.length:'';return '<button data-t="'+t[0]+'" class="'+(tab==t[0]?'on':'')+'">'+t[1]+(n!==''?' <span class="mut">'+n+'</span>':'')+'</button>'}).join('');
 Array.prototype.forEach.call($('nav').children,function(b){b.onclick=function(){tab=b.dataset.t;render()}});
 var f={overview:overview,assets:assets,alerts:alerts,flows:flows,map:mapTab}[tab];$('main').innerHTML=(m.errors&&m.errors.length?'<div class="card" style="border-color:var(--critical)">'+m.errors.map(esc).join('<br>')+'</div>':'')+f();if(tab=='map')drawMap();bind()}
function tiles(){var s=D.summary,a=s.alerts_by_severity;return '<div class="tiles">'+
 [['Assets',s.assets,''],['OT assets',s.ot_assets,'ot'],['Communications',s.flows,''],['OT communications',s.ot_flows,'ot'],
 ['Critical / High',(a.critical||0)+' / '+(a.high||0),''],['Medium / Low',(a.medium||0)+' / '+(a.low||0),''],['OT protocols',s.ot_protocols.length,'ot']].map(function(t){return '<div class="tile"><small>'+t[0]+'</small><b'+(t[2]?' style="color:var(--ot)"':'')+'>'+t[1]+'</b></div>'}).join('')+'</div>'}
function overview(){var maxp=Math.max.apply(null,D.protocols.map(function(p){return p.packets}).concat([1]));
 var pr=D.protocols.slice(0,16).map(function(p){return '<tr><td>'+esc(p.protocol)+(p.ot?' <span class="badge ot">OT</span>':'')+'</td><td>'+p.packets.toLocaleString()+'</td><td style="width:40%"><div class="bar'+(p.ot?' ot':'')+'"><i style="width:'+Math.max(2,100*p.packets/maxp)+'%"></i></div></td></tr>'}).join('');
 var dt=Object.keys(D.summary.device_types).map(function(k){return '<tr><td><i style="display:inline-block;width:10px;height:10px;border-radius:50%;background:'+col(k)+'"></i> '+esc(k)+'</td><td>'+D.summary.device_types[k]+'</td></tr>'}).join('');
 var al=D.alerts.slice(0,8).map(function(a){return '<tr><td><span class="sev '+a.severity+'">'+a.severity+'</span></td><td>'+esc(a.title)+'<br><span class="mut">'+esc(a.src)+' &rarr; '+esc(a.dst)+'</span></td></tr>'}).join('')||'<tr><td class="mut">No alerts</td></tr>';
 var risky=D.assets.slice().sort(function(a,b){return b.risk-a.risk}).filter(function(a){return a.risk>0}).slice(0,8).map(function(a){return '<tr class="row" data-a="'+esc(a.id)+'"><td>'+esc(a.ip||a.mac)+'</td><td>'+esc(a.device_type)+'</td><td><div class="bar"><i style="width:'+a.risk+'%;background:var(--high)"></i></div></td><td>'+a.risk+'</td></tr>'}).join('')||'<tr><td class="mut">-</td></tr>';
 return tiles()+'<div class="grid2"><div class="card"><h2>Protocols</h2><table>'+pr+'</table></div><div class="card"><h2>Device types</h2><table>'+dt+'</table></div><div class="card"><h2>Top alerts</h2><table>'+al+'</table></div><div class="card"><h2>Highest-risk assets</h2><table>'+risky+'</table></div></div>'}
function srt(name,cols,rows,rowfn){var s=S[name];var c=cols.filter(function(x){return x[0]==s[0]})[0];
 var q=Q.toLowerCase();if(q)rows=rows.filter(function(r){return JSON.stringify(r).toLowerCase().indexOf(q)>=0});
 if(c){rows=rows.slice().sort(function(a,b){var x=c[2]?c[2](a):a[c[0]],y=c[2]?c[2](b):b[c[0]];return (x<y?-1:x>y?1:0)*s[1]})}
 return '<div class="toolbar"><input id="q" placeholder="Filter..." value="'+esc(Q)+'" size="28"><span class="mut">'+rows.length+' shown</span></div><div class="card wrap"><table><tr>'+cols.map(function(x){return '<th data-s="'+name+'|'+x[0]+'">'+x[1]+(s[0]==x[0]?(s[1]>0?' &#9650;':' &#9660;'):'')+'</th>'}).join('')+'</tr>'+rows.map(rowfn).join('')+'</table></div>'}
function assets(){return srt('assets',[['ip','IP',function(a){return ipn(a.ip)}],['mac','MAC'],['vendor','Vendor'],['device_type','Device type'],['model','Model / info'],['protocols','Protocols',function(a){return a.ot_protocols.length}],['zone','Zone'],['purdue_guess','Purdue (guess)'],['os_guess','OS'],['risk','Risk']],D.assets,function(a){
 return '<tr class="row" data-a="'+esc(a.id)+'"><td>'+esc(a.ip||'-')+'</td><td>'+esc(a.mac||'-')+'</td><td>'+esc(a.vendor||'-')+'</td><td><i style="display:inline-block;width:9px;height:9px;border-radius:50%;background:'+col(a.device_type)+'"></i> '+esc(a.device_type)+'<br><span class="mut">'+esc(a.subtype||'')+'</span></td><td>'+esc((a.model||'')+(a.firmware?' fw '+a.firmware:''))+(a.hostnames.length?'<br><span class="mut">'+esc(a.hostnames.join(', '))+'</span>':'')+'</td><td>'+badges(a.ot_protocols,a.ot_protocols)+badges(Object.keys(a.serves).filter(function(p){return a.ot_protocols.indexOf(p)<0}).slice(0,4))+'</td><td>'+esc(a.zone)+'</td><td>'+esc(a.purdue_guess)+'</td><td>'+esc(a.os_guess||'-')+'</td><td><div class="bar"><i style="width:'+a.risk+'%;background:var(--high)"></i></div></td></tr>'})}
function alerts(){return srt('alerts',[['sev','Severity',function(a){return SEV[a.severity]}],['kind','Type'],['title','Description'],['src','Source'],['dst','Target'],['proto','Protocol'],['count','Count'],['last','Last seen'],['mitre','ATT&CK ICS']],D.alerts,function(a){
 return '<tr><td><span class="sev '+a.severity+'">'+a.severity+'</span></td><td>'+esc(a.kind)+'</td><td>'+esc(a.title)+(a.detail?'<br><span class="mut">'+esc(a.detail)+'</span>':'')+'</td><td>'+esc(a.src)+'</td><td>'+esc(a.dst)+'</td><td>'+esc(a.proto)+'</td><td>'+a.count+'</td><td>'+esc(a.last)+'</td><td>'+esc(a.mitre)+'</td></tr>'})}
function flows(){return srt('flows',[['client','Client'],['server','Server'],['proto','Protocol'],['port','Port'],['packets','Packets'],['bytes','Bytes'],['functions','Functions seen',function(f){return Object.keys(f.functions).length}],['last','Last seen']],D.flows,function(f){
 return '<tr><td>'+esc(f.client)+'</td><td>'+esc(f.server)+'</td><td>'+esc(f.proto)+(f.ot?' <span class="badge ot">OT</span>':'')+'</td><td>'+f.l4+'/'+f.port+'</td><td>'+f.packets.toLocaleString()+'</td><td>'+fb(f.bytes)+'</td><td>'+Object.keys(f.functions).slice(0,6).map(function(k){return '<span class="badge">'+esc(k)+' x'+f.functions[k]+'</span>'}).join('')+'</td><td>'+esc(f.last)+'</td></tr>'})}
function mapTab(){var leg=Object.keys(TYPECOL).map(function(k){return '<span><i style="background:'+TYPECOL[k]+'"></i>'+k+'</span>'}).join('');
 return '<div class="legend card">'+leg+'<span><i style="background:var(--ot)"></i>orange lines = OT traffic</span></div><canvas id="map"></canvas><p class="mut">Assets are grouped by subnet/zone. Click a node for details.</p>'}
var NODES=[];
function drawMap(){var c=$('map');if(!c)return;var ctx=c.getContext('2d'),dpr=window.devicePixelRatio||1,W=c.clientWidth,H=c.clientHeight;c.width=W*dpr;c.height=H*dpr;ctx.setTransform(dpr,0,0,dpr,0,0);
 var zones={};D.assets.forEach(function(a){(zones[a.zone]=zones[a.zone]||[]).push(a)});var zk=Object.keys(zones).sort();var cols=Math.max(1,Math.ceil(Math.sqrt(zk.length*W/H))),rows=Math.ceil(zk.length/cols);var pos={};NODES=[];
 zk.forEach(function(z,i){var cx=(i%cols+.5)*W/cols,cy=(Math.floor(i/cols)+.5)*H/rows,arr=zones[z],R=Math.min(W/cols,H/rows)/2-26,r=Math.max(18,Math.min(R,12+arr.length*8));
  ctx.strokeStyle='#263142';ctx.setLineDash([4,4]);ctx.beginPath();ctx.arc(cx,cy,r+16,0,7);ctx.stroke();ctx.setLineDash([]);ctx.fillStyle='#8996a8';ctx.font='11px system-ui';ctx.textAlign='center';ctx.fillText(z,cx,cy-r-22);
  arr.forEach(function(a,j){var ang=2*Math.PI*j/arr.length-Math.PI/2,x=arr.length==1?cx:cx+r*Math.cos(ang),y=arr.length==1?cy:cy+r*Math.sin(ang);pos[a.id]=[x,y];NODES.push({a:a,x:x,y:y})})});
 D.flows.slice(0,700).forEach(function(f){var p=pos[f.client_id],q=pos[f.server_id];if(p&&q&&f.client_id!==f.server_id){ctx.strokeStyle=f.ot?'rgba(255,159,67,.6)':'rgba(130,150,180,.22)';ctx.lineWidth=f.ot?1.4:1;ctx.beginPath();ctx.moveTo(p[0],p[1]);ctx.lineTo(q[0],q[1]);ctx.stroke()}});
 NODES.forEach(function(n){ctx.beginPath();ctx.arc(n.x,n.y,n.a.is_ot?9:7,0,7);ctx.fillStyle=col(n.a.device_type);ctx.fill();if(n.a.risk>=25){ctx.strokeStyle='#ff4d4f';ctx.lineWidth=2.5;ctx.stroke()}ctx.fillStyle='#c9d6e6';ctx.font='10px system-ui';ctx.textAlign='center';ctx.fillText((n.a.ip||n.a.mac||'').split('.').slice(-1)[0].slice(0,12),n.x,n.y+20)});
 c.onmousemove=function(e){var r=c.getBoundingClientRect(),x=e.clientX-r.left,y=e.clientY-r.top,h=null;NODES.forEach(function(n){if(Math.hypot(n.x-x,n.y-y)<12)h=n.a});var t=$('tip');if(h){t.style.display='block';t.style.left=e.clientX+12+'px';t.style.top=e.clientY+12+'px';t.textContent=(h.ip||h.mac)+' - '+h.device_type+(h.model?' - '+h.model:'')}else t.style.display='none'};
 c.onclick=function(e){var r=c.getBoundingClientRect(),x=e.clientX-r.left,y=e.clientY-r.top;NODES.forEach(function(n){if(Math.hypot(n.x-x,n.y-y)<12)detail(n.a.id)})}}
function detail(id){var a=D.assets.filter(function(x){return x.id===id})[0];if(!a)return;
 var kv=[['IP',a.ip],['MAC',a.mac],['Vendor',a.vendor],['Device type',a.device_type+(a.subtype?' - '+a.subtype:'')],['Model',a.model],['Firmware',a.firmware],['Serial',a.serial],['Hostnames',a.hostnames.join(', ')],['OS (guess)',a.os_guess],['Zone / VLAN',a.zone+(a.vlans.length?' / VLAN '+a.vlans.join(','):'')],['Purdue (guess)',a.purdue_guess],['First / last seen',a.first_seen+' / '+a.last_seen],['Traffic',a.tx_packets+' pkts sent, '+a.rx_packets+' received ('+fb(a.tx_bytes+a.rx_bytes)+')'],['Listening ports',a.listening_ports.join(', ')],['Peers',a.peer_count+': '+a.peers.slice(0,12).join(', ')],['Flags',a.flags.join(', ')]];
 Object.keys(a.properties).forEach(function(k){kv.push([k,a.properties[k]])});Object.keys(a.tags).forEach(function(k){kv.push([k,a.tags[k].join('; ')])});
 var h='<button class="btn sec" onclick="$(\'drawer\').classList.remove(\'open\')" style="float:right">Close</button><h3>'+esc(a.ip||a.mac)+'</h3><span class="mut">'+esc(a.device_type)+'</span><div class="kv">'+kv.filter(function(x){return x[1]}).map(function(x){return '<div>'+esc(x[0])+'</div><div>'+esc(x[1])+'</div>'}).join('')+'</div>';
 h+='<h2>Serves</h2>'+badges(Object.keys(a.serves),a.ot_protocols)+'<h2 style="margin-top:12px">Initiates</h2>'+badges(Object.keys(a.uses),a.ot_protocols);
 if(a.risk_factors.length)h+='<h2 style="margin-top:12px">Risk '+a.risk+'/100</h2><ul>'+a.risk_factors.map(function(x){return '<li>'+esc(x)+'</li>'}).join('')+'</ul>';
 $('drawer').innerHTML=h;$('drawer').classList.add('open')}
function bind(){var q=$('q');if(q){q.oninput=function(){Q=q.value;var p=q.selectionStart;render();var n=$('q');n.focus();n.setSelectionRange(p,p)}}
 Array.prototype.forEach.call(document.querySelectorAll('th[data-s]'),function(th){th.onclick=function(){var p=th.dataset.s.split('|');var s=S[p[0]];S[p[0]]=[p[1],s[0]==p[1]?-s[1]:1];render()}});
 Array.prototype.forEach.call(document.querySelectorAll('tr[data-a]'),function(tr){tr.onclick=function(){detail(tr.dataset.a)}})}
window.addEventListener('resize',function(){if(tab=='map')drawMap()});
</script></body></html>'''


def render_html(snap, live=False):
    data = "null" if live else json.dumps(snap, separators=(",", ":")).replace("</", "<\\/")
    return DASH_HTML.replace("/*__DATA__*/null", data).replace("/*__LIVE__*/false", "true" if live else "false")


def write_reports(snap, outdir):
    os.makedirs(outdir, exist_ok=True)
    paths = {}
    p = os.path.join(outdir, "report.html")
    with open(p, "w", encoding="utf-8") as f:
        f.write(render_html(snap))
    paths["html"] = p
    p = os.path.join(outdir, "otsense.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(snap, f, indent=1)
    paths["json"] = p
    p = os.path.join(outdir, "assets.csv")
    with open(p, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ip", "mac", "vendor", "device_type", "subtype", "model", "firmware", "serial", "hostnames", "os_guess",
                    "zone", "purdue_guess", "ot_protocols", "serves", "listening_ports", "peers", "risk", "first_seen",
                    "last_seen", "tx_packets", "rx_packets"])
        for a in snap["assets"]:
            w.writerow([a["ip"], a["mac"], a["vendor"], a["device_type"], a["subtype"], a["model"], a["firmware"], a["serial"],
                        ";".join(a["hostnames"]), a["os_guess"], a["zone"], a["purdue_guess"], ";".join(a["ot_protocols"]),
                        ";".join(a["serves"]), ";".join(a["listening_ports"]), a["peer_count"], a["risk"], a["first_seen"],
                        a["last_seen"], a["tx_packets"], a["rx_packets"]])
    paths["assets"] = p
    p = os.path.join(outdir, "alerts.csv")
    with open(p, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["severity", "kind", "title", "src", "dst", "protocol", "count", "first", "last", "mitre_ics", "detail"])
        for a in snap["alerts"]:
            w.writerow([a["severity"], a["kind"], a["title"], a["src"], a["dst"], a["proto"], a["count"], a["first"],
                        a["last"], a["mitre"], a["detail"]])
    paths["alerts"] = p
    p = os.path.join(outdir, "flows.csv")
    with open(p, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["client", "server", "protocol", "l4", "port", "ot", "packets", "bytes", "first", "last", "functions"])
        for x in snap["flows"]:
            w.writerow([x["client"], x["server"], x["proto"], x["l4"], x["port"], x["ot"], x["packets"], x["bytes"],
                        x["first"], x["last"], ";".join("%s x%d" % kv for kv in x["functions"].items())])
    paths["flows"] = p
    return paths


def _tab(rows, head, widths=None):
    widths = widths or [max(len(str(r[i])) for r in rows + [head]) for i in range(len(head))]
    out = ["  ".join(str(h).ljust(w) for h, w in zip(head, widths))]
    out.append("  ".join("-" * w for w in widths))
    for r in rows:
        out.append("  ".join(str(c)[:w].ljust(w) for c, w in zip(r, widths)))
    return "\n".join(out)


def print_summary(snap, max_assets=60, max_alerts=40):
    m, s = snap["meta"], snap["summary"]
    print("\n=== OTSense %s | %s | %d packets | %.1fs ===" % (VERSION, m["source"] or "live capture", m["packets"], m["duration_s"]))
    print("Assets: %d (%d OT)   Communications: %d (%d OT)   Alerts: %d %s" % (
        s["assets"], s["ot_assets"], s["flows"], s["ot_flows"], s["alerts"], s["alerts_by_severity"]))
    print("OT protocols seen: %s" % (", ".join(s["ot_protocols"]) or "none"))
    rows = []
    for a in snap["assets"][:max_assets]:
        rows.append([a["ip"] or "-", a["mac"] or "-", (a["vendor"] or "-")[:22], a["device_type"][:28],
                     ((a["model"] or "") + (" fw " + a["firmware"] if a["firmware"] else ""))[:34],
                     ",".join(a["ot_protocols"])[:34], a["risk"]])
    print("\n-- Assets --")
    print(_tab(rows, ["IP", "MAC", "Vendor", "Type", "Model", "OT protocols", "Risk"]))
    if s["assets"] > max_assets:
        print("... %d more (see report)" % (s["assets"] - max_assets))
    print("\n-- Alerts --")
    if not snap["alerts"]:
        print("none")
    else:
        rows = [[a["severity"].upper(), a["kind"], (a["src"] or "")[:20], (a["dst"] or "")[:20], a["title"][:70], a["count"]]
                for a in snap["alerts"][:max_alerts]]
        print(_tab(rows, ["Sev", "Kind", "Source", "Target", "Description", "#"]))


# ----------------------------------------------------------------------------------------------
# Live capture (Linux AF_PACKET with no dependencies; scapy elsewhere)
# ----------------------------------------------------------------------------------------------


class PcapOut:
    def __init__(self, path):
        self.f = open(path, "wb")
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

    def write(self, ts, data):
        self.f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(data), len(data)) + data)

    def close(self):
        self.f.close()


def list_ifaces():
    out = []
    if sys.platform.startswith("linux"):
        try:
            for name in sorted(os.listdir("/sys/class/net")):
                ip = ""
                try:
                    import fcntl
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    ip = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", name[:15].encode()))[20:24])
                    s.close()
                except Exception:
                    pass
                state = ""
                try:
                    state = open("/sys/class/net/%s/operstate" % name).read().strip()
                except OSError:
                    pass
                out.append({"name": name, "ip": ip, "state": state})
            return out
        except OSError:
            pass
    try:
        from scapy.all import conf
        for i in conf.ifaces.values():
            out.append({"name": i.name, "ip": getattr(i, "ip", "") or "", "state": getattr(i, "description", "") or ""})
    except Exception:
        pass
    return out


def capture_linux(iface, cb, stop):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    if iface not in ("any", "", None):
        s.bind((iface, 0))
        try:  # promiscuous mode (needed on a SPAN-fed port)
            s.setsockopt(263, 1, struct.pack("iHH8s", socket.if_nametoindex(iface), 1, 0, b""))
        except OSError:
            pass
    s.settimeout(0.5)
    try:
        while not stop.is_set():
            try:
                d, _ = s.recvfrom(65535)
            except socket.timeout:
                continue
            cb(time.time(), d, 1)
    finally:
        s.close()


def npcap_present():
    if os.name != "nt":
        return True
    root = os.environ.get("SystemRoot", r"C:\Windows")
    return any(os.path.exists(os.path.join(root, "System32", *x)) for x in (("Npcap", "wpcap.dll"), ("wpcap.dll",)))


def _win_local_ip(iface):
    """IPv4 address of the network card to listen on: the one given, else the card Windows uses to reach the network."""
    try:
        if iface:
            socket.inet_aton(iface)
            return iface
    except OSError:
        pass
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))   # UDP connect sends nothing; it only makes Windows pick the outgoing card
        return s.getsockname()[0]
    finally:
        s.close()


def capture_winraw(iface, cb, stop):
    """Passive listening on Windows WITHOUT Npcap: a raw socket with SIO_RCVALL (built into Windows, needs Administrator).
    Delivers IPv4 packets only (no Ethernet header), so there are no MAC addresses / ARP / PROFINET-DCP / LLDP in this mode."""
    ip = _win_local_ip(iface)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    s.bind((ip, 0))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    s.settimeout(0.5)
    try:
        while not stop.is_set():
            try:
                d = s.recv(65535)
            except socket.timeout:
                continue
            if d:
                cb(time.time(), d, 101)   # 101 = raw IP
    finally:
        try:
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except Exception:
            pass
        s.close()


def capture_scapy(iface, cb, stop, bpf=None):
    try:
        from scapy.all import AsyncSniffer
    except ImportError:
        raise RuntimeError("Live capture on this OS needs scapy (pip install scapy) plus Npcap on Windows / libpcap on macOS.")

    def handler(p):
        nm = type(p).__name__
        link = 113 if nm == "CookedLinux" else 276 if nm == "CookedLinuxV2" else 0 if nm == "Loopback" else 1
        cb(float(p.time), getattr(p, "original", None) or bytes(p), link)

    sn = AsyncSniffer(iface=iface or None, prn=handler, store=False, filter=bpf or None)
    sn.start()
    try:
        while not stop.is_set():
            time.sleep(0.3)
            if not sn.running:
                break
    finally:
        try:
            sn.stop()
        except Exception:
            pass


def run_capture(an, iface, stop, bpf=None, pcap_out=None, errors=None, tap=None):
    out = PcapOut(pcap_out) if pcap_out else None

    def cb(ts, d, link):
        an.process_raw(ts, d, link)
        if tap:
            tap(ts, d)
        if out:
            out.write(ts, d)

    an.busy = True
    try:
        if sys.platform.startswith("linux") and not bpf:
            capture_linux(iface, cb, stop)
        elif os.name == "nt" and not npcap_present():
            capture_winraw(iface, cb, stop)
        else:
            capture_scapy(iface, cb, stop, bpf)
    except PermissionError:
        msg = ("Permission denied - right-click OTSense-Sensor.exe and choose Run as administrator (needed to listen without Npcap)."
               if os.name == "nt" else
               "Permission denied - run as root (sudo) or grant CAP_NET_RAW: sudo setcap cap_net_raw+eip $(readlink -f $(which python3))")
        (errors.append(msg) if errors is not None else print(msg, file=sys.stderr))
    except Exception as e:  # noqa
        msg = "Capture error: %s" % e
        (errors.append(msg) if errors is not None else print(msg, file=sys.stderr))
    finally:
        an.busy = False
        if out:
            out.close()


# ----------------------------------------------------------------------------------------------
# Web UI (stdlib only): dashboard + pcap upload + live capture control
# ----------------------------------------------------------------------------------------------


def serve_web(host, port, an, outdir):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlparse, parse_qs

    st = {"stop": threading.Event(), "thread": None, "errors": []}

    def stop_live():
        st["stop"].set()
        t = st["thread"]
        if t:
            t.join(3)
        st["thread"] = None

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="application/json"):
            if isinstance(body, str):
                body = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            u = urlparse(self.path)
            if u.path in ("/", "/index.html"):
                self._send(200, render_html(None, live=True), "text/html; charset=utf-8")
            elif u.path == "/api/state":
                snap = dict(an.snapshot())
                snap["meta"] = dict(snap["meta"], busy=bool(an.busy), errors=list(st["errors"]))
                self._send(200, json.dumps(snap))
            elif u.path == "/api/ifaces":
                self._send(200, json.dumps(list_ifaces()))
            elif u.path == "/report.html":
                self._send(200, render_html(an.snapshot()), "text/html; charset=utf-8")
            else:
                self._send(404, "{}")

        def do_POST(self):
            u = urlparse(self.path)
            q = parse_qs(u.query)
            n = int(self.headers.get("Content-Length") or 0)
            if u.path == "/api/upload":
                fd, tmp = tempfile.mkstemp(suffix=".pcap")
                left = n
                with os.fdopen(fd, "wb") as f:
                    while left > 0:
                        ch = self.rfile.read(min(1 << 20, left))
                        if not ch:
                            break
                        f.write(ch)
                        left -= len(ch)
                name = q.get("name", ["upload.pcap"])[0]
                stop_live()
                if q.get("reset", ["1"])[0] == "1":
                    an.reset()
                an.busy = True

                def work():
                    try:
                        an.feed_pcap(tmp, name)
                    except Exception as e:  # noqa
                        st["errors"].append("Could not read %s: %s" % (name, e))
                    finally:
                        an.busy = False
                        try:
                            os.remove(tmp)
                        except OSError:
                            pass

                threading.Thread(target=work, daemon=True).start()
                self._send(200, '{"ok":true}')
                return
            body = self.rfile.read(n) if n else b""
            if u.path == "/api/live/start":
                try:
                    req = json.loads(body or b"{}")
                except ValueError:
                    req = {}
                stop_live()
                st["stop"] = threading.Event()
                st["errors"] = []
                if not an.pkts:
                    an.source = "live: " + (req.get("iface") or "any")
                t = threading.Thread(target=run_capture, args=(an, req.get("iface") or "any", st["stop"], req.get("bpf") or None,
                                                              None, st["errors"]), daemon=True)
                t.start()
                st["thread"] = t
                time.sleep(0.4)
                self._send(200, json.dumps({"ok": not st["errors"], "error": "; ".join(st["errors"]) or None}))
            elif u.path == "/api/live/stop":
                stop_live()
                self._send(200, '{"ok":true}')
            elif u.path == "/api/reset":
                stop_live()
                an.reset()
                self._send(200, '{"ok":true}')
            else:
                self._send(404, "{}")

    srv = ThreadingHTTPServer((host, port), H)
    print("OTSense web UI: http://%s:%d   (Ctrl-C to stop)" % ("localhost" if host in ("0.0.0.0", "") else host, port))
    if host in ("0.0.0.0", ""):
        print("WARNING: listening on all interfaces with no authentication. Use an SSH tunnel or firewall it.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop_live()
        srv.server_close()


# ----------------------------------------------------------------------------------------------
# Synthetic OT traffic generator (so you can test with no real pcap)
# ----------------------------------------------------------------------------------------------


def _csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(">%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _mb(m):
    return bytes.fromhex(m.replace(":", ""))


def _eth(dst, src, et, pl):
    return _mb(dst) + _mb(src) + struct.pack(">H", et) + pl


def _ip4(src, dst, proto, pl, ttl=64, ident=1):
    h = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(pl), ident, 0x4000, ttl, proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return h[:10] + struct.pack(">H", _csum(h)) + h[12:] + pl


def _tcp(src, dst, sp, dp, flags, pl=b"", seq=1000, ack=0):
    hdr = struct.pack(">HHIIBBHHH", sp, dp, seq, ack, 0x50, flags, 65535, 0, 0)
    ph = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack(">BBH", 0, 6, len(hdr) + len(pl))
    return hdr[:16] + struct.pack(">H", _csum(ph + hdr + pl)) + hdr[18:] + pl


def _udp(src, dst, sp, dp, pl):
    ln = 8 + len(pl)
    hdr = struct.pack(">HHHH", sp, dp, ln, 0)
    ph = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack(">BBH", 0, 17, ln)
    return struct.pack(">HHHH", sp, dp, ln, _csum(ph + hdr + pl) or 0xFFFF) + pl


def _build_sample(path, attacks=True):
    import random
    rnd = random.Random(7)
    LOCAL = "192.168.10."
    GW = "00:00:0c:07:ac:01"

    def host(name, ip, mac, ttl):
        return {"name": name, "ip": ip, "mac": mac, "ttl": ttl}

    H = dict(
        gw=host("gw", "192.168.10.1", GW, 255), dns=host("dns", "192.168.10.2", "00:50:56:aa:00:02", 64),
        sw=host("sw", "192.168.10.250", "00:80:63:aa:aa:aa", 255),
        hmi=host("hmi", "192.168.10.20", "d4:be:d9:00:00:20", 128), ews=host("ews", "192.168.10.30", "d4:be:d9:00:00:30", 128),
        plc1=host("plc1", "192.168.10.11", "00:1b:1b:11:22:33", 64), plc2=host("plc2", "192.168.10.12", "00:00:bc:aa:bb:cc", 64),
        rtu1=host("rtu1", "192.168.10.13", "00:80:f4:12:34:56", 64), opc=host("opc", "192.168.10.40", "00:15:5d:00:10:40", 128),
        pn=host("pn", "192.168.10.60", "00:1b:1b:aa:00:01", 64),
        scada=host("scada", "192.168.20.2", "00:15:5d:00:20:02", 126), dnp=host("dnp", "192.168.20.5", "00:a0:45:55:66:77", 62),
        iec=host("iec", "192.168.20.6", "00:90:e8:66:66:66", 62), bac=host("bac", "192.168.30.40", "b8:27:eb:40:40:40", 61),
        rogue=host("rogue", "192.168.10.99", "b8:27:eb:99:99:99", 64), cloud=host("cloud", "8.8.4.4", "00:00:00:00:00:00", 55),
        web=host("web", "93.184.216.34", "00:00:00:00:00:00", 52))
    pk = []
    t = [time.time() - 3600.0]

    def add(frame, dt=None):
        t[0] += rnd.uniform(0.002, 0.08) if dt is None else dt
        pk.append((t[0], frame))

    def macof(h):
        return h["mac"] if h["ip"].startswith(LOCAL) else GW

    def send(a, b, proto, l4, dt=None):
        add(_eth(macof(b), macof(a), 0x0800, _ip4(a["ip"], b["ip"], proto, l4, a["ttl"])), dt)

    def conv(a, b, sp, dp, msgs):
        s1, s2 = 1000, 5000
        send(a, b, 6, _tcp(a["ip"], b["ip"], sp, dp, 0x02, seq=s1))
        send(b, a, 6, _tcp(b["ip"], a["ip"], dp, sp, 0x12, seq=s2, ack=s1 + 1))
        send(a, b, 6, _tcp(a["ip"], b["ip"], sp, dp, 0x10, seq=s1 + 1, ack=s2 + 1))
        s1 += 1
        s2 += 1
        for who, data in msgs:
            if who == "c":
                send(a, b, 6, _tcp(a["ip"], b["ip"], sp, dp, 0x18, data, seq=s1, ack=s2))
                s1 += len(data)
            else:
                send(b, a, 6, _tcp(b["ip"], a["ip"], dp, sp, 0x18, data, seq=s2, ack=s1))
                s2 += len(data)

    def udp(a, b, sp, dp, data, bcast=False, dt=None):
        if bcast:
            add(_eth("ff:ff:ff:ff:ff:ff", macof(a), 0x0800, _ip4(a["ip"], b, 17, _udp(a["ip"], b, sp, dp, data), a["ttl"])), dt)
        else:
            send(a, b, 17, _udp(a["ip"], b["ip"], sp, dp, data), dt)

    def arp(op, sha, spa, tha, tpa):
        pay = struct.pack(">HHBBH", 1, 0x0800, 6, 4, op) + _mb(sha) + socket.inet_aton(spa) + _mb(tha) + socket.inet_aton(tpa)
        dst = "ff:ff:ff:ff:ff:ff" if op == 1 else tha
        add(_eth(dst, sha, 0x0806, pay))

    # ---- protocol message builders
    def mb(txn, unit, pdu):
        return struct.pack(">HHHB", txn, 0, len(pdu) + 1, unit) + pdu

    def obj(i, s):
        return bytes([i, len(s)]) + s.encode()

    def tpkt(p):
        return b"\x03\x00" + struct.pack(">H", len(p) + 4) + p

    def s7(ros, pduref, par, data=b""):
        h = b"\x32" + bytes([ros]) + b"\x00\x00" + struct.pack(">HHH", pduref, len(par), len(data))
        if ros in (2, 3):
            h += b"\x00\x00"
        return tpkt(b"\x02\xf0\x80" + h + par + data)

    item = bytes([0x12, 0x0A, 0x10, 0x02, 0, 1, 0, 1, 0x84, 0, 0, 0])
    s7_cr = tpkt(bytes([0x11, 0xE0, 0, 0, 0, 1, 0, 0xC1, 2, 1, 0, 0xC2, 2, 1, 2, 0xC0, 1, 0x0A]))
    s7_cc = tpkt(bytes([0x11, 0xD0, 0, 1, 0, 1, 0, 0xC1, 2, 1, 0, 0xC2, 2, 1, 2, 0xC0, 1, 0x0A]))
    s7_setup = s7(1, 1, bytes([0xF0, 0, 0, 1, 0, 1, 1, 0xE0]))
    s7_setup_r = s7(3, 1, bytes([0xF0, 0, 0, 1, 0, 1, 1, 0xE0]))
    s7_read = s7(1, 2, bytes([0x04, 0x01]) + item)
    s7_read_r = s7(3, 2, bytes([0x04, 0x01]), bytes([0xFF, 4, 0, 16, 0x12, 0x34]))
    s7_write = s7(1, 3, bytes([0x05, 0x01]) + item, bytes([0, 4, 0, 16, 0x04, 0xD2]))
    s7_stop = s7(1, 4, bytes([0x29, 0, 0, 0, 0, 0, 9]) + b"P_PROGRAM")
    s7_dl = s7(1, 5, bytes([0x1A, 0, 0, 0, 0, 0, 0, 0xFD, 0, 0x0A]))
    s7_szl = s7(7, 6, bytes([0, 1, 0x12, 4, 0x11, 0x44, 1, 0]), bytes([0xFF, 9, 0, 4, 0, 0x11, 0, 1]))
    s7_szl_r = s7(7, 6, bytes([0, 1, 0x12, 8, 0x12, 0x84, 1, 1, 0, 0, 0, 0]),
                  b"\xff\x09\x00\x60" + b"6ES7 212-1AE40-0XB0\x00CPU 1212C DC/DC/DC\x00S C-J4U123456\x00V 4.2.3\x00Original Siemens Equipment")

    def enip(cmd, data=b"", sess=0):
        return struct.pack("<HHII8sI", cmd, len(data), sess, 0, b"\0" * 8, 0) + data

    name = b"1756-L83E/B"
    body = struct.pack("<H", 1) + struct.pack(">hH4s8s", 2, 44818, socket.inet_aton(H["plc2"]["ip"]), b"\0" * 8) + \
        struct.pack("<HHHBBHI", 1, 0x0E, 54, 33, 11, 0x30, 0xDEAD1234) + bytes([len(name)]) + name + b"\x03"
    enip_li_r = enip(0x63, struct.pack("<H", 1) + struct.pack("<HH", 0x0C, len(body)) + body)

    def cip(c):
        return enip(0x6F, struct.pack("<IHH", 0, 10, 2) + struct.pack("<HH", 0, 0) + struct.pack("<HH", 0xB2, len(c)) + c, 7)

    cip_read = cip(bytes([0x4C, 0x04, 0x91, 0x05]) + b"MyTag\x00" + b"\x01\x00")
    cip_write = cip(bytes([0x4D, 0x04, 0x91, 0x05]) + b"MyTag\x00" + b"\xc3\x00\x01\x00\x07\x00")
    cip_stop = cip(bytes([0x07, 0x02, 0x20, 0x01, 0x24, 0x01]))

    def dnp3(dst, src, fc, objs=b"", ctrl=0xC4):
        user = bytes([0xC0, 0xC1, fc]) + objs
        return b"\x05\x64" + bytes([5 + len(user)]) + bytes([ctrl]) + struct.pack("<HH", dst, src) + b"\x00\x00" + user

    def bvlc(func, x):
        return b"\x81" + bytes([func]) + struct.pack(">H", 4 + len(x)) + x

    whois = bvlc(0x0B, b"\x01\x20\xff\xff\x00\xff\x10\x08")
    iam = bvlc(0x0B, b"\x01\x00\x10\x00\xc4" + struct.pack(">I", (8 << 22) | 40) + b"\x22\x05\xc4\x91\x00\x21\x07")
    bac_write = bvlc(0x0A, b"\x01\x04\x00\x05\x01\x0f\x0c\x00\x40\x00\x01\x19\x55\x3e\x44\x42\xc8\x00\x00\x3f")
    url = b"opc.tcp://192.168.10.40:4840"
    opc_hel = b"HELF" + struct.pack("<I", 28 + 4 + len(url)) + struct.pack("<IIIII", 0, 65536, 65536, 0, 0) + struct.pack("<I", len(url)) + url
    opc_ack = b"ACKF" + struct.pack("<I", 28) + struct.pack("<IIIII", 0, 65536, 65536, 0, 0)
    iec_start = bytes([0x68, 0x04, 0x07, 0, 0, 0])
    iec_gi = bytes([0x68, 0x0E, 0, 0, 0, 0, 100, 1, 6, 0, 1, 0, 0, 0, 0, 20])
    iec_meas = bytes([0x68, 0x0E, 2, 0, 2, 0, 13, 1, 3, 0, 1, 0, 1, 0, 0, 0x41])
    iec_cmd = bytes([0x68, 0x0E, 2, 0, 2, 0, 45, 1, 6, 0, 1, 0, 1, 0, 0, 1])

    def dcp(fid, svc, typ, blocks):
        return struct.pack(">HBBIHH", fid, svc, typ, 0x1234, 0, len(blocks)) + blocks

    def dcp_block(o, s, v):
        b = bytes([o, s]) + struct.pack(">H", len(v)) + v
        return b + (b"\0" if len(v) & 1 else b"")

    dcp_req = dcp(0xFEFE, 5, 0, bytes([0xFF, 0xFF, 0, 0]))
    dcp_resp = dcp(0xFEFF, 5, 1, dcp_block(2, 2, b"\0\0" + b"s7-1200-line1") + dcp_block(2, 1, b"\0\0" + b"S7-1200") +
                   dcp_block(2, 3, b"\0\0" + struct.pack(">HH", 0x002A, 0x0101)))

    def tlv(t, v):
        return struct.pack(">H", (t << 9) | len(v)) + v

    lldp = tlv(1, b"\x04" + _mb(H["sw"]["mac"])) + tlv(2, b"\x05Gi1/0/1") + tlv(3, b"\x00\x78") + tlv(5, b"SW-CORE-01") + \
        tlv(6, b"Hirschmann RS20 industrial switch") + tlv(7, struct.pack(">HH", 0x14, 0x04)) + tlv(8, b"\x05\x01" + socket.inet_aton(H["sw"]["ip"]) + b"\x02\x00\x00\x00\x01\x00") + tlv(0, b"")
    goose = struct.pack(">HHHH", 0x0001, 80, 0, 0) + b"\x61\x40\x80\x20IED1PROT/LLN0$GO$gcbTrip\x81\x01\x01"

    def dns_q(nm, txid=1):
        return struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0) + b"".join(bytes([len(x)]) + x.encode() for x in nm.split(".")) + b"\0" + struct.pack(">HH", 1, 1)

    def dhcp(op, mt, cmac, host=None, vc=None, yi="0.0.0.0", sid=None):
        h = struct.pack(">BBBBIHH4s4s4s4s16s64s128s", op, 1, 6, 0, 0xABCD, 0, 0x8000, b"\0" * 4, socket.inet_aton(yi), b"\0" * 4, b"\0" * 4,
                        _mb(cmac) + b"\0" * 10, b"", b"") + b"\x63\x82\x53\x63"
        o = bytes([53, 1, mt])
        if host:
            o += bytes([12, len(host)]) + host.encode()
        if vc:
            o += bytes([60, len(vc)]) + vc.encode()
        if sid:
            o += bytes([54, 4]) + socket.inet_aton(sid)
        o += bytes([55, 4, 1, 3, 6, 15]) + b"\xff"
        return h + o

    def tls_hello(sni):
        s = sni.encode()
        ext = struct.pack(">HH", 0, len(s) + 5) + struct.pack(">HBH", len(s) + 3, 0, len(s)) + s
        b = b"\x03\x03" + b"\x11" * 32 + b"\x00" + struct.pack(">H", 2) + b"\xc0\x2f" + b"\x01\x00" + struct.pack(">H", len(ext)) + ext
        hs = b"\x01" + len(b).to_bytes(3, "big") + b
        return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs

    http_req = b"GET / HTTP/1.1\r\nHost: 192.168.10.11\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n"
    http_resp = b"HTTP/1.1 200 OK\r\nServer: Siemens, SIMATIC, S7-1200\r\nContent-Length: 0\r\n\r\n"

    hs_ = lambda n: H[n]
    # ================= phase 1: normal operation =================
    for n, h in H.items():  # ARP presence
        if h["ip"].startswith(LOCAL):
            arp(2, h["mac"], h["ip"], H["gw"]["mac"], H["gw"]["ip"])
    arp(2, GW, H["gw"]["ip"], H["hmi"]["mac"], H["hmi"]["ip"])
    arp(2, GW, H["gw"]["ip"], H["scada"]["mac"], H["scada"]["ip"])  # (gw answers on behalf)
    for _ in range(3):
        add(_eth("01:80:c2:00:00:0e", H["sw"]["mac"], 0x88CC, lldp), 5)
    add(_eth("01:0e:cf:00:00:00", H["ews"]["mac"], 0x8892, dcp_req))
    add(_eth(H["ews"]["mac"], H["pn"]["mac"], 0x8892, dcp_resp))
    for _ in range(10):
        add(_eth("01:0c:cd:01:00:01", H["pn"]["mac"], 0x88B8, goose), 1)
    # DHCP
    add(_eth("ff:ff:ff:ff:ff:ff", H["ews"]["mac"], 0x0800, _ip4("0.0.0.0", "255.255.255.255", 17, _udp("0.0.0.0", "255.255.255.255", 68, 67, dhcp(1, 1, H["ews"]["mac"], "EWS-01", "MSFT 5.0")), 128)))
    udp(H["dns"], "255.255.255.255", 67, 68, dhcp(2, 2, H["ews"]["mac"], yi=H["ews"]["ip"], sid=H["dns"]["ip"]), bcast=True)
    # DNS
    for nm in ("scada.plant.local", "historian.plant.local", "time.windows.com"):
        udp(H["hmi"], H["dns"], 40000 + rnd.randint(0, 999), 53, dns_q(nm))
    # S7: HMI & EWS -> PLC1
    msgs = [("c", s7_cr), ("s", s7_cc), ("c", s7_setup), ("s", s7_setup_r)]
    for _ in range(25):
        msgs += [("c", s7_read), ("s", s7_read_r)]
    conv(H["hmi"], H["plc1"], 49200, 102, msgs)
    conv(H["ews"], H["plc1"], 49300, 102, [("c", s7_cr), ("s", s7_cc), ("c", s7_setup), ("s", s7_setup_r), ("c", s7_szl), ("s", s7_szl_r)])
    conv(H["ews"], H["plc1"], 49301, 80, [("c", http_req), ("s", http_resp)])
    # Modbus: SCADA (routed) -> RTU
    mm = []
    for i in range(30):
        mm += [("c", mb(i, 1, bytes([3]) + struct.pack(">HH", 0, 10))), ("s", mb(i, 1, bytes([3, 20]) + b"\x00\x01" * 10))]
    mm += [("c", mb(99, 1, bytes([43, 0x0E, 1, 0]))),
           ("s", mb(99, 1, bytes([43, 0x0E, 1, 1, 0, 0, 3]) + obj(0, "Schneider Electric") + obj(1, "BMXP342020") + obj(2, "v2.70")))]
    conv(H["scada"], H["rtu1"], 50100, 502, mm)
    conv(H["hmi"], H["rtu1"], 50101, 502, [("c", mb(1, 1, bytes([3]) + struct.pack(">HH", 0, 4))), ("s", mb(1, 1, bytes([3, 8]) + b"\x00" * 8))])
    # EtherNet/IP
    conv(H["hmi"], H["plc2"], 50200, 44818, [("c", enip(0x65, struct.pack("<HH", 1, 0))), ("s", enip(0x65, struct.pack("<HH", 1, 0), 7))] + [("c", cip_read), ("s", cip_read)] * 12)
    udp(H["ews"], "192.168.10.255", 50201, 44818, enip(0x63), bcast=True)
    udp(H["plc2"], H["ews"], 44818, 50201, enip_li_r)
    # DNP3
    dd = [("c", dnp3(5, 1, 1, b"\x3c\x01\x06")), ("s", dnp3(1, 5, 129, b"\x00\x00", 0x44))] * 20
    conv(H["scada"], H["dnp"], 50300, 20000, dd)
    # IEC-104
    conv(H["scada"], H["iec"], 50400, 2404, [("c", iec_start), ("s", bytes([0x68, 4, 0x0B, 0, 0, 0])), ("c", iec_gi), ("s", iec_meas)] + [("s", iec_meas)] * 10)
    # BACnet
    udp(H["hmi"], "192.168.10.255", 47808, 47808, whois, bcast=True)
    udp(H["bac"], H["hmi"], 47808, 47808, iam)
    # OPC UA
    conv(H["hmi"], H["opc"], 50500, 4840, [("c", opc_hel), ("s", opc_ack)])
    # TLS to internet from EWS
    conv(H["ews"], H["web"], 50600, 443, [("c", tls_hello("update.vendor-portal.com"))])
    # PLC2 talks to the internet (misconfig / exposure)
    conv(H["plc2"], H["cloud"], 50700, 44818, [("c", enip(0x65, struct.pack("<HH", 1, 0))), ("s", enip(0x65, struct.pack("<HH", 1, 0), 9))])
    cut = len(pk)
    # ================= phase 2: rogue device appears =================
    t[0] += 120
    R = H["rogue"]
    for i in range(1, 41):  # ARP sweep
        arp(1, R["mac"], R["ip"], "00:00:00:00:00:00", "192.168.10.%d" % i)
    for p in range(20, 62):  # port scan PLC1
        send(R, H["plc1"], 6, _tcp(R["ip"], H["plc1"]["ip"], 41000 + p, p, 0x02), 0.01)
    conv(R, H["plc1"], 42000, 102, [("c", s7_cr), ("s", s7_cc), ("c", s7_setup), ("s", s7_setup_r), ("c", s7_szl), ("s", s7_szl_r),
                                    ("c", s7_write), ("c", s7_dl), ("c", s7_stop)])
    conv(R, H["rtu1"], 42001, 502, [("c", mb(1, 1, bytes([6]) + struct.pack(">HH", 100, 1234))),
                                    ("c", mb(2, 1, bytes([16]) + struct.pack(">HHB", 0, 2, 4) + b"\x00\x01\x00\x02"))])
    conv(R, H["rtu1"], 42002, 23, [("c", b"admin\r\n")])
    conv(R, H["plc2"], 42003, 44818, [("c", enip(0x65, struct.pack("<HH", 1, 0))), ("c", cip_write), ("c", cip_stop)])
    conv(R, H["dnp"], 42004, 20000, [("c", dnp3(5, 3, 13))])
    conv(R, H["iec"], 42005, 2404, [("c", iec_start), ("c", iec_cmd)])
    udp(R, H["bac"], 47808, 47808, bac_write)
    udp(R, "255.255.255.255", 68, 67, dhcp(1, 1, R["mac"], "raspberrypi", "dhcpcd-8.1.2"), bcast=True)
    udp(R, "255.255.255.255", 67, 68, dhcp(2, 2, H["ews"]["mac"], yi="192.168.10.150", sid=R["ip"]), bcast=True)
    arp(2, R["mac"], H["plc1"]["ip"], H["hmi"]["mac"], H["hmi"]["ip"])  # ARP spoof PLC1

    if not attacks:
        pk = pk[:cut]
    pk.sort(key=lambda x: x[0])
    out = PcapOut(path)
    for ts, fr in pk:
        out.write(ts, fr)
    out.close()
    return len(pk)



# ----------------------------------------------------------------------------------------------
# Sensor (appliance) mode: capture locally, push inventory/alerts to OTSense Central
# ----------------------------------------------------------------------------------------------



class ActiveScanner:
    """Active scanning. OFF unless the mode is "active" (choice made on the sensor page, in the sensor settings, or by central).
    PASSIVE (default) = the sensor only listens and sends nothing to the monitored network.
    ACTIVE = every `every` seconds it asks every address of its own subnet (max /22) "are you there?":
      Linux with root: ARP who-has requests (layer 2 only, harmless to PLCs).
      Windows / no root / phone: short TCP connects to common IT ports + a read of the ARP table (estimate, lower bound).
    Own network only. Each device found is added as an asset and the list goes to central in the sensor meta ("active").
    OTSENSE_ACTIVE=0 hard-disables it, whatever anybody selects."""

    def __init__(self, an, iface="", every=60):
        self.an, self.iface, self.every = an, iface or "", max(20, int(every))
        self.mode = "passive"
        self.result = {"enabled": False, "devices": 0, "list": [], "subnet": "", "iface": "", "at": 0, "error": ""}
        self.started = False
        self.dead = False
        self.wake = threading.Event()

    def set_mode(self, mode):
        mode = "active" if mode == "active" else "passive"
        if os.environ.get("OTSENSE_ACTIVE", "1") == "0":
            mode = "passive"
        if mode == self.mode and (self.started or mode == "passive"):
            return
        self.mode = mode
        if mode == "active":
            if not self.started:
                self.started = True
                threading.Thread(target=self._loop, daemon=True).start()
            self.wake.set()
        else:
            self.result = {"enabled": False, "devices": 0, "list": [], "subnet": "", "iface": "", "at": int(time.time()), "error": ""}

    def close(self):
        self.dead = True
        self.wake.set()

    def _find(self):
        ifc = self.iface
        if not ifc or ifc == "any":
            out = subprocess.run(["ip", "-4", "route", "show", "default"], capture_output=True, text=True).stdout
            m = re.search(r"dev (\S+)", out)
            ifc = m.group(1) if m else ""
        if not ifc:
            raise RuntimeError("no management interface with an IPv4 address")
        out = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev", ifc], capture_output=True, text=True).stdout
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", out)
        if not m:
            raise RuntimeError("%s has no IPv4 address" % ifc)
        net = ipaddress.ip_network("%s/%s" % (m.group(1), m.group(2)), strict=False)
        if net.prefixlen < 22:
            net = ipaddress.ip_network("%s/22" % m.group(1), strict=False)
        mac = open("/sys/class/net/%s/address" % ifc).read().strip()
        return ifc, m.group(1), net, mac

    def scan(self):
        ifc, myip, net, mymac = self._find()
        smac = bytes.fromhex(mymac.replace(":", ""))
        sip = socket.inet_aton(myip)
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        s.bind((ifc, 0))
        found = {}
        for ip in net.hosts():
            ips = str(ip)
            if ips == myip:
                continue
            pkt = (b"\xff" * 6 + smac + b"\x08\x06" + struct.pack(">HHBBH", 1, 0x0800, 6, 4, 1) + smac + sip
                   + b"\x00" * 6 + socket.inet_aton(ips))
            try:
                s.send(pkt)
            except OSError:
                pass
            time.sleep(0.002)
        end = time.time() + 4
        while time.time() < end:
            s.settimeout(max(0.1, end - time.time()))
            try:
                d = s.recv(2048)
            except (socket.timeout, OSError):
                break
            if len(d) >= 42 and d[12:14] == b"\x08\x06" and d[20:22] == b"\x00\x02":
                found[socket.inet_ntoa(d[28:32])] = ":".join("%02x" % b for b in d[22:28])
        s.close()
        found[myip] = mymac
        return ifc, net, found

    @staticmethod
    def _arp_table(net):
        """IP -> MAC from the operating system's ARP/neighbour table (Windows `arp -a`, Linux `arp -a` / `ip neigh`)."""
        out = ""
        for cmd in (["arp", "-a"], ["ip", "-4", "neigh"]):
            try:
                out += subprocess.run(cmd, capture_output=True, text=True, timeout=8).stdout + "\n"
            except Exception:  # noqa
                pass
        res = {}
        for m in re.finditer(r"(\d{1,3}(?:\.\d{1,3}){3})\)?(?:\s+dev\s+\S+\s+lladdr|\s+at)?\s+([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})", out):
            try:
                ip = ipaddress.ip_address(m.group(1))
            except ValueError:
                continue
            mac = m.group(2).lower().replace("-", ":")
            if ip not in net or ip == net.network_address or ip == net.broadcast_address or mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                continue
            res[str(ip)] = mac
        return res

    LITE_PORTS = (80, 443, 502, 102, 44818, 20000, 47808, 4840, 135, 445, 139, 22, 23, 53, 8080, 62078, 8008, 8009, 7000, 49152, 5000)

    def scan_lite(self, net=None):
        """No root / no raw sockets (a phone in Termux): probe the /24 with short TCP connects. A host that answers OR actively
        refuses is alive. Phones/PCs whose firewall silently drops packets are missed, so this is an ESTIMATE (a lower bound)."""
        import errno
        from concurrent.futures import ThreadPoolExecutor
        if net is None:
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                try:
                    u.connect(("8.8.8.8", 80))
                except OSError:
                    u.connect(("10.255.255.255", 80))
                myip = u.getsockname()[0]
            finally:
                u.close()
            net = ipaddress.ip_network(myip + "/24", strict=False)
        else:
            myip = ""

        def probe(ip):
            for port in self.LITE_PORTS:
                c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                c.settimeout(0.4)
                try:
                    rc = c.connect_ex((ip, port))
                except OSError:
                    rc = -1
                finally:
                    c.close()
                if rc in (0, errno.ECONNREFUSED):
                    return ip
            return None

        hosts = [str(h) for h in net.hosts() if str(h) != myip]
        with ThreadPoolExecutor(max_workers=64) as ex:
            alive = [x for x in ex.map(probe, hosts) if x]
        found = {ip: "" for ip in alive}
        # one UDP datagram per address forces Windows to ask \"who has <ip>?\" even for hosts that drop every TCP/ICMP packet
        us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for h in hosts:
                try:
                    us.sendto(b"\x00", (h, 9))
                except OSError:
                    pass
        finally:
            us.close()
        time.sleep(3)   # give Windows time to finish its ARP lookups before the table is read
        # every connect above makes the OS ask "who has <ip>?", so the ARP table now also lists hosts that hide all TCP ports
        for ip, mac in self._arp_table(net).items():
            if ip != myip:
                found.setdefault(ip, mac)
                if not found[ip]:
                    found[ip] = mac
        if myip:
            found[myip] = ""
        return "tcp-probe", net, found

    def _loop(self):
        while not self.dead:
            if self.mode != "active":
                self.wake.wait(5)
                self.wake.clear()
                continue
            try:
                method = "arp"
                try:
                    ifc, net, found = self.scan()
                except (PermissionError, FileNotFoundError, AttributeError, RuntimeError, OSError):
                    method = "tcp-probe (estimate, no root)"
                    ifc, net, found = self.scan_lite()
                if self.mode != "active" or self.dead:
                    continue
                now = time.time()
                with self.an.lock:
                    for ip, mac in found.items():
                        a = self.an.asset("ip:" + ip, now, ip=ip)
                        a.flags.add("active-scan")
                        if mac:
                            a.arp_macs[mac] += 1
                            self.an.mac_ips[mac].add(ip)
                lst = [{"ip": ip, "mac": mac, "vendor": mac_vendor(mac) or ""} for ip, mac in
                       sorted(found.items(), key=lambda kv: ipaddress.ip_address(kv[0]))]
                self.result = {"enabled": True, "devices": len(lst), "list": lst[:300], "subnet": str(net), "iface": ifc,
                               "method": method, "at": int(now), "error": ""}
            except Exception as e:  # noqa
                self.result = dict(self.result, enabled=True, error=str(e)[:200], at=int(time.time()))
            self.wake.wait(self.every)
            self.wake.clear()


class Sensor:
    """Pushes only what changed since the last successful push. If central is unreachable nothing is
    lost: unsent items stay 'changed' and go out with the next successful push (exponential back-off)."""

    def __init__(self, an, site, central, token, interval=30, cafile=None, insecure=False, iface="any", mode="live",
                 batch=1500):
        self.an, self.site, self.token = an, site, token
        self.url = central.rstrip("/") + "/api/ingest"
        self.interval, self.iface, self.mode, self.batch = max(5, int(interval)), iface, mode, batch
        self.sent, self.started, self.fail, self.last_ok, self.pushes = {}, time.time(), 0, None, 0
        self.pending, self.last_attempt, self.pushed_total = 0, None, 0
        self.act_pending, self.act_total, self.act_overflow = [], 0, 0  # activity rows waiting for central
        self.ctx = None
        if self.url.startswith("https"):
            if insecure:
                self.ctx = ssl._create_unverified_context()
            else:
                self.ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
        elif self.url.startswith("http://"):
            self.log("WARNING: central URL is plain http - the site token and data cross the network unencrypted")
        self._last_err = None
        self.ui_url = ""
        self.active = ActiveScanner(an, "", int(os.environ.get("OTSENSE_ACTIVE_EVERY", "60")))
        self.scan_local = "active" if (os.environ.get("OTSENSE_SCAN") or "").strip().lower() == "active" else "passive"   # this sensor's own choice
        self.scan_central = ""      # "passive" / "active" when central has taken over the decision for this site, "" = sensor decides
        self.mgmt_iface = ""

    def scan_effective(self):
        return self.scan_central or self.scan_local

    def _apply_scan(self):
        self.active.iface = self.mgmt_iface or ""
        self.active.set_mode(self.scan_effective())

    def _orders(self, resp):
        m = str((resp or {}).get("scan_mode") or "").lower()
        new = m if m in ("passive", "active") else ""
        if new != self.scan_central:
            self.scan_central = new
            self.log("central set scanning to %s" % (new or "the sensor's own choice"))
        self._apply_scan()

    @staticmethod
    def log(msg):
        print("[%s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)

    def _meta(self, snap):
        an, up = self.an, time.time() - self.started
        s = snap["summary"]
        return {"hostname": socket.gethostname(), "version": VERSION, "iface": self.iface, "mode": self.mode,
                "interval": self.interval, "uptime_s": int(up), "packets": an.pkts, "bytes": an.bytes,
                "pps": round(an.pkts / max(up, 1), 1), "parse_errors": an.errors, "first_packet": iso(an.t0),
                "last_packet": iso(an.t1), "assets": s["assets"], "ot_assets": s["ot_assets"], "flows": s["flows"],
                "alerts": s["alerts"], "ot_protocols": s["ot_protocols"],
                "protocols": [{"p": p["protocol"], "n": p["packets"], "ot": p["ot"]} for p in snap["protocols"][:20]],
                "source": an.source, "ui_url": getattr(self, "ui_url", ""),
                "activities_sent": self.act_total, "activities_dropped": an.act_dropped + self.act_overflow,
                "active": self.active.result, "scan_mode": self.scan_effective(),
                "scan_source": "central" if self.scan_central else "sensor"}

    def _collect(self, snap):
        out = []
        for a in snap["assets"]:
            out.append(("assets", a["id"], a))
        for f in snap["flows"]:
            f["fid"] = "|".join([f["client"], f["server"], f["l4"], str(f["port"]), f["proto"]])
            out.append(("flows", f["fid"], f))
        for al in snap["alerts"]:
            out.append(("alerts", al["uid"], {k: v for k, v in al.items() if k != "id"}))
        changed = []
        for kind, key, obj in out:
            h = hashlib.md5(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            if self.sent.get((kind, key)) != h:
                changed.append((kind, key, obj, h))
        return changed

    def _post(self, body):
        data = gzip.compress(json.dumps(body, separators=(",", ":")).encode("utf-8"))
        req = urllib.request.Request(self.url, data=data, method="POST", headers={
            "Content-Type": "application/json", "Content-Encoding": "gzip",
            "Authorization": "Bearer " + self.token, "User-Agent": "otsense-sensor/" + VERSION})
        with urllib.request.urlopen(req, timeout=30, context=self.ctx) as r:
            return json.loads(r.read() or b"{}")

    ACT_BACKLOG = 100000

    def push(self):
        self._apply_scan()
        snap = self.an.snapshot()
        items = self._collect(snap)
        self.act_pending.extend(self.an.drain_activities())
        if len(self.act_pending) > self.ACT_BACKLOG:  # central unreachable for a very long time: drop the oldest
            cut = len(self.act_pending) - self.ACT_BACKLOG
            del self.act_pending[:cut]
            self.act_overflow += cut
        self.pending, self.last_attempt = len(items) + len(self.act_pending), time.time()
        meta = self._meta(snap)
        posts = [(items[i:i + self.batch], []) for i in range(0, len(items), self.batch)]
        posts += [([], self.act_pending[i:i + self.batch]) for i in range(0, len(self.act_pending), self.batch)]
        n = {"assets": 0, "flows": 0, "alerts": 0, "activities": 0}
        resp = None
        for ch, acts in posts or [([], [])]:
            body = {"v": 2, "site": self.site, "sensor": meta, "assets": [], "flows": [], "alerts": [], "activities": acts}
            for kind, _key, obj, _h in ch:
                body[kind].append(obj)
            try:
                resp = self._post(body)
            except urllib.error.HTTPError as e:
                self.fail += 1
                msg = "central rejected the push (HTTP %d)%s" % (e.code, " - check the site token" if e.code == 401 else "")
                self._err(msg)
                return False
            except Exception as e:  # noqa
                self.fail += 1
                self._err("cannot reach central at %s: %s (will retry, data is kept)" % (self.url, e))
                return False
            for kind, key, _obj, h in ch:
                self.sent[(kind, key)] = h
                n[kind] += 1
            if acts:
                del self.act_pending[:len(acts)]
                n["activities"] += len(acts)
        self._orders(resp)
        if self.fail or self._last_err:
            self.log("connection to central restored")
        self.fail, self._last_err, self.last_ok = 0, None, time.time()
        self.pending = 0
        self.act_total += n["activities"]
        self.pushed_total += sum(n.values())
        self.pushes += 1
        if sum(n.values()) or self.pushes == 1:
            self.log("pushed %d assets, %d flows, %d alerts, %d activities to central (%d packets seen)" % (
                n["assets"], n["flows"], n["alerts"], n["activities"], self.an.pkts))
        return True

    def _err(self, msg):
        if msg != self._last_err:
            self.log(msg)
        self._last_err = msg


def serve_sensor_page(sn, an, errs, host, port, state_file):
    """Tiny status page of the headless sensor (Windows app / any computer): shows the connection to central and lets the person
    choose Passive or Active scanning. Listens on this computer only unless --ui-host says otherwise."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from html import escape
    csrf = secrets.token_hex(16)
    if host not in ("127.0.0.1", "localhost", "::1"):
        sn.log("WARNING: the local page is reachable from the network and has no password - keep it on 127.0.0.1 unless the network is trusted")

    def data():
        now = time.time()
        a = sn.active.result
        return {"site": sn.site, "central": sn.url.replace("/api/ingest", ""), "iface": sn.iface, "packets": an.pkts, "assets": len(an.assets),
                "alerts": len(an.alerts), "connected": bool(sn.last_ok) and not sn._last_err, "last_ok_s": int(now - sn.last_ok) if sn.last_ok else None,
                "error": sn._last_err or "", "capture_errors": list(errs), "scan_mode": sn.scan_effective(), "scan_source": "central" if sn.scan_central else "sensor",
                "scan_local": sn.scan_local, "active": {"devices": a.get("devices", 0), "method": a.get("method", ""), "subnet": a.get("subnet", ""),
                                                       "error": a.get("error", ""), "enabled": bool(a.get("enabled"))}, "version": VERSION}

    def page():
        d = data()
        ok = d["connected"]
        rows = [("Site", d["site"]), ("Central", d["central"]),
                ("Connection", ("connected, last data %ss ago" % d["last_ok_s"]) if ok else ("not connected yet" + ((": " + d["error"]) if d["error"] else ""))),
                ("Capture", ("on %s - %s packets, %s devices, %s alerts" % (d["iface"] or "main network card", d["packets"], d["assets"], d["alerts"]))),
                ("Sensor version", d["version"])]
        if d["capture_errors"]:
            rows.append(("Capture problem", "; ".join(d["capture_errors"])))
        t = "".join("<tr><th>%s</th><td>%s</td></tr>" % (escape(k), escape(str(v))) for k, v in rows)
        mode, src = d["scan_mode"], d["scan_source"]
        form = ""
        if src == "central":
            form = "<p class='note'>Scanning is set to <b>%s</b> by central for this whole site. Ask the central administrator to change it (Sites tab).</p>" % escape(mode)
        else:
            form = ("<form method='post' action='/scan'><input type='hidden' name='csrf' value='%s'>"
                    "<label><input type='radio' name='mode' value='passive'%s> <b>Passive</b> - only listen to the traffic this computer sees. Sends nothing.</label>"
                    "<label><input type='radio' name='mode' value='active'%s> <b>Active</b> - also ask every device on this computer's own network "
                    "(short connection attempts + ARP). Use only on a network you may scan.</label>"
                    "<button>Save</button></form>") % (csrf, " checked" if mode == "passive" else "", " checked" if mode == "active" else "")
        ac = ""
        if mode == "active":
            ac = "<p class='note'>Active scan: %s</p>" % escape(("%s devices found on %s (%s)" % (d["active"]["devices"], d["active"]["subnet"], d["active"]["method"]))
                                                                if d["active"]["enabled"] and not d["active"]["error"] else (d["active"]["error"] or "first scan running..."))
        return ("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><meta http-equiv=refresh content=15>"
                "<title>OT Sense sensor</title><style>body{font:15px system-ui,sans-serif;background:#0b1220;color:#dbe4f0;max-width:640px;margin:24px auto;padding:0 14px}"
                "h1{font-size:20px}table{width:100%%;border-collapse:collapse}th{text-align:left;color:#8aa0bd;width:34%%;padding:6px 0;vertical-align:top}td{padding:6px 0}"
                "form{display:grid;gap:10px;margin:14px 0}label{display:block;padding:10px;border:1px solid #27364f;border-radius:8px}button{padding:10px;border-radius:8px;"
                "border:1px solid #2aa;background:#17636a;color:#fff;font-size:15px}.note{color:#9fb3cc}.pill{display:inline-block;padding:2px 10px;border-radius:99px;background:%s}</style>"
                "<h1>OT Sense sensor <span class=pill>%s</span></h1><table>%s</table><h2>Scanning: %s <small class=note>(set by %s)</small></h2>%s%s") % (
                    "#1b6b3a" if ok else "#7a5a12", "online" if ok else "waiting", t, escape(mode), escape(src), form, ac)

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
            b = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(b)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "DENY")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            if self.path.split("?")[0] == "/api/status":
                return self._send(200, json.dumps(data()), "application/json")
            self._send(200, page())

        def do_POST(self):
            if self.path != "/scan":
                return self._send(404, "not found")
            from urllib.parse import parse_qs
            n = min(int(self.headers.get("Content-Length") or 0), 2000)
            f = parse_qs(self.rfile.read(n).decode("utf-8", "replace"))
            if f.get("csrf", [""])[0] != csrf:
                return self._send(403, "bad form token - go back and reload the page")
            if sn.scan_central:
                return self._send(409, "scanning is controlled by central")
            m = "active" if f.get("mode", [""])[0] == "active" else "passive"
            sn.scan_local = m
            sn._apply_scan()
            sn.log("scanning set to %s on the local page" % m)
            if state_file:
                try:
                    with open(state_file, "w") as fh:
                        json.dump({"scan_mode": m}, fh)
                except OSError:
                    pass
            self._send(303, "", extra={"Location": "/"})

    srv = ThreadingHTTPServer((host, port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    sn.log("sensor page: http://%s:%d/" % ("127.0.0.1" if host in ("0.0.0.0", "") else host, port))
    return srv


def run_sensor(args):
    if not args.central or not args.token:
        print("error: --central and --token are required (or OTSENSE_CENTRAL / OTSENSE_TOKEN)", file=sys.stderr)
        return 2
    an = Analyzer(_load_baseline(args.baseline), args.debug)
    sn = Sensor(an, args.site, args.central, args.token, args.interval, args.cafile, args.insecure,
                args.iface if not args.pcap else "pcap", "pcap" if args.pcap else "live")
    sn.scan_local = "active" if getattr(args, "scan", "passive") == "active" else "passive"
    sf = getattr(args, "state_file", None)
    if sf:
        try:
            with open(sf) as f:
                m = json.load(f).get("scan_mode")
            if m in ("passive", "active"):
                sn.scan_local = m       # a choice made on the local page wins over the install-time default
        except (OSError, ValueError):
            pass
    try:
        from urllib.parse import urlparse
        cu = urlparse(args.central)
        an.exclude = (socket.gethostbyname(cu.hostname), cu.port or (443 if cu.scheme == "https" else 80))
    except Exception:
        pass
    stop, errs, th = threading.Event(), [], None
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    if getattr(args, "ui_port", 0):
        try:
            serve_sensor_page(sn, an, errs, args.ui_host, args.ui_port, sf)
        except OSError as e:
            sn.log("local status page not started: %s" % e)
    if args.pcap:
        try:
            an.feed_pcap(args.pcap)
        except (OSError, ValueError) as e:
            print("Cannot read %s: %s" % (args.pcap, e), file=sys.stderr)
            return 2
        sn.log("replayed %d packets from %s" % (an.pkts, args.pcap))
        ok = sn.push()
        if not args.keep_alive:
            return 0 if ok else 1
    else:
        an.source = "live: " + args.iface
        cap_if = args.iface if (sys.platform.startswith("linux") or args.iface not in ("any", "")) else ""   # Windows/macOS: "" = the computer's main network card
        if getattr(args, "no_capture", False):
            errs.append("Live listening is OFF: the Npcap driver is not installed (get it from https://npcap.com, default options). Active scanning and the link to central still work.")
            sn.log(errs[0])
        else:
            th = threading.Thread(target=run_capture, args=(an, cap_if, stop, args.bpf, None, errs), daemon=True)
            th.start()
            sn.log("sensor '%s' capturing on %s, pushing to %s every %ds" % (args.site, args.iface, args.central, sn.interval))
    rc, nxt = 0, time.time() + 5
    try:
        while not stop.is_set():
            time.sleep(1)
            if th is not None and not th.is_alive() and not stop.is_set():
                for e in errs:
                    print(e, file=sys.stderr)
                sn.log("capture stopped - exiting so the service manager can restart us")
                rc = 1
                break
            if time.time() >= nxt:
                ok = sn.push()
                nxt = time.time() + (sn.interval if ok else min(300, sn.interval * (2 ** min(sn.fail, 4))))
    except KeyboardInterrupt:
        pass
    stop.set()
    if th:
        th.join(3)
    try:
        sn.push()
    except Exception:
        pass
    return rc



# ----------------------------------------------------------------------------------------------
# Sensor APPLIANCE: the sensor with a local web UI (setup wizard, live status, live traffic)
# ----------------------------------------------------------------------------------------------

DEFAULT_CFG = {"site": "", "central": "", "token": "", "iface": "", "interval": 30, "cafile": "", "insecure": False,
               "bpf": "", "autostart": True, "mgmt_iface": "", "restrict_ui": False, "scan_mode": "passive", "scan_user": False}


def _hash_pw(pw, salt=None, it=200000):
    salt = salt or os.urandom(16)
    return "pbkdf2$%d$%s$%s" % (it, salt.hex(), hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, it).hex())


def _check_pw(pw, stored):
    try:
        _, it, salt, h = stored.split("$")
        return hmac.compare_digest(hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), int(it)).hex(), h)
    except Exception:
        return False


def _rd(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


_IPCACHE = {"t": 0.0, "d": {}}


def _ipv4_map():
    """name -> ['10.0.0.5/24', ...] for every interface (one `ip` call, cached 2 s)."""
    now = time.time()
    if now - _IPCACHE["t"] < 2:
        return _IPCACHE["d"]
    d = {}
    ipb = shutil.which("ip") or next((x for x in ("/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip") if os.path.exists(x)), None)
    if ipb:
        try:
            r = subprocess.run([ipb, "-o", "-4", "addr", "show"], capture_output=True, text=True, timeout=4)
            for ln in r.stdout.splitlines():
                m = re.match(r"^\d+:\s+(\S+?)(?:@\S+)?\s+inet\s+(\S+)", ln)
                if m:
                    d.setdefault(m.group(1), []).append(m.group(2))
        except Exception:
            pass
    _IPCACHE.update(t=now, d=d)
    return d


def _nic_kind(name, base, wireless, virtual):
    if name == "lo":
        return "loopback"
    if os.path.exists(base + "/bridge"):
        return "bridge"
    if os.path.exists(base + "/bonding"):
        return "bond"
    if os.path.exists("/proc/net/vlan/" + name):
        return "vlan"
    if wireless:
        return "wifi"
    return "virtual" if virtual else "physical"


def nic_info():
    """Every network port with link state, speed, addresses, driver and rx counters (Linux /sys)."""
    out, route_if = [], None
    for ln in (_rd("/proc/net/route") or "").splitlines()[1:]:
        p = ln.split()
        if len(p) > 3 and p[1] == "00000000" and int(p[3], 16) & 2:
            route_if = p[0]
            break
    try:
        names = sorted(os.listdir("/sys/class/net"))
    except OSError:
        return out
    v4 = _ipv4_map()
    for name in names:
        base = "/sys/class/net/" + name
        ips = [x.split("/")[0] for x in v4.get(name, [])]
        ip = ips[0] if ips else ""
        if not ip:
            try:
                import fcntl
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                ip = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", name[:15].encode()))[20:24])
                s.close()
                ips = [ip]
            except Exception:
                pass
        speed = _rd(base + "/speed")
        flags = int(_rd(base + "/flags") or "0", 16)
        real = os.path.realpath(base)
        virtual = real.startswith("/sys/devices/virtual/") or name == "lo"
        wireless = os.path.exists(base + "/wireless")
        drv = ""
        try:
            if os.path.exists(base + "/device/driver"):
                drv = os.path.basename(os.path.realpath(base + "/device/driver"))
        except OSError:
            pass
        duplex = _rd(base + "/duplex")
        out.append({"name": name, "mac": _rd(base + "/address"), "state": _rd(base + "/operstate") or "unknown",
                    "carrier": _rd(base + "/carrier") == "1", "speed": int(speed) if speed and speed.lstrip("-").isdigit() and int(speed) > 0 else None,
                    "duplex": duplex if duplex in ("full", "half") else None,
                    "ip": ip, "ips": ips, "ip_cidr": v4.get(name, []), "mtu": int(_rd(base + "/mtu") or 0),
                    "driver": drv, "bus": "usb" if "/usb" in real else "pci" if "/pci" in real else "",
                    "kind": _nic_kind(name, base, wireless, virtual),
                    "rx_packets": int(_rd(base + "/statistics/rx_packets") or 0),
                    "rx_bytes": int(_rd(base + "/statistics/rx_bytes") or 0),
                    "virtual": virtual, "ether": _rd(base + "/type") == "1",
                    "wireless": wireless, "default_route": name == route_if,
                    "promisc": bool(flags & 0x100), "up": bool(flags & 1)})
    return out


def mgmt_ip(toward=None):
    """The address this box uses to reach the management network (UDP connect sends no packets)."""
    from urllib.parse import urlparse
    host = (urlparse(toward).hostname if toward else None) or "192.0.2.1"
    try:
        sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sk.connect((host, 9))
        ip = sk.getsockname()[0]
        sk.close()
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    for n in nic_info():
        if n.get("ip") and not n["ip"].startswith("127."):
            return n["ip"]
    return ""


def prepare_nic(iface):
    """Bring the capture NIC up in promiscuous mode, merge-offloads off. Best effort (needs CAP_NET_ADMIN/root)."""
    msgs = []
    ipb = shutil.which("ip") or next((p for p in ("/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip") if os.path.exists(p)), None)
    if ipb:
        try:
            r = subprocess.run([ipb, "link", "set", "dev", iface, "up", "promisc", "on"], capture_output=True, text=True, timeout=8)
            if r.returncode:
                msgs.append("could not set %s up/promiscuous: %s" % (iface, (r.stderr or "").strip()))
        except Exception as e:  # noqa
            msgs.append(str(e))
    eth = shutil.which("ethtool")
    if eth:
        try:
            subprocess.run([eth, "-K", iface, "gro", "off", "lro", "off"], capture_output=True, timeout=8)
        except Exception:
            pass
    return msgs


def make_ui_cert(dirpath, names):
    crt, key = os.path.join(dirpath, "ui-cert.pem"), os.path.join(dirpath, "ui-key.pem")
    if os.path.exists(crt) and os.path.exists(key):
        return crt, key
    if not shutil.which("openssl"):
        return None, None
    san = ",".join(("IP:" + n if re.match(r"^[0-9.]+$", n) else "DNS:" + n) for n in dict.fromkeys(["localhost", "127.0.0.1"] + names) if n)
    try:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt, "-days", "3650",
                        "-subj", "/CN=otsense-sensor", "-addext", "subjectAltName=" + san], check=True, capture_output=True, timeout=60)
        os.chmod(key, 0o600)
        return crt, key
    except Exception:
        return None, None


# ---------------------------------------------------------------- web page certificate helpers
_PEM_CERT = re.compile(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)
_PEM_KEY = re.compile(r"-----BEGIN ((?:ENCRYPTED |RSA |EC |DSA )?PRIVATE KEY)-----.+?-----END \1-----", re.S)


def _pem_certs(text):
    return [c.strip() + "\n" for c in _PEM_CERT.findall(text or "")]


def _pem_key(text):
    m = _PEM_KEY.search(text or "")
    return (m.group(0).strip() + "\n") if m else ""


def _openssl():
    return shutil.which("openssl")


def _pfx_to_pem(data, password, tmpdir):
    """PKCS#12 (.pfx/.p12) -> (certificate chain PEM, unencrypted key PEM). Needs the openssl command."""
    if not _openssl():
        raise ValueError("openssl is not installed on the sensor (apt install openssl) - needed to read a .pfx/.p12 file")
    f = os.path.join(tmpdir, "in.p12")
    with open(f, "wb") as fh:
        fh.write(data)
    env = dict(os.environ, OTS_PFX_PW=password or "")
    res = {}
    for what, args in (("cert", ["-nokeys"]), ("key", ["-nocerts", "-nodes"])):
        r = subprocess.run([_openssl(), "pkcs12", "-in", f, "-passin", "env:OTS_PFX_PW"] + args, capture_output=True, text=True, timeout=30, env=env)
        if r.returncode:
            err = (r.stderr or "").lower()
            if "mac verify" in err or "password" in err:
                raise ValueError("wrong .pfx password")
            if "unsupported" in err or "legacy" in err:
                raise ValueError("this .pfx uses an old encryption format; re-export it with AES, or convert it with: openssl pkcs12 -legacy -in file.pfx -out file.pem -nodes")
            raise ValueError("cannot read the .pfx file: %s" % (r.stderr or "").strip().splitlines()[-1:] or "unknown error")
        res[what] = r.stdout
    return res["cert"], res["key"]


def _decrypt_key(key_pem, passphrase, tmpdir):
    """Return an unencrypted PEM key (the service has no way to ask for a passphrase at boot)."""
    if "ENCRYPTED" not in key_pem:
        return key_pem
    if not passphrase:
        raise ValueError("the private key is protected by a passphrase - enter it (web page: passphrase box; installer: set OTSENSE_UI_KEY_PASS)")
    if not _openssl():
        raise ValueError("openssl is not installed on the sensor (apt install openssl) - needed to unlock an encrypted key")
    f = os.path.join(tmpdir, "enc.key")
    with open(f, "w") as fh:
        fh.write(key_pem)
    r = subprocess.run([_openssl(), "pkey", "-in", f, "-passin", "env:OTS_KEY_PW"], capture_output=True, text=True, timeout=30,
                       env=dict(os.environ, OTS_KEY_PW=passphrase))
    if r.returncode or "PRIVATE KEY" not in r.stdout:
        raise ValueError("wrong passphrase for the private key")
    return r.stdout


def _cert_details(pem, tmpdir):
    """Subject / issuer / validity / names of the first certificate in pem (stdlib only)."""
    f = os.path.join(tmpdir, "leaf.pem")
    with open(f, "w") as fh:
        fh.write(pem)
    d = {"sha256": "", "subject": "", "issuer": "", "not_before": 0, "not_after": 0, "san": [], "cn": "", "self_signed": False, "known": False}
    try:
        der = ssl.PEM_cert_to_DER_cert(pem)
        h = hashlib.sha256(der).hexdigest().upper()
        d["sha256"] = ":".join(h[i:i + 2] for i in range(0, len(h), 2))
    except Exception:
        pass
    try:
        c = ssl._ssl._test_decode_cert(f)  # stdlib helper (CPython), parses without trusting anything

        def flat(t):
            return {k: v for rdn in t for k, v in rdn}
        sub, iss = flat(c.get("subject", ())), flat(c.get("issuer", ()))
        d.update(subject=", ".join("%s=%s" % kv for rdn in c.get("subject", ()) for kv in rdn),
                 issuer=", ".join("%s=%s" % kv for rdn in c.get("issuer", ()) for kv in rdn),
                 cn=sub.get("commonName", ""), self_signed=c.get("subject") == c.get("issuer"),
                 not_before=ssl.cert_time_to_seconds(c["notBefore"]), not_after=ssl.cert_time_to_seconds(c["notAfter"]),
                 san=[(k, v) for k, v in c.get("subjectAltName", ())], known=True)
        d["issuer_cn"] = iss.get("commonName", "") or iss.get("organizationName", "")
    except Exception:
        pass
    return d


def _cert_covers(d, host):
    """Does the certificate's name list (SAN, or CN when there is no SAN) cover this host/IP?"""
    host = (host or "").lower().strip("[]")
    if not host:
        return True
    isip = bool(re.match(r"^[0-9.]+$", host)) or ":" in host
    names = [(k, v) for k, v in d.get("san", [])] or ([("DNS", d["cn"])] if d.get("cn") else [])
    for k, v in names:
        v = str(v).lower()
        if isip:
            if k.startswith("IP") and v == host:
                return True
        elif k == "DNS" and (v == host or (v.startswith("*.") and "." in host and host.split(".", 1)[1] == v[2:])):
            return True
    return False


class Appliance:
    def __init__(self, state_dir, debug=False):
        self.dir = state_dir
        os.makedirs(self.dir, exist_ok=True)
        self.path = os.path.join(self.dir, "sensor.json")
        self.lock = threading.RLock()
        self.debug = debug
        self.cfg = dict(DEFAULT_CFG, site=socket.gethostname())
        self.cfg.update(self._read())
        self.an = None
        self.sensor = None
        self.cap_stop = self.cap_thread = self.push_stop = self.push_thread = None
        self.cap_errs = []
        self.cap_started = 0.0
        self.raw = collections.deque(maxlen=5000)
        self.rate = collections.deque(maxlen=180)
        self.last_rx = 0.0
        self.manual_stop = False
        self.test = {"state": "idle"}
        self.fails = {}
        self.ui_port, self.ui_scheme = 8080, "https"
        self.on_tls_reload = None   # set by serve_appliance: rebuilds the TLS context of the running web server
        self.tls = {"source": "none", "error": ""}
        self._ipc = (0.0, [])
        self.started = time.time()
        self._snapc = (0, None)
        self._prev = (time.time(), 0, 0)
        if not self.cfg.get("secret"):
            self.cfg["secret"] = secrets.token_hex(32)
            self.save()
        threading.Thread(target=self._housekeeping, daemon=True).start()

    # ---------------------------------------------------------------- config
    def _read(self):
        try:
            with open(self.path) as f:
                d = json.load(f)
            return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def save(self):
        with self.lock:
            tmp = self.path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(self.cfg, f, indent=1)
            os.replace(tmp, self.path)

    def public_cfg(self):
        c = {k: self.cfg.get(k) for k in DEFAULT_CFG}
        c["scan_mode"] = "active" if c.get("scan_mode") == "active" else "passive"
        c["scan_central"] = self.sensor.scan_central if self.sensor else ""
        c["has_token"] = bool(self.cfg.get("token"))
        c["token"] = ""
        c["has_ca"] = bool(self.cfg.get("cafile") and os.path.exists(self.cfg["cafile"]))
        return c

    def set_password(self, pw):
        self.cfg["ui_pw"] = _hash_pw(pw)
        self.save()

    def secret(self):
        return bytes.fromhex(self.cfg["secret"])

    def cookie(self, user="setup", role="admin", ttl=12 * 3600):
        p = base64.urlsafe_b64encode(json.dumps({"u": user, "r": role, "e": int(time.time() + ttl)}).encode()).decode().rstrip("=")
        return p + "." + hmac.new(self.secret(), p.encode(), hashlib.sha256).hexdigest()

    def cookie_info(self, val):
        try:
            p, sig = val.split(".")
            if not hmac.compare_digest(sig, hmac.new(self.secret(), p.encode(), hashlib.sha256).hexdigest()):
                return None
            d = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
            return d if d["e"] > time.time() else None
        except Exception:
            return None

    def cookie_ok(self, val):
        return self.cookie_info(val) is not None

    def configured(self):
        return bool(self.cfg.get("iface"))

    def mgmt_ips(self):
        """IPv4 addresses currently on the chosen management port (cached 2 s)."""
        mg = self.cfg.get("mgmt_iface")
        if not mg:
            return []
        if time.time() - self._ipc[0] > 2:
            n = next((x for x in nic_info() if x["name"] == mg), None)
            self._ipc = (time.time(), list(n["ips"]) if n else [])
        return self._ipc[1]

    def ui_access_ok(self, local_ip):
        """Web page restricted to the management port? Loopback always works; with no usable management address we fail open
        (a lock-out on an appliance is worse than an open page behind a password)."""
        if not (self.cfg.get("restrict_ui") and self.cfg.get("mgmt_iface")):
            return True
        if local_ip.startswith("127."):
            return True
        ips = self.mgmt_ips()
        return (not ips) or local_ip in ips

    def ui_url(self):
        mi = self.mgmt_ips()
        ip = mi[0] if mi else mgmt_ip(self.cfg.get("central"))
        return "%s://%s:%d" % (self.ui_scheme, ip, self.ui_port) if ip else ""

    def managed(self):
        """True once the sensor is enrolled with a central console, which then owns the logins."""
        return self.central_ready()

    def central_healthy(self):
        sn = self.sensor
        return bool(sn and sn.pushed_total > 0 and sn.fail == 0)

    def central_login(self, user, pw):
        """Ask central whether user/pw is a console account. -> ('ok', role) | ('denied', msg) | ('down', msg)"""
        c = self.cfg
        url = (c.get("central") or "").rstrip("/") + "/api/sensor-auth"
        ctx = None
        if url.startswith("https"):
            if c.get("insecure"):
                ctx = ssl._create_unverified_context()
            else:
                caf = c.get("cafile") or None
                ctx = ssl.create_default_context(cafile=caf if caf and os.path.exists(caf) else None)
        try:
            req = urllib.request.Request(url, data=json.dumps({"user": user, "password": pw}).encode(), method="POST",
                                         headers={"Content-Type": "application/json", "Authorization": "Bearer " + c["token"]})
            d = json.loads(urllib.request.urlopen(req, timeout=8, context=ctx).read() or b"{}")
            return "ok", d.get("role", "viewer")
        except urllib.error.HTTPError as e:
            try:
                msg = json.loads(e.read() or b"{}").get("error", "")
            except Exception:
                msg = ""
            if e.code == 401 and "token" not in msg:
                return "denied", "wrong username or password"
            if e.code == 429:
                return "denied", msg or "too many failed logins - wait a few minutes"
            return "down", "central answered HTTP %d" % e.code
        except Exception as e:  # noqa
            return "down", str(getattr(e, "reason", e))

    def login(self, user, pw):
        """-> (ok, who, role, error). Central console accounts first; the local setup password only for first setup or when central is down."""
        user = (user or "").strip()
        if user and self.managed():
            st, v = self.central_login(user, pw)
            if st == "ok":
                with self.lock:
                    users = self.cfg.setdefault("users", {})
                    users[user] = {"h": _hash_pw(pw), "role": v}
                    if len(users) > 25:
                        users.pop(next(iter(users)))
                    self.save()
                return True, user, v, ""
            if st == "denied":
                with self.lock:
                    if self.cfg.get("users", {}).pop(user, None) is not None:
                        self.save()
                return False, "", "", v
            cu = self.cfg.get("users", {}).get(user)  # central unreachable: accept a login central accepted earlier
            if cu and _check_pw(pw, cu["h"]):
                return True, user, cu["role"], ""
            return False, "", "", "Central cannot be reached right now (%s) and this login has not been used on this sensor before." % v
        if user and not self.managed():
            return False, "", "", "This sensor is not connected to a central console yet. Leave the username empty and use the setup password."
        # no username: local setup password
        if self.managed() and self.central_healthy():
            return False, "", "", "This sensor is managed by the central console - sign in with your console username and password."
        if _check_pw(pw, self.cfg.get("ui_pw", "")):
            return True, "setup", "admin", ""
        return False, "", "", "wrong password"

    def central_ready(self):
        return bool(self.cfg.get("central") and self.cfg.get("token"))

    # ---------------------------------------------------------------- capture + push control
    def _exclude(self):
        try:
            from urllib.parse import urlparse
            cu = urlparse(self.cfg["central"])
            return (socket.gethostbyname(cu.hostname), cu.port or (443 if cu.scheme == "https" else 80))
        except Exception:
            return None

    def _tap(self, ts, d):
        self.raw.append((ts, d))
        self.last_rx = time.time()

    def start_capture(self):
        with self.lock:
            if self.cap_thread and self.cap_thread.is_alive():
                return
            if not self.configured() or not sys.platform.startswith("linux"):
                return
            iface = self.cfg["iface"]
            if self.an is None:
                self.an = Analyzer(debug=self.debug)
            self.an.source = "live: " + iface
            self.an.exclude = self._exclude()
            self.cap_errs = []
            prepare_nic(iface)
            self.cap_stop = threading.Event()
            self.cap_started = time.time()
            self.manual_stop = False
            self.cap_thread = threading.Thread(target=run_capture, args=(self.an, iface, self.cap_stop, self.cfg.get("bpf") or None,
                                                                          None, self.cap_errs, self._tap), daemon=True)
            self.cap_thread.start()

    def stop_capture(self, manual=False):
        with self.lock:
            if manual:
                self.manual_stop = True
            if self.cap_stop:
                self.cap_stop.set()
            t = self.cap_thread
        if t:
            t.join(3)
        with self.lock:
            self.cap_thread = None

    def start_push(self):
        with self.lock:
            self.stop_push()
            if not self.central_ready() or self.an is None:
                self.sensor = None
                return
            c = self.cfg
            self.sensor = Sensor(self.an, c["site"] or socket.gethostname(), c["central"], c["token"], int(c.get("interval") or 30),
                                 c.get("cafile") or None, bool(c.get("insecure")), c["iface"], "live")
            self.sensor.ui_url = self.ui_url()
            self.sensor.mgmt_iface = c.get("mgmt_iface") or ""
            self.sensor.scan_local = "active" if c.get("scan_mode") == "active" else "passive"
            self.push_stop = threading.Event()
            sn, stop = self.sensor, self.push_stop

            def loop():
                nxt = time.time() + 3
                while not stop.wait(1):
                    if time.time() >= nxt:
                        try:
                            ok = sn.push()
                        except Exception as e:  # noqa
                            sn.fail += 1
                            sn._err("push failed: %s" % e)
                            ok = False
                        nxt = time.time() + (sn.interval if ok else min(300, sn.interval * (2 ** min(sn.fail, 4))))

            self.push_thread = threading.Thread(target=loop, daemon=True)
            self.push_thread.start()

    def stop_push(self):
        with self.lock:
            if self.sensor is not None:
                self.sensor.active.close()      # the old sensor object must not keep scanning in the background
            if self.push_stop:
                self.push_stop.set()
            self.push_stop = self.push_thread = None

    def start_all(self):
        self.start_capture()
        self.start_push()

    # ---------------------------------------------------------------- web page TLS certificate
    def cert_paths(self):
        return os.path.join(self.dir, "custom-cert.pem"), os.path.join(self.dir, "custom-key.pem")

    def build_tls_ctx(self):
        """TLS context for the web page: the uploaded certificate if there is one and it loads, else the self-signed one."""
        tried = []
        cc, ck = self.cert_paths()
        if os.path.exists(cc) and os.path.exists(ck):
            tried.append(("custom", cc, ck))
        else:
            names = [socket.gethostname()] + [i for n in nic_info() for i in n["ips"]]
            crt, key = make_ui_cert(self.dir, names)
            if crt:
                tried.append(("self-signed", crt, key))
        err = ""
        for src, crt, key in tried:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx.load_cert_chain(crt, key)
                self.tls = {"source": src, "crt": crt, "error": ""}
                return ctx
            except (ssl.SSLError, OSError, ValueError) as e:
                err = "the uploaded certificate could not be loaded (%s)" % e
        if tried and tried[0][0] == "custom":  # broken upload: fall back rather than lose the page
            names = [socket.gethostname()] + [i for n in nic_info() for i in n["ips"]]
            crt, key = make_ui_cert(self.dir, names)
            if crt:
                try:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                    ctx.load_cert_chain(crt, key)
                    self.tls = {"source": "self-signed", "crt": crt, "error": err}
                    return ctx
                except (ssl.SSLError, OSError, ValueError):
                    pass
        self.tls = {"source": "none", "error": err}
        return None

    def cert_info(self, host=""):
        t = self.tls
        out = {"source": t.get("source", "none"), "error": t.get("error", ""), "https": t.get("source") in ("custom", "self-signed")}
        if not out["https"]:
            return out
        try:
            with open(t["crt"]) as f:
                chain = _pem_certs(f.read())
            tmp = tempfile.mkdtemp(dir=self.dir)
            try:
                d = _cert_details(chain[0], tmp)
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
            out.update(d)
            out["chain_len"] = len(chain)
            if d["known"]:
                out["days_left"] = int((d["not_after"] - time.time()) // 86400)
                out["names_ok"] = _cert_covers(d, host)
        except Exception as e:  # noqa
            out["error"] = out["error"] or "cannot read the certificate: %s" % e
        return out

    def install_cert(self, cert_text="", key_text="", passphrase="", pfx=b"", host=""):
        """Validate and install an uploaded web certificate; switches the running web server over without a restart.
        Raises ValueError with a plain-English reason when something is wrong. Returns {'warnings': [...]}."""
        if self.tls.get("source") not in ("custom", "self-signed"):
            raise ValueError("the web page is not on HTTPS (openssl is missing), so a private key must not be sent to it - install openssl and restart the sensor")
        tmp = tempfile.mkdtemp(dir=self.dir)
        os.chmod(tmp, 0o700)
        try:
            if pfx:
                cert_text, key_text = _pfx_to_pem(pfx, passphrase, tmp)
            certs = _pem_certs(cert_text)
            if not certs:
                raise ValueError("no certificate found. It must be PEM text starting with -----BEGIN CERTIFICATE----- "
                                 "(a .crt/.pem/.cer file). For a binary (DER) file run: openssl x509 -inform der -in cert.cer -out cert.pem")
            key = _pem_key(key_text) or _pem_key(cert_text)
            if not key:
                raise ValueError("no private key found. Upload the matching .key file (PEM, starting with -----BEGIN PRIVATE KEY-----), or a .pfx bundle")
            key = _decrypt_key(key, passphrase, tmp)
            kf = os.path.join(tmp, "key.pem")
            fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(key)
            # the server certificate is the one whose public key matches the private key; put it first, then the rest as the chain
            chain, last = None, ""
            for i in range(len(certs)):
                order = [certs[i]] + certs[:i] + certs[i + 1:]
                cf = os.path.join(tmp, "chain.pem")
                with open(cf, "w") as fh:
                    fh.write("".join(order))
                try:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ctx.load_cert_chain(cf, kf)
                    chain = order
                    break
                except ssl.SSLError as e:
                    last = str(e)
            if chain is None:
                if "too small" in last or "weak" in last:
                    raise ValueError("the key is too weak for this system (%s) - use at least RSA 2048 / EC P-256" % last)
                raise ValueError("the private key does not match this certificate. Make sure the .crt and the .key are from the same request")
            d = _cert_details(chain[0], tmp)
            warnings = []
            if d["known"]:
                now = time.time()
                if d["not_after"] < now:
                    raise ValueError("this certificate expired on %s" % time.strftime("%Y-%m-%d", time.gmtime(d["not_after"])))
                if d["not_before"] > now + 300:
                    warnings.append("The certificate is not valid until %s. If that date is in the past, the sensor clock is wrong (check NTP)."
                                    % time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(d["not_before"])))
                if d["not_after"] - now < 30 * 86400:
                    warnings.append("The certificate expires in less than 30 days (%s)." % time.strftime("%Y-%m-%d", time.gmtime(d["not_after"])))
                if d["self_signed"]:
                    warnings.append("This is a self-signed certificate: browsers will keep warning until it is trusted on each computer.")
                if host and not _cert_covers(d, host):
                    warnings.append("The certificate does not list the address you are browsing to (%s). Browsers will warn until you open the page "
                                    "with a name or IP that is in the certificate: %s" % (host, ", ".join(v for _, v in d["san"]) or d["cn"] or "none"))
            if len(chain) == 1 and not d.get("self_signed"):
                warnings.append("Only the server certificate was uploaded, without the intermediate (CA) certificates. Some clients cannot verify it; "
                                "paste the full chain if you have it.")
            cc, ck = self.cert_paths()
            # install: key first, then certificate (each replace is atomic)
            for src, dst in ((kf, ck), (os.path.join(tmp, "chain.pem"), cc)):
                os.chmod(src, 0o600)
                os.replace(src, dst)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        self._reload_tls()
        return {"warnings": warnings}

    def reset_cert(self):
        for f in self.cert_paths():
            try:
                os.remove(f)
            except OSError:
                pass
        self._reload_tls()

    def _reload_tls(self):
        if self.on_tls_reload:
            self.on_tls_reload()

    def apply_config(self, new):
        """Apply a validated config dict; restarts only what changed."""
        with self.lock:
            old = dict(self.cfg)
            self.cfg.update(new)
            self.save()
            self._ipc = (0.0, [])
            cap_changed = (old.get("iface") != self.cfg["iface"]) or (old.get("bpf") != self.cfg["bpf"])
            if cap_changed:
                self.stop_capture()
                if old.get("iface") != self.cfg["iface"]:
                    self.an = None
                    self.raw.clear()
            self.start_capture()
            self.start_push()

    def reset_data(self):
        with self.lock:
            self.stop_push()
            if self.an:
                self.an.reset()
                self.an.source = "live: " + self.cfg.get("iface", "")
            self.raw.clear()
            self.start_push()

    def _housekeeping(self):
        while True:
            time.sleep(1)
            try:
                now = time.time()
                an = self.an
                pk, by = (an.pkts, an.bytes) if an else (0, 0)
                t0, p0, b0 = self._prev
                dt = max(now - t0, 0.001)
                self.rate.append((round(max(pk - p0, 0) / dt, 1), round(max(by - b0, 0) / dt)))
                self._prev = (now, pk, by)
                # watchdog: restart a dead capture (NIC unplugged/replugged, transient error)
                t = self.cap_thread
                if self.configured() and not self.manual_stop and (t is None or not t.is_alive()) and now - self.cap_started > 15:
                    self.start_capture()
                    if self.sensor is None and self.central_ready():
                        self.start_push()
            except Exception:
                if self.debug:
                    traceback.print_exc()

    # ---------------------------------------------------------------- views
    def snap(self, max_age=4):
        with self.lock:
            if self.an is None:
                return None
            if time.time() - self._snapc[0] > max_age or self._snapc[1] is None:
                self._snapc = (time.time(), self.an.snapshot())
            return self._snapc[1]

    def status(self):
        now = time.time()
        iface = self.cfg.get("iface")
        nic = next((n for n in nic_info() if n["name"] == iface), None) if iface else None
        t = self.cap_thread
        running = bool(t and t.is_alive())
        an, sn = self.an, self.sensor
        quiet = (now - self.last_rx) if self.last_rx else None
        hints = []
        if not sys.platform.startswith("linux"):
            level, head, det = "red", "Unsupported system", "The sensor appliance needs Linux."
        elif not self.configured():
            level, head, det = "gray", "Not set up yet", "Open the Setup tab and choose the capture port."
            hints.append(("amber", "Step 1: Setup -> choose the network port that receives the mirrored (SPAN) traffic."))
        elif not running and self.manual_stop:
            level, head, det = "gray", "Capture is stopped", "Press Start capture to resume."
        elif not running:
            err = "; ".join(self.cap_errs) or "capture is starting"
            level, head, det = "red", "Capture problem", err
            hints.append(("red", err))
        elif nic is None:
            level, head, det = "red", "Capture port not found", "Network port '%s' does not exist on this device." % iface
            hints.append(("red", "The chosen port '%s' is missing. Pick another port in Setup." % iface))
        elif not nic["carrier"]:
            level, head, det = "red", "Capture port has no link", "No cable / link on %s." % iface
            hints.append(("red", "Check the cable to %s and that the switch port is enabled." % iface))
        elif (an and an.pkts == 0 and now - self.cap_started > 20) or (quiet is not None and quiet > 30):
            level, head, det = "amber", "Running, but no traffic is arriving", "Nothing received on %s for %d seconds." % (
                iface, int(quiet if quiet is not None else now - self.cap_started))
            hints.append(("amber", "On the switch, make sure the mirror (SPAN) DESTINATION is the port this cable goes to. "
                                   "Use the 'Test this port' button in Setup for a diagnosis."))
        else:
            level, head, det = "green", "Running, receiving traffic", "Listening on %s." % iface
        mg = self.cfg.get("mgmt_iface")
        mgnic = next((n for n in nic_info() if n["name"] == mg), None) if mg else None
        if mg and mgnic is None:
            hints.append(("red", "The management port '%s' is missing. Pick another one in Setup." % mg))
        elif mg and not mgnic["carrier"]:
            hints.append(("amber", "The management port %s has no link - check its cable." % mg))
        elif mg and not mgnic["ips"]:
            hints.append(("amber", "The management port %s has no IP address yet, so nobody can open this page on it." % mg))
        if nic and nic["ip"] and (nic["default_route"] or (mg and iface == mg)):
            hints.append(("amber", "%s is also the management port. The sensor sees its own network traffic; use a separate port for the mirror if you can." % iface))
        central = {"configured": self.central_ready(), "url": self.cfg.get("central"), "state": "off", "detail": "Not sending data - this sensor is local-only.",
                   "pending": 0, "sent_total": 0, "last_ok_age": None}
        if self.central_ready():
            if sn is None:
                central.update(state="wait", detail="Starting...")
            else:
                central.update(pending=sn.pending, sent_total=sn.pushed_total,
                               last_ok_age=int(now - sn.last_ok) if sn.last_ok else None)
                if sn._last_err:
                    central.update(state="error", detail=sn._last_err)
                    hints.append(("amber", "Central: " + sn._last_err))
                elif sn.last_ok:
                    central.update(state="ok", detail="Connected. Last data sent %ds ago." % int(now - sn.last_ok))
                else:
                    central.update(state="wait", detail="Waiting for the first push...")
        s = self.snap() if an else None
        sm = s["summary"] if s else {"assets": 0, "ot_assets": 0, "alerts": 0}
        r = list(self.rate)
        return {"level": level, "headline": head, "detail": det, "hints": [{"level": a, "text": b} for a, b in hints],
                "running": running, "manual_stop": self.manual_stop, "iface": iface, "nic": nic, "site": self.cfg.get("site"),
                "mgmt_iface": mg, "mgmt_nic": mgnic, "restrict_ui": bool(self.cfg.get("restrict_ui") and mg),
                "packets": an.pkts if an else 0, "bytes": an.bytes if an else 0,
                "pps": round(sum(x[0] for x in r[-5:]) / max(len(r[-5:]), 1), 1), "bps": round(sum(x[1] for x in r[-5:]) / max(len(r[-5:]), 1)),
                "rate": [x[0] for x in r], "assets": sm["assets"], "ot_assets": sm["ot_assets"], "alerts": sm["alerts"],
                "protocols": [{"p": x["protocol"], "n": x["packets"], "ot": x["ot"]} for x in (s["protocols"][:8] if s else [])],
                "central": central, "uptime": int(now - self.started), "errors": list(self.cap_errs),
                "scan": {"mode": sn.scan_effective() if sn else ("active" if self.cfg.get("scan_mode") == "active" else "passive"),
                         "source": "central" if (sn and sn.scan_central) else "sensor",
                         "devices": (sn.active.result.get("devices", 0) if sn and sn.active.result.get("enabled") else 0)}}

    def live(self, window=60):
        now = time.time()
        agg = {}
        for ts, a, b, proto, func, cat, port, ot in list(self.an.recent) if self.an else []:
            if now - ts > window:
                continue
            k = (a, b, proto, func, cat)
            e = agg.get(k)
            if e is None:
                agg[k] = {"src": a, "dst": b, "proto": proto, "func": func, "cat": cat, "port": port, "ot": ot, "count": 1, "last": ts}
            else:
                e["count"] += 1
                e["last"] = max(e["last"], ts)
        rows = sorted(agg.values(), key=lambda x: -x["last"])[:250]
        for r in rows:
            r["ago"] = round(now - r["last"], 1)
            del r["last"]
        al = []
        s = self.snap(2)
        if s:
            al = [{"severity": a["severity"], "title": a["title"], "src": a["src"], "dst": a["dst"], "last": a["last"]} for a in s["alerts"][:8]]
        return {"rows": rows, "alerts": al, "window": window, "rate": [x[0] for x in self.rate]}

    def devices(self):
        s = self.snap(3)
        if not s:
            return []
        return [{"ip": a["ip"], "mac": a["mac"], "vendor": a["vendor"], "type": a["device_type"], "model": ((a["model"] or "") + (" fw " + a["firmware"] if a["firmware"] else "")).strip(),
                 "protocols": a["ot_protocols"], "risk": a["risk"], "last": a["last_seen"], "hostnames": a["hostnames"]} for a in s["assets"][:2000]]

    def pcap_bytes(self):
        out = io.BytesIO()
        out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, d in list(self.raw):
            out.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(d), len(d)) + d)
        return out.getvalue()

    # ---------------------------------------------------------------- mirror test
    def run_test(self, iface, secs=8):
        with self.lock:
            if self.test.get("state") == "running":
                return
            self.test = {"state": "running", "iface": iface, "started": time.time(), "seconds": secs}
        threading.Thread(target=self._test, args=(iface, secs), daemon=True).start()

    def _test(self, iface, secs):
        res = {"state": "done", "iface": iface, "seconds": secs, "packets": 0, "mirrored": 0, "broadcast": 0, "multicast": 0,
               "to_me": 0, "outgoing": 0, "macs": 0, "protocols": [], "ot_protocols": [], "level": "red", "headline": "", "detail": "", "steps": []}
        try:
            nic = next((n for n in nic_info() if n["name"] == iface), None)
            if nic is None:
                raise RuntimeError("Network port '%s' not found." % iface)
            if not nic["carrier"]:
                res.update(level="red", headline="No link on %s" % iface, detail="The port has no cable / link.",
                           steps=["Plug the cable from the switch's mirror (SPAN) port into %s." % iface, "Check the switch port is enabled and not shut down."])
                self.test = res
                return
            with self.lock:
                if self.cap_thread and self.cap_thread.is_alive() and self.cfg.get("iface") == iface:
                    pass  # fine: AF_PACKET allows several listeners
            prepare_nic(iface)
            tmp = Analyzer()
            macs = set()
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            s.bind((iface, 0))
            try:
                s.setsockopt(263, 1, struct.pack("iHH8s", socket.if_nametoindex(iface), 1, 0, b""))
            except OSError:
                pass
            s.settimeout(0.5)
            end = time.time() + secs
            try:
                while time.time() < end:
                    try:
                        d, addr = s.recvfrom(65535)
                    except socket.timeout:
                        continue
                    pt = addr[2]
                    if pt == 4:
                        res["outgoing"] += 1
                        continue
                    res["packets"] += 1
                    if pt == 3:
                        res["mirrored"] += 1
                    elif pt == 1:
                        res["broadcast"] += 1
                    elif pt == 2:
                        res["multicast"] += 1
                    else:
                        res["to_me"] += 1
                    if len(d) >= 12:
                        macs.add(mac_str(d[6:12]))
                    tmp.process_raw(time.time(), d, 1)
            finally:
                s.close()
            res["macs"] = len(macs)
            sn = tmp.snapshot()
            res["protocols"] = [p["protocol"] for p in sn["protocols"][:8]]
            res["ot_protocols"] = sn["summary"]["ot_protocols"]
            if res["packets"] == 0:
                res.update(level="red", headline="No traffic arrived on %s in %d seconds" % (iface, secs),
                           detail="The port is up but nothing is being received.",
                           steps=["On the switch, set this port as the mirror (SPAN) DESTINATION and pick the source ports/VLAN to copy.",
                                  "Make sure the cable from that switch port goes to %s." % iface,
                                  "If you use a virtual machine: enable promiscuous mode on the virtual switch / port group."])
            elif res["mirrored"] == 0:
                res.update(level="amber", headline="Traffic seen, but it does not look mirrored",
                           detail="Only broadcast/multicast or traffic for this device arrived - no conversations between OTHER devices.",
                           steps=["This often means the port is on a normal switch port, not a mirror (SPAN) destination.",
                                  "Configure the SPAN/mirror session on the switch so other devices' traffic is copied here.",
                                  "If this is a VM, enable promiscuous mode on its virtual network."])
            else:
                res.update(level="green", headline="Mirrored traffic is arriving on %s" % iface,
                           detail="%d packets in %d s from %d devices (%d between other devices). %s" % (
                               res["packets"], secs, res["macs"], res["mirrored"],
                               ("OT protocols seen: " + ", ".join(res["ot_protocols"])) if res["ot_protocols"] else "No OT protocol seen yet - normal if the mirrored VLAN has no OT traffic in these few seconds."),
                           steps=["This port is a good capture port. Choose it and press Save & start."])
        except PermissionError:
            res.update(level="red", headline="Not allowed to listen on the network",
                       detail="The sensor service needs the CAP_NET_RAW permission (the installer sets this).", steps=[])
        except Exception as e:  # noqa
            res.update(level="red", headline="Test failed", detail=str(e), steps=[])
        self.test = res

    # ---------------------------------------------------------------- central connection test
    def test_central(self, c):
        from urllib.parse import urlparse
        url = (c.get("central") or "").strip().rstrip("/")
        tok = c.get("token") or self.cfg.get("token") or ""
        if not url:
            return {"level": "red", "msg": "Enter the central server address, for example https://10.0.0.5:8443"}
        if not re.match(r"^https?://[^/\s]+$", url):
            return {"level": "red", "msg": "The address must look like https://10.0.0.5:8443 (no path)."}
        ctx, tmpca = None, None
        if url.startswith("https"):
            try:
                if c.get("insecure"):
                    ctx = ssl._create_unverified_context()
                else:
                    pem = (c.get("ca_pem") or "").strip()
                    caf = self.cfg.get("cafile") or None
                    if pem:
                        ssl.PEM_cert_to_DER_cert(pem if pem.endswith("\n") else pem + "\n")
                        fd, tmpca = tempfile.mkstemp(suffix=".pem")
                        with os.fdopen(fd, "w") as f:
                            f.write(pem + "\n")
                        caf = tmpca
                    ctx = ssl.create_default_context(cafile=caf if caf and os.path.exists(caf) else None)
            except Exception as e:  # noqa
                return {"level": "red", "msg": "The certificate text is not valid PEM (it should start with -----BEGIN CERTIFICATE-----): %s" % e}
        steps = []
        try:
            r = urllib.request.urlopen(url + "/health", timeout=8, context=ctx)
            ver = json.loads(r.read() or b"{}").get("version", "?")
            steps.append("Reached the central server (version %s)." % ver)
        except urllib.error.URLError as e:
            return {"level": "red", "msg": self._why(e.reason, url), "steps": steps}
        except Exception as e:  # noqa
            return {"level": "red", "msg": self._why(e, url), "steps": steps}
        finally:
            if tmpca:
                try:
                    os.remove(tmpca)
                except OSError:
                    pass
        if not tok:
            return {"level": "amber", "msg": "Central is reachable, but no site token was entered.", "steps": steps}
        body = {"v": 1, "site": c.get("site") or self.cfg.get("site"), "sensor": {"hostname": socket.gethostname(), "version": VERSION, "mode": "test",
                                                                               "iface": self.cfg.get("iface"), "interval": int(c.get("interval") or 30)},
                "assets": [], "flows": [], "alerts": []}
        try:
            if tmpca:  # ctx already built; fine
                pass
            req = urllib.request.Request(url + "/api/ingest", data=gzip.compress(json.dumps(body).encode()), method="POST", headers={
                "Content-Type": "application/json", "Content-Encoding": "gzip", "Authorization": "Bearer " + tok})
            r = urllib.request.urlopen(req, timeout=10, context=ctx)
            d = json.loads(r.read() or b"{}")
            steps.append("Site token accepted.")
            return {"level": "green", "msg": "Connection works. This sensor will appear as site '%s' in the console." % d.get("site", "?"), "steps": steps}
        except urllib.error.HTTPError as e:
            if e.code == 401:
                return {"level": "red", "msg": "Central rejected the token. Copy the token again from Console -> Sites & sensors (or issue a new one).", "steps": steps}
            return {"level": "red", "msg": "Central answered with an error (HTTP %d)." % e.code, "steps": steps}
        except Exception as e:  # noqa
            return {"level": "red", "msg": self._why(getattr(e, "reason", e), url), "steps": steps}

    @staticmethod
    def _why(r, url):
        if isinstance(r, ssl.SSLCertVerificationError):
            return ("The central server's certificate is not trusted. Paste central's cert.pem into the certificate box "
                    "(or, for a lab only, tick 'Don't verify the certificate'). Detail: %s" % getattr(r, "verify_message", r))
        if isinstance(r, ssl.SSLError):
            return "Secure connection failed (%s). Is the address https:// and the port right?" % r
        if isinstance(r, ConnectionRefusedError):
            return "Nothing is listening at %s. Check that central is running, the port is right, and a firewall allows it." % url
        if isinstance(r, socket.gaierror):
            return "The name in the address cannot be found. Use the central server's IP address or a valid DNS name."
        if isinstance(r, (socket.timeout, TimeoutError)):
            return "No answer from %s (timed out). Check the network route and any firewall." % url
        return "Could not connect: %s" % r


def serve_appliance(ap, host, port, no_tls=False):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlparse, parse_qs

    class Srv(ThreadingHTTPServer):
        daemon_threads = True
        ctx = None

        def get_request(self):
            s, a = self.socket.accept()
            try:
                if not ap.ui_access_ok(s.getsockname()[0]):   # web page limited to the management port
                    s.close()
                    raise OSError("not on the management port")
            except OSError:
                try:
                    s.close()
                except OSError:
                    pass
                raise
            if self.ctx:
                s = self.ctx.wrap_socket(s, server_side=True, do_handshake_on_connect=False)
            return s, a

        def handle_error(self, request, client_address):
            if isinstance(sys.exc_info()[1], (OSError, ssl.SSLError)):
                return
            traceback.print_exc()

    class H(BaseHTTPRequestHandler):
        server_version = "OTSenseSensor"
        protocol_version = "HTTP/1.1"
        timeout = 60

        def setup(self):
            if isinstance(self.request, ssl.SSLSocket):
                self.request.settimeout(20)
                self.request.do_handshake()
            BaseHTTPRequestHandler.setup(self)

        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype, headers=None):
            if isinstance(body, str):
                body = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def j(self, obj, code=200, headers=None):
            self._send(code, json.dumps(obj), "application/json", headers)

        def who(self):
            m = re.search(r"(?:^|;\s*)otsb=([^;]+)", self.headers.get("Cookie", ""))
            return ap.cookie_info(m.group(1)) if m else None

        def authed(self):
            return self.who() is not None

        def hostname(self):
            """Name/IP the browser used to reach this page (without the port)."""
            h = (self.headers.get("Host") or "").strip()
            if h.startswith("["):
                return h[1:].split("]")[0]
            return h.rsplit(":", 1)[0] if ":" in h else h

        def body(self, limit=64 * 1024):
            n = int(self.headers.get("Content-Length") or 0)
            if n < 0 or n > limit:
                raise ValueError("body too large")
            d = json.loads(self.rfile.read(n) or b"{}")
            if not isinstance(d, dict):
                raise ValueError("JSON object expected")
            return d

        def do_GET(self):
            u = urlparse(self.path)
            p = {k: v[0] for k, v in parse_qs(u.query).items()}
            try:
                if u.path in ("/", "/index.html"):
                    return self._send(200, APP_PAGE, "text/html; charset=utf-8")
                if u.path == "/health":
                    return self.j({"ok": True, "version": VERSION})
                if u.path == "/api/me":
                    w = self.who()
                    return self.j({"ok": True, "site": ap.cfg.get("site"), "user": w.get("u", "setup"), "role": w.get("r", "admin"),
                                   "managed": ap.managed()} if w else {"anon": True, "managed": ap.managed(), "site": ap.cfg.get("site")})
                if not self.authed():
                    return self.j({"error": "login required"}, 401)
                if u.path == "/api/status":
                    return self.j(ap.status())
                if u.path == "/api/nics":
                    return self.j({"nics": nic_info(), "now": time.time(), "platform_ok": sys.platform.startswith("linux")})
                if u.path == "/api/config":
                    return self.j(ap.public_cfg())
                if u.path == "/api/cert":
                    return self.j(ap.cert_info(self.hostname()))
                if u.path == "/api/live":
                    return self.j(ap.live())
                if u.path == "/api/devices":
                    return self.j(ap.devices())
                if u.path == "/api/test-capture":
                    return self.j(ap.test)
                if u.path == "/api/capture.pcap":
                    return self._send(200, ap.pcap_bytes(), "application/vnd.tcpdump.pcap", {"Content-Disposition": 'attachment; filename="otsense_last_packets.pcap"'})
                return self.j({"error": "not found"}, 404)
            except Exception:
                traceback.print_exc()
                return self.j({"error": "internal error"}, 500)

        def do_POST(self):
            path = urlparse(self.path).path
            try:
                o = self.headers.get("Origin")
                if o and urlparse(o).netloc != self.headers.get("Host"):
                    return self.j({"error": "cross-origin request refused"}, 403)
                b = self.body(768 * 1024 if (path == "/api/cert/upload" and self.authed()) else 64 * 1024)
                if path == "/api/login":
                    ip, now = self.client_address[0], time.time()
                    cnt, first = ap.fails.get(ip, (0, now))
                    if now - first > 300:
                        cnt, first = 0, now
                    if cnt >= 10:
                        return self.j({"error": "too many failed logins - wait a few minutes"}, 429)
                    ok, who, role, err = ap.login(str(b.get("user", "")), str(b.get("password", "")))
                    if not ok:
                        ap.fails[ip] = (cnt + 1, first)
                        time.sleep(0.8)
                        return self.j({"error": err or "login failed"}, 401)
                    ap.fails.pop(ip, None)
                    ck = "otsb=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Strict%s" % (ap.cookie(who, role), 12 * 3600, "; Secure" if self.server.ctx else "")
                    return self.j({"ok": True, "user": who, "role": role}, headers={"Set-Cookie": ck})
                if not self.authed():
                    return self.j({"error": "login required"}, 401)
                if path == "/api/logout":
                    return self.j({"ok": True}, headers={"Set-Cookie": "otsb=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"})
                w = self.who() or {}
                if w.get("r", "admin") != "admin":
                    return self.j({"error": "your console role (%s) is read-only on the sensor - ask an admin to change settings" % w.get("r")}, 403)
                if path == "/api/cert/upload":
                    if not self.server.ctx:
                        return self.j({"error": "this page is on plain http - a private key must not be sent over it. Install openssl and restart the sensor."}, 400)
                    host = self.hostname()
                    pfx = b""
                    if b.get("pfx_b64"):
                        try:
                            pfx = base64.b64decode(str(b["pfx_b64"]), validate=False)
                        except Exception:
                            return self.j({"error": "the .pfx file could not be read"}, 400)
                    try:
                        r = ap.install_cert(str(b.get("cert", "")), str(b.get("key", "")), str(b.get("passphrase", "")), pfx, host)
                    except ValueError as e:
                        return self.j({"error": str(e)}, 400)
                    return self.j(dict(r, ok=True, info=ap.cert_info(host)))
                if path == "/api/cert/reset":
                    ap.reset_cert()
                    return self.j({"ok": True, "info": ap.cert_info(self.hostname())})
                if path == "/api/password":
                    if w.get("u", "setup") != "setup":
                        return self.j({"error": "your password is managed by the central console - change it there"}, 400)
                    if not _check_pw(str(b.get("old", "")), ap.cfg.get("ui_pw", "")):
                        return self.j({"error": "current password is wrong"}, 400)
                    if len(str(b.get("new", ""))) < 8:
                        return self.j({"error": "new password must be at least 8 characters"}, 400)
                    ap.set_password(b["new"])
                    return self.j({"ok": True})
                if path == "/api/config":
                    new = {}
                    iface = str(b.get("iface", "")).strip()
                    if iface and not re.match(r"^[A-Za-z0-9_.:@-]{1,15}$", iface):
                        return self.j({"error": "invalid network port name"}, 400)
                    new["iface"] = iface
                    mg = str(b.get("mgmt_iface", "")).strip()
                    if mg:
                        if not re.match(r"^[A-Za-z0-9_.:@-]{1,15}$", mg):
                            return self.j({"error": "invalid management port name"}, 400)
                        mgn = next((n for n in nic_info() if n["name"] == mg), None)
                        if mgn is None:
                            return self.j({"error": "the management port '%s' does not exist on this device" % mg}, 400)
                        if mg == iface:
                            return self.j({"error": "one port cannot be both the SPAN (capture) port and the management port"}, 400)
                    restrict = bool(b.get("restrict_ui")) and bool(mg)
                    if restrict and not b.get("confirm_lockout"):
                        mips = mgn["ips"]
                        here = self.connection.getsockname()[0]
                        if not mips:
                            return self.j({"error": "the management port %s has no IP address yet. Give it one first (DHCP or static, in the operating system), "
                                                    "otherwise nobody could open this page on it." % mg}, 400)
                        if here not in mips and not here.startswith("127."):
                            return self.j({"error": "You are connected to this page on %s, which is not on port %s (%s). If you restrict the page to %s you will "
                                                    "lose this connection and must reconnect at https://%s:%d" % (here, mg, ", ".join(mips), mg, mips[0], ap.ui_port),
                                           "confirm": True}, 409)
                    new["mgmt_iface"] = mg
                    new["restrict_ui"] = restrict
                    new["site"] = str(b.get("site", "")).strip()[:80] or socket.gethostname()
                    c = str(b.get("central", "")).strip().rstrip("/")
                    if c and not re.match(r"^https?://[^/\s]+$", c):
                        return self.j({"error": "central address must look like https://10.0.0.5:8443"}, 400)
                    new["central"] = c
                    if b.get("token"):
                        new["token"] = str(b["token"]).strip()
                    if b.get("clear_token"):
                        new["token"] = ""
                    new["interval"] = max(5, min(3600, int(b.get("interval") or 30)))
                    new["scan_mode"] = "active" if str(b.get("scan_mode", "")).lower() == "active" else "passive"
                    if new["scan_mode"] != ap.cfg.get("scan_mode", "passive"):
                        new["scan_user"] = True         # chosen on this page: a later install-time default must not undo it
                    new["insecure"] = bool(b.get("insecure"))
                    new["bpf"] = str(b.get("bpf", "")).strip()[:200]
                    pem = str(b.get("ca_pem", "")).strip()
                    if pem:
                        try:
                            ssl.PEM_cert_to_DER_cert(pem + "\n")
                        except Exception:
                            return self.j({"error": "the certificate text is not valid PEM"}, 400)
                        cap = os.path.join(ap.dir, "central-ca.pem")
                        with open(cap, "w") as f:
                            f.write(pem + "\n")
                        new["cafile"] = cap
                    if b.get("clear_ca"):
                        new["cafile"] = ""
                    ap.apply_config(new)
                    return self.j({"ok": True})
                if path == "/api/test-capture":
                    iface = str(b.get("iface", ""))
                    if not re.match(r"^[A-Za-z0-9_.:@-]{1,15}$", iface):
                        return self.j({"error": "invalid port"}, 400)
                    ap.run_test(iface)
                    return self.j({"ok": True})
                if path == "/api/test-central":
                    return self.j(ap.test_central(b))
                if path == "/api/capture/stop":
                    ap.stop_capture(manual=True)
                    return self.j({"ok": True})
                if path == "/api/capture/start":
                    ap.manual_stop = False
                    ap.start_all()
                    return self.j({"ok": True})
                if path == "/api/capture/restart":
                    ap.stop_capture()
                    ap.manual_stop = False
                    ap.start_all()
                    return self.j({"ok": True})
                if path == "/api/reset-data":
                    ap.reset_data()
                    return self.j({"ok": True})
                return self.j({"error": "not found"}, 404)
            except (ValueError, TypeError) as e:
                return self.j({"error": "bad request: %s" % e}, 400)
            except Exception:
                traceback.print_exc()
                return self.j({"error": "internal error"}, 500)

    srv = Srv((host, port), H)
    scheme = "http"

    def reload_tls():
        c = ap.build_tls_ctx()
        if c:
            srv.ctx = c     # new connections use the new certificate; open ones finish on the old one
    ap.on_tls_reload = reload_tls
    if not no_tls:
        ctx = ap.build_tls_ctx()
        if ctx:
            srv.ctx, scheme = ctx, "https"
            if ap.tls.get("source") == "custom":
                print("Web page certificate: uploaded certificate", flush=True)
            if ap.tls.get("error"):
                print("WARNING: %s - using the self-signed certificate instead." % ap.tls["error"], flush=True)
        else:
            print("WARNING: openssl not found - serving the setup page over plain http (password in clear text).", flush=True)
    ap.ui_port, ap.ui_scheme = port, scheme
    if ap.sensor:
        ap.sensor.ui_url = ap.ui_url()
    ips = [n["ip"] for n in nic_info() if n["ip"] and not n["ip"].startswith("127.")]
    print("OTSense sensor web UI: %s://%s:%d" % (scheme, ips[0] if ips else "localhost", port), flush=True)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=srv.shutdown, daemon=True).start())
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    ap.stop_push()
    ap.stop_capture(manual=True)
    srv.server_close()


def run_appliance(args):
    sd = args.state_dir
    try:
        os.makedirs(sd, exist_ok=True)
        if not os.access(sd, os.W_OK):
            raise OSError
    except OSError:
        sd = os.path.join(os.path.expanduser("~"), ".otsense")
        print("State directory not writable, using %s" % sd, flush=True)
    ap = Appliance(sd, args.debug)
    new = {}
    for k in ("site", "central", "token", "iface"):
        v = getattr(args, k, None)
        if v:
            new[k] = v
    if args.interval:
        new["interval"] = args.interval
    if args.insecure:
        new["insecure"] = True
    if args.cafile:
        try:
            shutil.copyfile(args.cafile, os.path.join(sd, "central-ca.pem"))
            new["cafile"] = os.path.join(sd, "central-ca.pem")
        except OSError as e:
            print("Cannot read --cafile: %s" % e, file=sys.stderr)
            return 2
    if getattr(args, "scan", None) and not ap.cfg.get("scan_user"):
        new["scan_mode"] = "active" if args.scan == "active" else "passive"
    if getattr(args, "mgmt_iface", None):
        new["mgmt_iface"] = args.mgmt_iface
    if getattr(args, "restrict_ui", False):
        new["restrict_ui"] = True
    if new.get("restrict_ui") and not (new.get("mgmt_iface") or ap.cfg.get("mgmt_iface")):
        print("--restrict-ui needs --mgmt-iface", file=sys.stderr)
        return 2
    if (new.get("mgmt_iface") or "") and new.get("mgmt_iface") == (new.get("iface") or ap.cfg.get("iface")):
        print("the management port and the capture port must be different", file=sys.stderr)
        return 2
    ap.cfg.update(new)
    if getattr(args, "ui_cert", None):
        try:
            ap.tls = {"source": "self-signed"}      # the installer path: no web server yet, nothing is sent over a network
            with open(args.ui_cert) as f:
                ct = f.read()
            kt = ""
            if args.ui_key:
                with open(args.ui_key) as f:
                    kt = f.read()
            ap.install_cert(ct, kt, args.ui_key_pass or "")
            print("Web page certificate installed from %s" % args.ui_cert)
        except (OSError, ValueError) as e:
            print("Cannot install the web certificate: %s" % e, file=sys.stderr)
            return 2
    shown = None
    if args.ui_password:
        ap.cfg["ui_pw"] = _hash_pw(args.ui_password)
    elif not ap.cfg.get("ui_pw"):
        shown = secrets.token_urlsafe(9)
        ap.cfg["ui_pw"] = _hash_pw(shown)
    ap.save()
    if shown:
        print("=" * 60 + "\nSensor web UI password (shown once): %s\n" % shown + "=" * 60, flush=True)
    if args.configure_only:
        print("Configuration saved to %s" % ap.path)
        return 0
    if not sys.platform.startswith("linux"):
        print("The sensor appliance needs Linux (AF_PACKET).", file=sys.stderr)
    elif ap.configured() and ap.cfg.get("autostart", True):
        ap.start_all()
    serve_appliance(ap, args.ui_host, args.ui_port, args.no_tls)
    return 0


APP_PAGE = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OTSense Sensor</title>
<style>
:root{--bg:#0e1319;--card:#161d26;--line:#263142;--txt:#e7edf4;--mut:#8996a8;--acc:#4da3ff;--ot:#ff9f43;
--green:#4ecb71;--amber:#f5b02e;--red:#ff4d4f;--critical:#ff4d4f;--high:#ff7a45;--medium:#f5b02e;--low:#4ecb71;--info:#69b1ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font:15px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
header{display:flex;align-items:center;gap:14px;padding:12px 18px;border-bottom:1px solid var(--line);flex-wrap:wrap}
h1{font-size:18px;margin:0}h1 span{color:var(--acc)}.mut{color:var(--mut)}
nav{display:flex;gap:4px;padding:0 18px;border-bottom:1px solid var(--line);overflow-x:auto}
nav button{background:none;border:0;color:var(--mut);padding:11px 16px;cursor:pointer;font:inherit;border-bottom:2px solid transparent;white-space:nowrap}
nav button.on{color:var(--txt);border-color:var(--acc)}
main{padding:16px 18px;max-width:1300px;margin:auto}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:14px}
.card h2{font-size:16px;margin:0 0 4px}.card .sub{color:var(--mut);margin-bottom:12px;font-size:14px}
.banner{border-radius:10px;padding:16px 18px;margin-bottom:14px;border:1px solid var(--line);border-left-width:6px}
.banner b{font-size:20px;display:block}.banner.green{border-left-color:var(--green)}.banner.amber{border-left-color:var(--amber)}.banner.red{border-left-color:var(--red)}.banner.gray{border-left-color:#5b6778}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:14px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}.tile b{display:block;font-size:24px}.tile small{color:var(--mut)}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:14px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:middle}
th{color:var(--mut);font-weight:600;white-space:nowrap}.wrap{overflow:auto;max-height:62vh}
.badge{display:inline-block;padding:1px 8px;border-radius:9px;font-size:12px;margin:1px 3px 1px 0;background:#223044;color:#c9d6e6}
.badge.green{background:#173a25;color:var(--green)}.badge.red{background:#4a1d20;color:#ff8486}.badge.amber{background:#4a3414;color:var(--amber)}.badge.ot{background:#4a3414;color:var(--ot)}
.sev{padding:1px 8px;border-radius:4px;font-size:12px;font-weight:600;color:#0e1319;white-space:nowrap}
.sev.critical{background:var(--critical)}.sev.high{background:var(--high)}.sev.medium{background:var(--medium)}.sev.low{background:var(--low)}.sev.info{background:var(--info)}
input[type=text],input[type=password],input[type=number],select,textarea{background:#0e1319;color:var(--txt);border:1px solid var(--line);border-radius:6px;padding:8px 10px;font:inherit;width:100%}
textarea{font-family:ui-monospace,Menlo,monospace;font-size:12px;min-height:90px}
label.f{display:block;margin:10px 0 4px;color:var(--mut);font-size:13px}
button,.btn{background:#223044;color:var(--txt);border:0;border-radius:6px;padding:8px 14px;font:inherit;cursor:pointer;text-decoration:none;display:inline-block}
button.pri{background:var(--acc);color:#04121f;font-weight:600}button.danger{background:#5a2226}button:disabled{opacity:.5;cursor:default}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.row>*{flex:0 0 auto}
.res{margin-top:12px;padding:12px 14px;border-radius:8px;border:1px solid var(--line);border-left-width:5px}
.res.green{border-left-color:var(--green)}.res.amber{border-left-color:var(--amber)}.res.red{border-left-color:var(--red)}
.res ul{margin:6px 0 0;padding-left:20px}
.hint{padding:9px 12px;border-radius:8px;margin-bottom:8px;border:1px solid var(--line)}.hint.amber{background:#3b2a12;border-color:#7a5418;color:#ffd48a}.hint.red{background:#3b1517;border-color:#7a2a2e;color:#ffb3b5}
.overlay{position:fixed;inset:0;background:#000b;display:flex;align-items:center;justify-content:center;z-index:20}
.box{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:22px;width:min(440px,94%)}.box h3{margin:0 0 12px}.box input{margin-bottom:10px}
canvas{width:100%;height:90px;display:block}
.step{display:inline-flex;width:26px;height:26px;border-radius:50%;background:var(--acc);color:#04121f;font-weight:700;align-items:center;justify-content:center;margin-right:8px}
pre,code{background:#0b1016;border:1px solid var(--line);border-radius:6px;padding:2px 6px}pre{padding:10px;overflow:auto}
.nic:hover{background:#1c2633}.nic.sel{background:#1a2b44}select.role{width:auto;min-width:150px}.kv{display:grid;grid-template-columns:150px 1fr;gap:4px 12px;margin-top:10px}.kv div:nth-child(odd){color:var(--mut)}.kv div{word-break:break-all}
details summary{cursor:pointer;color:var(--mut);margin-top:10px}
</style></head><body>
<div id="login" class="overlay" style="display:none"><form class="box" id="lf"><h3><span style="color:var(--acc)">OT</span>Sense Sensor</h3>
<div id="lhint" class="mut" style="margin-bottom:8px"></div><input id="lu" placeholder="Username" autocomplete="username" style="display:none"><input id="lp" type="password" placeholder="Password" autocomplete="current-password" autofocus><div id="le" style="color:var(--red);min-height:20px"></div><button class="pri" type="submit">Sign in</button></form></div>
<header><h1><span>OT</span>Sense <small class="mut">Sensor</small></h1><span id="site" class="mut"></span><span style="flex:1"></span><span id="pill"></span> <a href="#" id="pw" class="mut">password</a> <a href="#" id="lo" class="mut">sign out</a></header>
<nav id="nav"></nav><main id="main"></main><div id="modal"></div>
<script>
'use strict';
const $=id=>document.getElementById(id);
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fb=n=>{if(n<1024)return Math.round(n)+' B';const u=['KB','MB','GB','TB'];let i=-1;do{n/=1024;i++}while(n>=1024&&i<3);return n.toFixed(1)+' '+u[i]};
async function api(path,body){
 const r=await fetch(path,body!==undefined?{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}:{});
 if(r.status===401){showLogin();throw new Error('auth')}
 let j={};try{j=await r.json()}catch(e){}
 if(!r.ok){const e=new Error(j.error||r.statusText);e.confirm=!!j.confirm;throw e}return j}
async function showLogin(){$('login').style.display='flex';
 try{const m=await (await fetch('/api/me')).json();
  $('lu').style.display=m.managed?'':'none';
  $('lhint').textContent=m.managed?'Sign in with your central console username and password.':'First setup: enter the setup password shown by the installer.';
  if(m.managed)$('lu').focus()}catch(e){}}
$('lf').onsubmit=async e=>{e.preventDefault();$('le').textContent='';
 const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user:$('lu').value,password:$('lp').value})});
 if(r.ok){$('lp').value='';$('login').style.display='none';start()}else{let j={};try{j=await r.json()}catch(x){}$('le').textContent=j.error||'Login failed'}};
$('lo').onclick=async e=>{e.preventDefault();await fetch('/api/logout',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});location.reload()};
$('pw').onclick=e=>{e.preventDefault();modal('<h3>Change password</h3><input id="po" type="password" placeholder="Current password"><input id="pn" type="password" placeholder="New password (min 8 characters)"><div id="pe" style="color:var(--red)"></div><button class="pri" id="ps">Change</button>');
 $('ps').onclick=async()=>{try{await api('/api/password',{old:$('po').value,new:$('pn').value});$('modal').innerHTML=''}catch(x){$('pe').textContent=x.message}}};
function modal(h){$('modal').innerHTML='<div class="overlay"><div class="box">'+h+'<div style="text-align:right;margin-top:8px"><button id="mc">Close</button></div></div></div>';$('mc').onclick=()=>$('modal').innerHTML=''}

const TABS=[['status','Status'],['setup','Setup'],['https','HTTPS certificate'],['live','Live traffic'],['devices','Devices found'],['help','Help']];
let tab='status',timer=null,paused=false,otOnly=false,showAll=false,sel='',mg='',lastNames='',lastNics=[],prevRx={},cfg={};
function nav(){$('nav').innerHTML=TABS.map(t=>'<button data-t="'+t[0]+'" class="'+(tab===t[0]?'on':'')+'">'+t[1]+'</button>').join('')}
$('nav').onclick=e=>{const b=e.target.closest('button[data-t]');if(b)go(b.dataset.t)};
function go(t){tab=t;nav();clearInterval(timer);VIEW[t].init();if(VIEW[t].tick){VIEW[t].tick();timer=setInterval(VIEW[t].tick,VIEW[t].every||2000)}}
async function start(){
 const me=await api('/api/me').catch(()=>null);if(!me||me.anon){showLogin();return}
 $('site').textContent=(me.site?'Site: '+me.site+' \u00b7 ':'')+(me.user==='setup'?'setup account':me.user+' ('+me.role+')');
 if(me.user!=='setup')$('pw').style.display='none';
 const st=await api('/api/status');go(st.iface?'status':'setup')}
function spark(el,data,color){
 const c=el,ctx=c.getContext('2d'),dpr=window.devicePixelRatio||1,W=c.clientWidth,H=c.clientHeight;c.width=W*dpr;c.height=H*dpr;ctx.setTransform(dpr,0,0,dpr,0,0);ctx.clearRect(0,0,W,H);
 if(!data.length)return;const mx=Math.max(1,...data);ctx.strokeStyle=color||'#4da3ff';ctx.lineWidth=2;ctx.beginPath();
 data.forEach((v,i)=>{const x=i*(W-2)/Math.max(1,data.length-1)+1,y=H-4-(H-10)*v/mx;i?ctx.lineTo(x,y):ctx.moveTo(x,y)});ctx.stroke();
 ctx.fillStyle='#8996a8';ctx.font='11px system-ui';ctx.fillText('peak '+mx+' pkt/s',4,12)}
const VIEW={};

// ------------------------------------------------------------------ status
VIEW.status={every:2000,init(){
 $('main').innerHTML='<div id="banner"></div><div id="hints"></div><div class="tiles" id="tiles"></div><div class="grid2"><div class="card"><h2>Traffic received</h2><div class="sub">packets per second, last 3 minutes</div><canvas id="spark"></canvas></div><div class="card" id="proto"></div></div><div class="grid2"><div class="card" id="central"></div><div class="card" id="capture"></div><div class="card" id="mgmtc"></div></div>'},
 async tick(){
  const s=await api('/api/status');
  $('pill').innerHTML='<span class="badge '+(s.level==='gray'?'':s.level)+'">'+esc(s.headline)+'</span>';
  $('banner').innerHTML='<div class="banner '+s.level+'"><b>'+esc(s.headline)+'</b>'+esc(s.detail)+'</div>';
  $('hints').innerHTML=s.hints.map(h=>'<div class="hint '+h.level+'">'+esc(h.text)+'</div>').join('');
  $('tiles').innerHTML=[['Packets / second',s.pps],['Throughput',fb(s.bps)+'/s'],['Packets seen',s.packets.toLocaleString()],['Devices found',s.assets],['OT devices',s.ot_assets],['Alerts',s.alerts]].map(x=>'<div class="tile"><small>'+x[0]+'</small><b>'+x[1]+'</b></div>').join('');
  spark($('spark'),s.rate,s.level==='green'?'#4ecb71':'#f5b02e');
  $('proto').innerHTML='<h2>What is on the wire</h2><div class="sub">protocols seen so far</div>'+(s.protocols.length?s.protocols.map(p=>'<span class="badge'+(p.ot?' ot':'')+'">'+esc(p.p)+' '+p.n.toLocaleString()+'</span>').join(''):'<span class="mut">Nothing yet.</span>');
  const c=s.central,cb={ok:'green',error:'red',wait:'amber',off:''}[c.state];
  $('central').innerHTML='<h2>Connection to central</h2><div class="sub">'+esc(c.url||'not configured')+'</div><span class="badge '+cb+'">'+({ok:'Connected',error:'Problem',wait:'Starting',off:'Local only'}[c.state])+'</span> '+esc(c.detail)+(c.configured?'<div class="mut" style="margin-top:8px">Items sent: '+c.sent_total.toLocaleString()+(c.pending?' &middot; waiting to be sent: '+c.pending:'')+'</div>':'');
  const mn=s.mgmt_nic;
  $('mgmtc').innerHTML='<h2>Management port</h2><div class="sub">'+(s.mgmt_iface?esc(s.mgmt_iface):'not chosen')+'</div>'+(mn?'<span class="badge '+(mn.carrier?'green':'red')+'">'+(mn.carrier?'link up'+(mn.speed?' '+mn.speed+' Mb/s':''):'no link')+'</span>'+(mn.ips.length?mn.ips.map(i=>'<span class="badge">'+esc(i)+'</span>').join(''):'<span class="badge amber">no IP address</span>')+'<div class="mut" style="margin-top:8px">'+(s.restrict_ui?'This web page answers only on this port.':'This web page answers on every port that has an IP address.')+'</div>':'<div class="mut">Choose one in Setup.</div>');
  const n=s.nic;
  $('capture').innerHTML='<h2>Capture port</h2><div class="sub">'+(s.iface?esc(s.iface):'not chosen')+'</div>'+(n?'<span class="badge '+(n.carrier?'green':'red')+'">'+(n.carrier?'link up'+(n.speed?' '+n.speed+' Mb/s':''):'no link')+'</span><span class="badge">'+(n.promisc?'promiscuous on':'promiscuous off')+'</span><span class="badge">'+esc(n.mac||'')+'</span>':'')+
   '<div class="row" style="margin-top:12px">'+(s.running?'<button data-a="stop">Stop capture</button><button data-a="restart">Restart</button>':(s.iface?'<button class="pri" data-a="start">Start capture</button>':''))+'<button class="danger" data-a="reset">Clear collected devices</button></div>'}};
document.addEventListener('click',async e=>{const b=e.target.closest('button[data-a]');if(!b)return;const a=b.dataset.a;
 if(a==='reset'&&!confirm('Clear all devices and alerts collected so far on this sensor? (Data already sent to central stays there.)'))return;
 const m={start:'/api/capture/start',stop:'/api/capture/stop',restart:'/api/capture/restart',reset:'/api/reset-data'}[a];await api(m,{});VIEW.status.tick()});

// ------------------------------------------------------------------ setup
VIEW.setup={every:2000,async init(){
 cfg=await api('/api/config');sel=sel||cfg.iface||'';mg=mg||cfg.mgmt_iface||'';
 $('main').innerHTML='<div class="card"><h2><span class="step">1</span>Network ports</h2><div class="sub">Every network port found on this device is listed - a port you plug in later appears here by itself. Give each port a role: <b>SPAN / capture</b> receives the mirrored traffic from your switch (no IP address needed; one per sensor). <b>Management</b> is the port you use to reach this page and central.</div><div class="wrap"><table><thead><tr><th>Port</th><th>Link</th><th>Address</th><th>Receiving now</th><th>Detected</th><th>Role</th></tr></thead><tbody id="nics"></tbody></table></div><label class="f"><input type="checkbox" id="showall"> show virtual / other interfaces</label><div class="row" style="margin-top:10px"><button id="suggest">Use suggested roles</button></div><label class="f"><input type="checkbox" id="c_restrict"> Only answer this web page on the management port (it must have an IP address)</label><div class="row" style="margin-top:10px"><button id="testcap" class="pri">Test the SPAN port (8 seconds)</button><span class="mut" id="testnote"></span></div><div id="testres"></div></div>'+
  '<div class="card"><h2><span class="step">2</span>Central server <span class="mut" style="font-size:13px;font-weight:400">(optional)</span></h2><div class="sub">Where this sensor sends what it finds. Leave empty to use the sensor on its own.</div>'+
  '<label class="f">Site name (as shown in the console)</label><input type="text" id="c_site" value="'+esc(cfg.site)+'">'+
  '<label class="f">Central server address</label><input type="text" id="c_central" placeholder="https://10.0.0.5:8443" value="'+esc(cfg.central)+'">'+
  '<label class="f">Site token'+(cfg.has_token?' <span class="badge green">saved</span>':'')+'</label><input type="password" id="c_token" placeholder="'+(cfg.has_token?'leave empty to keep the saved token':'paste the token from the console (Sites & sensors)')+'" autocomplete="off">'+
  '<label class="f">Central server certificate'+(cfg.has_ca?' <span class="badge green">saved</span>':'')+'</label><textarea id="c_ca" placeholder="Paste the contents of central\'s cert.pem here (needed when central uses its own certificate). Leave empty to keep the saved one."></textarea>'+
  '<label class="f"><input type="checkbox" id="c_insecure"'+(cfg.insecure?' checked':'')+'> Don\'t verify the certificate (lab only - not secure)</label>'+
  '<label class="f">Send updates every</label><select id="c_int">'+[15,30,60,120].map(v=>'<option value="'+v+'"'+(cfg.interval==v?' selected':'')+'>'+v+' seconds</option>').join('')+'</select>'+
  '<label class="f">Scanning</label><select id="c_scan"><option value="passive"'+(cfg.scan_mode!=='active'?' selected':'')+'>Passive - only listen (recommended for OT)</option><option value="active"'+(cfg.scan_mode==='active'?' selected':'')+'>Active - also ask every device on this sensor\'s own network if it is there</option></select>'+
  (cfg.scan_central?'<div class="mut" style="margin-top:6px">Central currently controls this: <b>'+esc(cfg.scan_central)+'</b>. Your choice here applies only if central is set back to "sensor decides".</div>':'<div class="mut" style="margin-top:6px">Active sends packets (ARP / short TCP connects) on the management network. Passive sends nothing. Central can also change this per site.</div>')+
  '<div class="row" style="margin-top:12px"><button id="testcen">Test connection</button></div><div id="cenres"></div></div>'+
  '<div class="card"><h2><span class="step">3</span>Save &amp; start</h2><div class="row"><button class="pri" id="save">Save &amp; start</button><span id="saveres"></span></div><details><summary>Advanced</summary><label class="f">Capture filter (BPF, optional - e.g. <code>not port 22</code>)</label><input type="text" id="c_bpf" value="'+esc(cfg.bpf)+'"></details></div>';
 $('showall').checked=showAll;$('showall').onchange=e=>{showAll=e.target.checked;VIEW.setup.draw(lastNics)};
 $('c_restrict').checked=!!cfg.restrict_ui;$('suggest').onclick=suggestRoles;
 $('testcap').onclick=runTest;$('testcen').onclick=testCentral;$('save').onclick=save;
 const r=await api('/api/nics');lastNics=r.nics;if(!cfg.iface&&!cfg.mgmt_iface&&!sel&&!mg)suggestRoles();else VIEW.setup.draw(r.nics);
 if(!r.platform_ok)$('testnote').textContent='The sensor appliance needs Linux.'},
 draw(nics){
  const rows=nics.filter(n=>showAll||!n.virtual||n.name===sel||n.name===mg).map(n=>{
   let d='';
   if(n.bus)d+='<span class="badge">'+n.bus.toUpperCase()+'</span>';
   if(n.kind&&n.kind!=='physical')d+='<span class="badge">'+esc(n.kind)+'</span>';
   if(n.driver)d+='<span class="badge">'+esc(n.driver)+'</span>';
   if(n.default_route)d+='<span class="badge amber">default route - looks like management</span>';
   else if(!n.virtual&&n.carrier&&!n.ip)d+='<span class="badge green">no IP - likely SPAN port</span>';
   const role=sel===n.name?'span':mg===n.name?'mgmt':'';
   const warn=(role==='span'&&n.ip)?'<div class="mut" style="color:var(--amber)">has an IP address - a SPAN port should have none</div>':'';
   return '<tr class="nic'+(role?' sel':'')+'" data-n="'+esc(n.name)+'"><td><b>'+esc(n.name)+'</b><br><span class="mut">'+esc(n.mac||'')+(n.wireless?' &middot; wifi':'')+'</span></td><td><span class="badge '+(n.carrier?'green':'red')+'" data-link="'+esc(n.name)+'">'+(n.carrier?'link up'+(n.speed?' '+n.speed+'M'+(n.duplex?' '+n.duplex:''):''):'no link')+'</span></td><td>'+(n.ips&&n.ips.length?n.ips.map(esc).join('<br>'):'<span class="mut">no IP</span>')+'</td><td data-rx="'+esc(n.name)+'">-</td><td>'+d+'</td><td><select class="role" data-n="'+esc(n.name)+'"><option value=""'+(role===''?' selected':'')+'>Not used</option><option value="span"'+(role==='span'?' selected':'')+'>SPAN / capture</option><option value="mgmt"'+(role==='mgmt'?' selected':'')+'>Management</option></select>'+warn+'</td></tr>'}).join('');
  lastNames=nics.map(n=>n.name).join();
  if(!$('nics'))return;
  $('nics').innerHTML=rows||'<tr><td colspan="6" class="mut">No network ports found (tick "show virtual" to see all).</td></tr>'},
 async tick(){
  const r=await api('/api/nics');lastNics=r.nics;
  if(tab!=='setup'||!$('nics'))return;
  if(r.nics.map(n=>n.name).join()!==lastNames){VIEW.setup.draw(r.nics);return}
  r.nics.forEach(n=>{const p=prevRx[n.name];const el=document.querySelector('[data-rx="'+n.name+'"]');
   if(el&&p){const dt=Math.max(r.now-p.t,.5);el.textContent=Math.round((n.rx_packets-p.p)/dt)+' pkt/s'}
   prevRx[n.name]={t:r.now,p:n.rx_packets};
   const lk=document.querySelector('[data-link="'+n.name+'"]');if(lk){lk.className='badge '+(n.carrier?'green':'red');lk.textContent=n.carrier?'link up'+(n.speed?' '+n.speed+'M':''):'no link'}})}};
document.addEventListener('change',e=>{const el=e.target.closest('select.role');if(!el)return;const n=el.dataset.n,v=el.value;
 if(sel===n)sel='';if(mg===n)mg='';if(v==='span')sel=n;if(v==='mgmt')mg=n;VIEW.setup.draw(lastNics)});
function suggestRoles(){const c=lastNics.filter(n=>!n.virtual);
 const m=c.find(n=>n.default_route)||c.find(n=>n.ip&&n.carrier);
 const sp=c.find(n=>n!==m&&!n.ip&&n.carrier)||c.find(n=>n!==m&&!n.ip);
 mg=m?m.name:'';sel=sp?sp.name:'';VIEW.setup.draw(lastNics)}
async function runTest(){
 if(!sel){$('testnote').textContent='Give a port the SPAN / capture role first.';return}
 $('testcap').disabled=true;$('testres').innerHTML='<div class="res amber">Listening on '+esc(sel)+' for 8 seconds...</div>';
 await api('/api/test-capture',{iface:sel});
 const poll=async()=>{const t=await api('/api/test-capture');
  if(t.state==='running'){setTimeout(poll,1000);return}
  $('testcap').disabled=false;
  $('testres').innerHTML='<div class="res '+t.level+'"><b>'+esc(t.headline)+'</b><div>'+esc(t.detail)+'</div>'+(t.packets?'<div class="mut" style="margin-top:6px">'+t.packets+' packets &middot; '+t.mirrored+' between other devices &middot; '+t.broadcast+' broadcast &middot; '+t.multicast+' multicast &middot; '+t.macs+' devices'+(t.protocols.length?' &middot; '+esc(t.protocols.join(', ')):'')+'</div>':'')+(t.steps&&t.steps.length?'<ul>'+t.steps.map(x=>'<li>'+esc(x)+'</li>').join('')+'</ul>':'')+'</div>'};
 setTimeout(poll,1500)}
async function testCentral(){
 $('testcen').disabled=true;$('cenres').innerHTML='<div class="res amber">Testing...</div>';
 try{const r=await api('/api/test-central',{central:$('c_central').value,token:$('c_token').value,ca_pem:$('c_ca').value,insecure:$('c_insecure').checked,site:$('c_site').value,interval:$('c_int').value});
  $('cenres').innerHTML='<div class="res '+r.level+'"><b>'+esc(r.msg)+'</b>'+(r.steps&&r.steps.length?'<ul>'+r.steps.map(x=>'<li>'+esc(x)+'</li>').join('')+'</ul>':'')+'</div>'}
 catch(e){$('cenres').innerHTML='<div class="res red">'+esc(e.message)+'</div>'}
 $('testcen').disabled=false}
async function save(){
 const b={iface:sel,mgmt_iface:mg,restrict_ui:$('c_restrict').checked,site:$('c_site').value,central:$('c_central').value,token:$('c_token').value,ca_pem:$('c_ca').value,insecure:$('c_insecure').checked,interval:$('c_int').value,scan_mode:$('c_scan').value,bpf:$('c_bpf').value};
 if(!sel){$('saveres').innerHTML='<span style="color:var(--amber)">Give one port the SPAN / capture role in step 1 first.</span>';return}
 try{
  try{await api('/api/config',b)}
  catch(e){if(!e.confirm)throw e;
   if(!confirm(e.message+'\n\nContinue?')){$('saveres').innerHTML='<span class="mut">Not saved.</span>';return}
   b.confirm_lockout=true;await api('/api/config',b)}
  $('saveres').innerHTML='<span style="color:var(--green)">Saved. The sensor is running - opening Status...</span>';setTimeout(()=>go('status'),1200)}
 catch(e){$('saveres').innerHTML='<span style="color:var(--red)">'+esc(e.message)+'</span>'}}

// ------------------------------------------------------------------ HTTPS certificate
let pfxB64='';
const readFile=(f,mode)=>new Promise((ok,no)=>{const r=new FileReader();r.onload=()=>ok(r.result);r.onerror=()=>no(r.error);mode==='b64'?r.readAsArrayBuffer(f):r.readAsText(f)});
const b64=buf=>{let s='';const u=new Uint8Array(buf);for(let i=0;i<u.length;i+=32768)s+=String.fromCharCode.apply(null,u.subarray(i,i+32768));return btoa(s)};
const day=t=>new Date(t*1000).toISOString().slice(0,10);
function certCard(c){
 if(!c.https)return `<h2>Web page certificate</h2><div class="res red"><b>This page is on plain http</b><div>${esc(c.error||'openssl is not installed on the sensor, so no certificate is in use.')} Install openssl and restart the sensor (<code>apt install openssl</code>).</div></div>`;
 const src=c.source==='custom'?'<span class="badge green">your uploaded certificate</span>':'<span class="badge amber">built-in self-signed certificate</span>';
 let h=`<h2>Web page certificate</h2><div class="sub">Used for https://&lt;this sensor&gt;</div>${src}`;
 if(c.error)h+=`<div class="res amber">${esc(c.error)}</div>`;
 if(c.known){
  h+=(c.days_left<0?'<span class="badge red">expired</span>':c.days_left<30?`<span class="badge amber">expires in ${c.days_left} days</span>`:`<span class="badge green">valid, ${c.days_left} days left</span>`);
  h+=(c.names_ok?`<span class="badge green">covers ${esc(location.hostname)}</span>`:`<span class="badge amber">does not list ${esc(location.hostname)}</span>`);
  h+=`<div class="kv"><div>Subject</div><div>${esc(c.subject)}</div><div>Issued by</div><div>${esc(c.issuer)}${c.self_signed?' (self-signed)':''}</div><div>Valid</div><div>${day(c.not_before)} to ${day(c.not_after)}</div><div>Names</div><div>${c.san.length?c.san.map(x=>esc(x[1])).join(', '):'<span class="mut">none listed (common name only)</span>'}</div><div>Certificates sent</div><div>${c.chain_len}${c.chain_len===1&&!c.self_signed?' <span class="mut">(server certificate only, no intermediates)</span>':''}</div><div>SHA-256</div><div><code>${esc(c.sha256)}</code></div></div>`}
 return h}
async function drawCert(){$('cinfo').innerHTML=certCard(await api('/api/cert'))}
VIEW.https={init(){
 pfxB64='';
 $('main').innerHTML=`<div class="card" id="cinfo"></div><div class="card"><h2>Upload your certificate</h2><div class="sub">The sensor web page switches to it immediately - no restart. Use the files from your certificate authority or IT team. The private key stays on the sensor and is never shown again.</div><div class="grid2"><div><label class="f">Certificate (.crt / .pem / .cer). Put the intermediate certificates in the same file if you have them.</label><input type="file" id="f_cert"><textarea id="t_cert" placeholder="-----BEGIN CERTIFICATE-----"></textarea></div><div><label class="f">Private key (.key / .pem)</label><input type="file" id="f_key"><textarea id="t_key" placeholder="-----BEGIN PRIVATE KEY-----"></textarea></div></div><label class="f">Passphrase (only if the key or the .pfx has one)</label><input type="password" id="t_pass" autocomplete="off"><details><summary>I have one .pfx / .p12 file instead</summary><label class="f">PKCS#12 bundle (certificate + key in one file)</label><input type="file" id="f_pfx"></details><div class="row" style="margin-top:12px"><button class="pri" id="cup">Upload &amp; apply</button><button class="danger" id="crs">Go back to the built-in self-signed certificate</button></div><div id="cres"></div></div>`;
 $('f_cert').onchange=async e=>{if(e.target.files[0])$('t_cert').value=await readFile(e.target.files[0])};
 $('f_key').onchange=async e=>{if(e.target.files[0])$('t_key').value=await readFile(e.target.files[0])};
 $('f_pfx').onchange=async e=>{pfxB64=e.target.files[0]?b64(await readFile(e.target.files[0],'b64')):''};
 $('cup').onclick=async()=>{
  const body={cert:$('t_cert').value,key:$('t_key').value,passphrase:$('t_pass').value,pfx_b64:pfxB64};
  if(!pfxB64&&!body.cert.trim()){$('cres').innerHTML='<div class="res amber">Choose the certificate file (and the key file) first.</div>';return}
  $('cup').disabled=true;$('cres').innerHTML='<div class="res amber">Checking and installing...</div>';
  try{const r=await api('/api/cert/upload',body);
   $('t_cert').value=$('t_key').value=$('t_pass').value='';pfxB64='';$('f_cert').value=$('f_key').value=$('f_pfx').value='';
   $('cres').innerHTML='<div class="res '+(r.warnings.length?'amber':'green')+'"><b>Certificate installed.</b> New connections already use it. <button id="rl">Reload this page</button>'+(r.warnings.length?'<ul>'+r.warnings.map(w=>'<li>'+esc(w)+'</li>').join('')+'</ul>':'')+'</div>';
   $('rl').onclick=()=>location.reload();$('cinfo').innerHTML=certCard(r.info)}
  catch(e){$('cres').innerHTML='<div class="res red">'+esc(e.message)+'</div>'}
  $('cup').disabled=false};
 $('crs').onclick=async()=>{if(!confirm('Go back to the built-in self-signed certificate? Browsers will show a warning again.'))return;
  try{const r=await api('/api/cert/reset',{});$('cres').innerHTML='<div class="res green">Back on the self-signed certificate. <button id="rl">Reload this page</button></div>';$('rl').onclick=()=>location.reload();$('cinfo').innerHTML=certCard(r.info)}
  catch(e){$('cres').innerHTML='<div class="res red">'+esc(e.message)+'</div>'}};
 drawCert()}};

// ------------------------------------------------------------------ live traffic
const CATSEV={stop:'critical',program:'high',control:'high',write:'medium',upload:'medium',discover:'low'};
VIEW.live={every:2000,init(){
 $('main').innerHTML='<div class="card"><div class="row"><button id="pause">Pause</button><label class="mut"><input type="checkbox" id="otonly"> OT protocols only</label><a class="btn" href="/api/capture.pcap">Download last packets (.pcap for Wireshark)</a><span class="mut">Decoded conversations from the last 60 seconds. Commands that change a controller are highlighted.</span></div></div><div class="card"><canvas id="lspark"></canvas></div><div class="card wrap" id="lt"></div><div class="card" id="la"></div>';
 $('pause').onclick=()=>{paused=!paused;$('pause').textContent=paused?'Resume':'Pause'};$('otonly').checked=otOnly;$('otonly').onchange=e=>{otOnly=e.target.checked}},
 async tick(){if(paused)return;const d=await api('/api/live');
  spark($('lspark'),d.rate);
  const rows=d.rows.filter(r=>!otOnly||r.ot);
  $('lt').innerHTML='<table><tr><th>Seen</th><th>From</th><th>To</th><th>Protocol</th><th>Action</th><th>Type</th><th>Count</th></tr>'+(rows.map(r=>'<tr><td class="mut">'+r.ago+' s ago</td><td>'+esc(r.src)+'</td><td>'+esc(r.dst)+'</td><td>'+esc(r.proto)+(r.ot?' <span class="badge ot">OT</span>':'')+'</td><td>'+esc(r.func||'')+'</td><td>'+(CATSEV[r.cat]?'<span class="sev '+CATSEV[r.cat]+'">'+esc(r.cat)+'</span>':'<span class="mut">'+esc(r.cat||'')+'</span>')+'</td><td>'+r.count+'</td></tr>').join('')||'<tr><td colspan="7" class="mut">No conversations in the last minute.</td></tr>')+'</table>';
  $('la').innerHTML='<h2 style="font-size:15px;margin:0 0 8px">Latest alerts</h2>'+(d.alerts.length?d.alerts.map(a=>'<div style="margin:4px 0"><span class="sev '+a.severity+'">'+a.severity+'</span> '+esc(a.title)+' <span class="mut">'+esc(a.src)+' &rarr; '+esc(a.dst)+'</span></div>').join(''):'<span class="mut">No alerts.</span>')}};

// ------------------------------------------------------------------ devices
let devQ='';
VIEW.devices={every:5000,init(){
 $('main').innerHTML='<div class="card"><input type="text" id="dq" placeholder="Filter devices (IP, MAC, vendor, type, protocol...)" value="'+esc(devQ)+'"></div><div class="card wrap" id="dt"></div>';
 $('dq').oninput=e=>{devQ=e.target.value;VIEW.devices.tick()}},
 async tick(){const d=await api('/api/devices'),q=devQ.toLowerCase();
  const rows=d.filter(x=>!q||JSON.stringify(x).toLowerCase().includes(q));
  $('dt').innerHTML='<table><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Type</th><th>Model / firmware</th><th>OT protocols</th><th>Risk</th><th>Last seen</th></tr>'+(rows.map(x=>'<tr><td>'+esc(x.ip||'-')+'</td><td>'+esc(x.mac||'-')+'</td><td>'+esc(x.vendor||'-')+'</td><td>'+esc(x.type)+'</td><td>'+esc(x.model)+(x.hostnames.length?'<br><span class="mut">'+esc(x.hostnames.join(', '))+'</span>':'')+'</td><td>'+x.protocols.map(p=>'<span class="badge ot">'+esc(p)+'</span>').join('')+'</td><td>'+x.risk+'</td><td class="mut">'+esc(x.last)+'</td></tr>').join('')||'<tr><td colspan="8" class="mut">No devices yet.</td></tr>')+'</table>'}};

// ------------------------------------------------------------------ help
VIEW.help={init(){$('main').innerHTML='<div class="card"><h2>How this sensor works</h2><p>It only <b>listens</b>. It needs a copy of your plant network traffic, delivered to one network port. It never sends anything to your controllers. What it finds is sent to the central console.</p><p><b>Two network ports</b> are normal: one receives the mirrored traffic (role <b>SPAN / capture</b>, no IP address), the other is the <b>management</b> port used to open this page and to reach central. Set both in <b>Setup</b>. Use the <b>HTTPS certificate</b> tab to install your own certificate for this page.</p></div>'+
 '<div class="card"><h2>Setting up the mirror (SPAN) on the switch</h2><p>This is configured on the <b>switch</b>, not here. Copy the traffic you want to watch to the port where this sensor is plugged in. Example (Cisco IOS - other vendors have the same idea, see your switch manual):</p><pre>monitor session 1 source interface Gi1/0/1 - 8 both\nmonitor session 1 destination interface Gi1/0/24</pre><p>Gi1/0/24 is the port connected to this sensor. A passive network TAP works too. For a virtual machine, enable <b>promiscuous mode</b> on the virtual switch / port group.</p></div>'+
 '<div class="card"><h2>If no traffic arrives</h2><ul><li>Is the cable plugged into the switch\'s <b>mirror destination</b> port (not a normal port)?</li><li>Does the port show "link up" in Setup? If not, check the cable and that the switch port is not shut down.</li><li>Press <b>Test this port</b> in Setup - it explains what it sees and what to check.</li><li>Is the mirror session copying the right ports or VLANs?</li></ul></div>'+
 '<div class="card"><h2>If central cannot be reached</h2><ul><li>Use <b>Test connection</b> in Setup. The message says whether the address, certificate or token is wrong.</li><li>Central must be reachable on its HTTPS port (default 8443) from this sensor\'s <b>management</b> port.</li><li>While central is unreachable, the sensor keeps collecting and sends everything when the connection returns.</li></ul></div>'}};
nav();start();
</script></body></html>'''

# ----------------------------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------------------------


def _load_baseline(p):
    if not p:
        return None
    try:
        with open(p) as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        print("Baseline not loaded (%s) - continuing without it" % e, file=sys.stderr)
        return None


def _app_dir():
    return os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))


def _read_conf(path):
    c = {"SCAN": "passive", "UI_PORT": "8099", "INTERVAL": "30"}
    with open(path, encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            v = v.strip()
            if len(v) >= 2 and v[0] in "'\"" and v[-1] == v[0]:
                v = v[1:-1]
            c[k.strip().upper()] = v
    return c


def _startup_cmd():
    return os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "OTSense-Sensor.cmd")


def run_winapp(av):
    """The Windows app (OTSense-Sensor.exe, built with PyInstaller - Python, scapy and this script are all inside the one file).
    Reads sensor.conf (written by central) from the folder of the exe.   OTSense-Sensor.exe [run | service | install | uninstall | ifaces]"""
    d = _app_dir()
    sub = (av[0].lower() if av else "run")
    interactive = sub != "service"
    exe = sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__)

    def pause():
        if interactive and sys.stdin and sys.stdin.isatty():
            try:
                input("\nPress Enter to close this window...")
            except EOFError:
                pass

    if sub == "ifaces":
        for i in list_ifaces():
            print("%-30s %-16s %s" % (i["name"], i["ip"], i["state"]))
        pause()
        return 0
    if sub == "uninstall":
        try:
            os.remove(_startup_cmd())
            print("Removed the automatic start.")
        except OSError:
            print("There was no automatic start to remove.")
        pause()
        return 0
    if sub == "install":
        cmd = '@echo off\r\ncd /d "%s"\r\nstart "" /min "%s" service\r\n' % (d, exe)
        try:
            with open(_startup_cmd(), "w") as f:
                f.write(cmd)
            print("Done: the sensor now starts whenever you sign in to Windows (minimised; log: %s)." % os.path.join(d, "otsense-sensor.log"))
        except OSError as e:
            print("Cannot write the startup entry: %s" % e)
        pause()
        return 0
    if sub == "service":
        lp = os.path.join(d, "otsense-sensor.log")
        try:
            if os.path.getsize(lp) > 5 << 20:
                os.replace(lp, lp + ".1")
        except OSError:
            pass
        sys.stdout = sys.stderr = open(lp, "a", buffering=1, encoding="utf-8")
    try:
        c = _read_conf(os.path.join(d, "sensor.conf"))
        for k in ("SITE", "CENTRAL", "TOKEN"):
            if not c.get(k):
                raise KeyError(k)
    except (OSError, KeyError) as e:
        print("sensor.conf is missing or incomplete (%s) in %s. Download the sensor again from central (Sites > Build a sensor > Windows)." % (e, d))
        pause()
        return 2
    ca = os.path.join(d, "ca.crt")
    port = int(c.get("UI_PORT") or 0)
    ns = argparse.Namespace(site=c["SITE"], central=c["CENTRAL"].rstrip("/"), token=c["TOKEN"], iface=c.get("IFACE") or "any",
                            interval=int(c.get("INTERVAL") or 30), cafile=ca if os.path.exists(ca) else None, insecure=False, bpf=None,
                            baseline=None, pcap=None, keep_alive=False, debug=False, scan="active" if c.get("SCAN") == "active" else "passive",
                            ui_port=port, ui_host="127.0.0.1", state_file=os.path.join(d, "sensor-state.json"), no_capture=False)
    if os.name == "nt" and not npcap_present():
        print("Npcap not installed: using Windows' built-in listening (IP traffic only, no MAC/ARP/PROFINET-DCP; run as Administrator). "
              "This is fine for trials; use the Linux sensor for full detail.")
    if c.get("SURVEY_MIN"):
        return run_survey(ns, c, d, interactive, pause)
    print("OT Sense sensor for site '%s' -> %s   scanning: %s" % (ns.site, ns.central, ns.scan))
    if interactive and port:
        print("Sensor page (status + Passive/Active switch): http://127.0.0.1:%d/     Ctrl+C stops." % port)
        try:
            import webbrowser
            threading.Timer(4.0, lambda: webbrowser.open("http://127.0.0.1:%d/" % port)).start()
        except Exception:  # noqa
            pass
    fails = 0
    while True:
        t0 = time.time()
        try:
            rc = run_sensor(ns)
        except KeyboardInterrupt:
            return 0
        if rc == 0:
            return 0
        fails = 0 if time.time() - t0 > 300 else fails + 1
        wait = min(60, 5 * (2 ** min(fails, 4)))
        print("[%s] the sensor stopped (code %s) - starting again in %d s" % (time.strftime("%H:%M:%S"), rc, wait), flush=True)
        try:
            time.sleep(wait)
        except KeyboardInterrupt:
            return 0


def _is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


SURVEY_PAGE = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>OT Sense survey</title>
<style>body{font-family:Segoe UI,Arial,sans-serif;background:#0f1722;color:#e8eef7;margin:0;display:flex;justify-content:center}
.c{max-width:640px;width:100%;padding:28px}h1{font-size:26px;margin:0 0 6px}.s{color:#9fb0c6;margin-bottom:22px}
.st{display:flex;align-items:center;gap:12px;padding:12px 14px;margin:8px 0;border-radius:10px;background:#18222f;font-size:18px}
.st i{width:22px;height:22px;border-radius:50%;background:#33445a;flex:none}.st.on i{background:#f5a623}.st.ok i{background:#2ecc71}
.bar{height:14px;background:#18222f;border-radius:8px;overflow:hidden;margin:18px 0}.bar b{display:block;height:100%;background:#4aa3ff;width:0}
.big{font-size:22px;margin:18px 0;padding:16px;border-radius:12px;background:#18222f}.err{background:#4a2020}.good{background:#1d4a2c}
.n{color:#9fb0c6;font-size:15px}</style>
<div class=c><h1>OT Sense network survey</h1><div class=s id=site></div>
<div class=st id=s1><i></i><span>Listening to the network</span></div>
<div class=st id=s2><i></i><span>Looking for devices</span></div>
<div class=st id=s3><i></i><span>Sending results to the central console</span></div>
<div class=bar><b id=pb></b></div><div class=n id=cnt></div><div class="big" id=msg>Starting...</div></div>
<script>
function g(i){return document.getElementById(i)}
function tick(){fetch('/state').then(r=>r.json()).then(s=>{g('site').textContent='Site: '+s.site;
g('pb').style.width=s.pct+'%';g('cnt').textContent='Devices found: '+s.devices+'   |   Network packets seen: '+s.packets;
g('s1').className='st '+(s.phase==='listen'?'on':'ok');
g('s2').className='st '+(s.phase==='listen'?(s.scan_done?'ok':'on'):'ok');
g('s3').className='st '+(s.phase==='send'?'on':s.phase==='done'?(s.sent?'ok':''):'');
var m=g('msg');m.className='big'+(s.error?' err':s.phase==='done'&&s.sent?' good':'');m.textContent=s.message;
if(s.phase!=='done')setTimeout(tick,2000)}).catch(function(){g('msg').textContent='This window has finished. You can close it.'})}
tick();
</script>"""


def run_survey(ns, c, d, interactive, pause):
    """ONE-TIME SURVEY (Windows app, for a non-IT person): listen + actively scan for SURVEY_MIN minutes, send everything to central,
    save a local report, show a plain progress page, then stop. Nothing to click or choose."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    minutes = max(1, min(240, int(c.get("SURVEY_MIN") or 10)))
    if os.name == "nt" and not npcap_present() and not _is_admin():
        try:   # the built-in listener needs Administrator: ask Windows (the person only clicks Yes)
            import ctypes
            exe = sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__)
            params = "" if getattr(sys, "frozen", False) else '"%s"' % exe
            prog = exe if getattr(sys, "frozen", False) else sys.executable
            if ctypes.windll.shell32.ShellExecuteW(None, "runas", prog, params, d, 1) > 32:
                return 0
        except Exception:  # noqa
            pass
        print("Please right-click this program and choose Run as administrator.")
        pause()
        return 2
    an = Analyzer(None, False)
    sn = Sensor(an, ns.site, ns.central, ns.token, ns.interval, ns.cafile, ns.insecure, ns.iface, "live")
    sn.scan_local = "active"
    try:
        from urllib.parse import urlparse
        cu = urlparse(ns.central)
        an.exclude = (socket.gethostbyname(cu.hostname), cu.port or (443 if cu.scheme == "https" else 80))
    except Exception:  # noqa
        pass
    stop, errs = threading.Event(), []
    st = {"phase": "listen", "message": "Collecting data. Please leave this PC switched on and connected to the network.", "sent": False,
          "error": "", "scan_done": False, "pct": 0, "t0": time.time()}
    total = int(os.environ.get("OTSENSE_SURVEY_SECONDS") or 0) or minutes * 60

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path.startswith("/state"):
                left = max(0, int(total - (time.time() - st["t0"])))
                msg = st["message"]
                if st["phase"] == "listen":
                    msg += "  About %d min %02d s left." % (left // 60, left % 60)
                body = json.dumps({"site": ns.site, "phase": st["phase"], "message": msg, "sent": st["sent"], "error": st["error"],
                                   "scan_done": st["scan_done"], "pct": st["pct"], "devices": len(an.assets), "packets": an.pkts}).encode()
                ct = "application/json"
            else:
                body, ct = SURVEY_PAGE.encode(), "text/html; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", ct)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    port = int(ns.ui_port or 8099)
    srv = None
    for p in (port, port + 1, port + 2, 0):
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", p), H)
            break
        except OSError:
            continue
    if srv:
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        print("Progress page: http://127.0.0.1:%d/" % port)
        try:
            import webbrowser
            webbrowser.open("http://127.0.0.1:%d/" % port)
        except Exception:  # noqa
            pass
    print("OT Sense survey for site '%s': listening and scanning for %d minutes, then sending to %s" % (ns.site, minutes, ns.central))
    th = threading.Thread(target=run_capture, args=(an, "" if ns.iface in ("any", "") else ns.iface, stop, None, None, errs), daemon=True)
    th.start()
    sn._apply_scan()
    scan_t0 = time.time()
    next_push = time.time() + 120
    while time.time() - st["t0"] < total:
        time.sleep(1)
        st["pct"] = int(min(90, 90.0 * (time.time() - st["t0"]) / total))
        if sn.active.result.get("at", 0) >= int(scan_t0) and sn.active.result.get("enabled"):
            st["scan_done"] = True
        if time.time() >= next_push:      # safety copy every 2 minutes in case the PC is switched off early
            sn.push()
            sn.scan_central = ""
            sn._apply_scan()
            next_push = time.time() + 120
    # make sure one full scan finished (up to 3 more minutes)
    st["message"] = "Finishing the device scan..."
    w0 = time.time()
    while not st["scan_done"] and time.time() - w0 < 180:
        time.sleep(1)
        if sn.active.result.get("at", 0) >= int(scan_t0) and sn.active.result.get("enabled"):
            st["scan_done"] = True
    stop.set()
    time.sleep(1)
    st.update(phase="send", pct=95, message="Sending the results to the central console...")
    sn.scan_central = ""
    ok = False
    for attempt in range(6):
        ok = sn.push()
        if ok:
            break
        st["message"] = "Cannot reach the central console yet (try %d of 6). Check this PC's internet connection..." % (attempt + 1)
        time.sleep(10)
    outdir = os.path.join(d, "OTSense-survey-results-" + time.strftime("%Y%m%d-%H%M"))
    try:
        snap = an.snapshot()
        write_reports(snap, outdir)
    except Exception as e:  # noqa
        print("could not save the local report: %s" % e)
    scan = sn.active.result
    st.update(phase="done", pct=100, sent=bool(ok))
    if ok:
        st["message"] = "Finished. %d devices were found and sent to the central console. You can close this window now." % len(an.assets)
    else:
        st["error"] = "x"
        st["message"] = "Finished, but the results could NOT be sent to central. They are saved in the folder next to this program: %s. Please give that folder to the person who sent you this program." % os.path.basename(outdir)
    print(st["message"])
    if scan.get("error"):
        print("Device scan note:", scan["error"])
    if interactive:
        time.sleep(300 if srv else 0)   # keep the "done" page up for a while, then exit by itself
    return 0 if ok else 1



def _finish(an, args, quiet=False):
    snap = an.snapshot()
    paths = write_reports(snap, args.output)
    if getattr(args, "save_baseline", None):
        with open(args.save_baseline, "w") as f:
            json.dump(an.baseline_dict(), f, indent=1)
        print("Baseline saved to", args.save_baseline)
    if not quiet:
        print_summary(snap)
    print("\nReports written to %s/ :  report.html (open in a browser), otsense.json, assets.csv, alerts.csv, flows.csv" % args.output)
    return snap


def main(argv=None):
    av = sys.argv[1:] if argv is None else list(argv)
    if (getattr(sys, "frozen", False) and (not av or av[0].lower() in ("run", "service", "install", "uninstall", "ifaces"))) or (av and av[0] == "winapp"):
        return run_winapp(av[1:] if av and av[0] == "winapp" else av)
    ap = argparse.ArgumentParser(prog="otsense", description="Passive OT/IT asset discovery, DPI and threat detection")
    ap.add_argument("--oui", help="vendor file (nmap-mac-prefixes or Wireshark manuf) for full MAC vendor names")
    ap.add_argument("--debug", action="store_true")
    sub = ap.add_subparsers(dest="cmd")

    def common(p):
        p.add_argument("-o", "--output", default="otsense_out", help="output directory (default otsense_out)")
        p.add_argument("--baseline", help="baseline JSON from --save-baseline; alerts on new devices / OT flows")
        p.add_argument("--save-baseline", help="save the current inventory as a baseline")
        p.add_argument("-q", "--quiet", action="store_true", help="do not print tables")

    p = sub.add_parser("pcap", help="analyse a pcap / pcapng file")
    p.add_argument("file")
    p.add_argument("--nmap-xml", help="merge an nmap -oX result into the inventory")
    common(p)
    p = sub.add_parser("live", help="live passive capture (run on the SPAN/TAP-fed interface)")
    p.add_argument("-i", "--iface", default="any")
    p.add_argument("-t", "--duration", type=int, default=0, help="seconds (0 = until Ctrl-C)")
    p.add_argument("--interval", type=int, default=30, help="rewrite reports every N seconds")
    p.add_argument("--bpf", help="BPF capture filter (needs scapy + libpcap)")
    p.add_argument("--save-pcap", help="also save the raw capture to this pcap file")
    common(p)
    p = sub.add_parser("web", help="dashboard with pcap upload and live capture")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("-o", "--output", default="otsense_out")
    p = sub.add_parser("nmap", help="optional active discovery via nmap (safe ARP ping by default) or import nmap XML")
    p.add_argument("target", nargs="?", help="CIDR to scan, e.g. 192.168.10.0/24")
    p.add_argument("--xml", help="import an existing nmap -oX file instead of scanning")
    p.add_argument("--ot-probe", action="store_true", help="also query OT ports with read-only nmap scripts (s7-info, modbus-discover, bacnet-info, enip-info)")
    p.add_argument("--i-have-permission", action="store_true", help="required for --ot-probe: confirms you may probe these devices")
    common(p)
    p = sub.add_parser("sample", help="write a synthetic OT pcap (Modbus, S7, ENIP, DNP3, BACnet, IEC-104, OPC UA, PROFINET + attacks)")
    p.add_argument("file", nargs="?", default="sample_ot.pcap")
    p.add_argument("--clean", action="store_true", help="normal operation only, no rogue device / attacks")
    p = sub.add_parser("sensor", help="APPLIANCE MODE: capture locally and push inventory + alerts to OTSense Central")
    env = os.environ.get
    p.add_argument("--site", default=env("OTSENSE_SITE") or socket.gethostname(), help="site name (default hostname)")
    p.add_argument("--central", default=env("OTSENSE_CENTRAL"), help="central URL, e.g. https://central.example:8443")
    p.add_argument("--token", default=env("OTSENSE_TOKEN"), help="site token from central (prefer OTSENSE_TOKEN env var)")
    p.add_argument("-i", "--iface", default=env("OTSENSE_IFACE") or "any", help="capture interface fed by SPAN/TAP")
    p.add_argument("--interval", type=int, default=int(env("OTSENSE_INTERVAL") or 30), help="push interval seconds")
    p.add_argument("--cafile", default=env("OTSENSE_CAFILE"), help="CA / self-signed cert of central to trust")
    p.add_argument("--insecure", action="store_true", help="do not verify central TLS certificate (lab only)")
    p.add_argument("--bpf", help="BPF capture filter (needs scapy + libpcap)")
    p.add_argument("--baseline", help="baseline JSON for new-device / new-flow alerts")
    p.add_argument("--scan", choices=["passive", "active"], default=env("OTSENSE_SCAN") or "passive",
                   help="passive = only listen (default); active = also probe this machine's own subnet. Central can override per site")
    p.add_argument("--ui-port", type=int, default=int(env("OTSENSE_SENSOR_UI_PORT") or 0),
                   help="small local status page with the Passive/Active switch (0 = off)")
    p.add_argument("--ui-host", default=env("OTSENSE_SENSOR_UI_HOST") or "127.0.0.1", help="address of that page (default this computer only)")
    p.add_argument("--state-file", default=env("OTSENSE_STATE_FILE"), help="remembers the Passive/Active choice made on the local page")
    p.add_argument("--pcap", help="replay a pcap instead of capturing live (testing)")
    p.add_argument("--keep-alive", action="store_true", help="with --pcap: keep sending heartbeats after the push")
    p = sub.add_parser("appliance", help="SENSOR APPLIANCE with a local web UI: setup wizard, live status, live traffic (Linux)")
    p.add_argument("--state-dir", default=env("OTSENSE_STATE") or "/var/lib/otsense", help="where settings are kept")
    p.add_argument("--ui-host", default="0.0.0.0")
    p.add_argument("--ui-port", type=int, default=8080)
    p.add_argument("--ui-password", default=env("OTSENSE_UI_PASSWORD"), help="web UI password (default: random, printed once)")
    p.add_argument("--no-tls", action="store_true", help="serve the UI over plain http (not recommended)")
    p.add_argument("--configure-only", action="store_true", help="write the settings given below and exit")
    p.add_argument("--site")
    p.add_argument("--central")
    p.add_argument("--token")
    p.add_argument("--iface")
    p.add_argument("--cafile")
    p.add_argument("--interval", type=int)
    p.add_argument("--insecure", action="store_true")
    p.add_argument("--mgmt-iface", help="management port (the web page and central traffic use it)")
    p.add_argument("--scan", choices=["passive", "active"], default=env("OTSENSE_SCAN") or None,
                   help="passive = only listen (default); active = also probe the sensor's own subnet. Central can override per site")
    p.add_argument("--restrict-ui", action="store_true", help="only answer the web page on the management port (+ localhost)")
    p.add_argument("--ui-cert", help="PEM certificate (with chain) for the sensor's web page")
    p.add_argument("--ui-key", help="PEM private key for --ui-cert")
    p.add_argument("--ui-key-pass", default=os.environ.get("OTSENSE_UI_KEY_PASS"), help="passphrase of --ui-key, if it has one (or env OTSENSE_UI_KEY_PASS)")
    sub.add_parser("ifaces", help="list capture interfaces")
    args = ap.parse_args(argv)

    if args.oui:
        print("Loaded %d OUI entries" % load_oui_file(args.oui))
    if args.cmd == "ifaces":
        for i in list_ifaces():
            print("%-18s %-16s %s" % (i["name"], i["ip"], i["state"]))
        return 0
    if args.cmd == "appliance":
        return run_appliance(args)
    if args.cmd == "sensor":
        return run_sensor(args)
    if args.cmd == "sample":
        n = _build_sample(args.file, not args.clean)
        print("Wrote %d packets to %s\nNow run:  python otsense.py pcap %s -o out" % (n, args.file, args.file))
        return 0
    if args.cmd == "web":
        serve_web(args.host, args.port, Analyzer(debug=args.debug), args.output)
        return 0
    if args.cmd == "pcap":
        an = Analyzer(_load_baseline(args.baseline), args.debug)
        t = time.time()
        try:
            an.feed_pcap(args.file)
        except (OSError, ValueError) as e:
            print("Cannot read %s: %s" % (args.file, e), file=sys.stderr)
            return 2
        if args.nmap_xml:
            with open(args.nmap_xml, encoding="utf-8", errors="replace") as f:
                print("Imported %d hosts from nmap XML" % an.import_nmap_xml(f.read()))
        print("Processed %d packets in %.1fs (%d parse errors)" % (an.pkts, time.time() - t, an.errors))
        _finish(an, args, args.quiet)
        return 0
    if args.cmd == "nmap":
        import shutil
        import subprocess
        an = Analyzer(_load_baseline(args.baseline), args.debug)
        an.source = "nmap " + (args.target or args.xml or "")
        if args.xml:
            with open(args.xml, encoding="utf-8", errors="replace") as f:
                xml = f.read()
        else:
            if not args.target:
                ap.error("give a target CIDR or --xml FILE")
            exe = shutil.which("nmap")
            if not exe:
                print("nmap not found. Install it (apt install nmap) or use --xml with an existing scan.", file=sys.stderr)
                return 2
            if args.ot_probe and not args.i_have_permission:
                print("--ot-probe sends traffic to PLCs/RTUs. Add --i-have-permission to confirm you are authorised.", file=sys.stderr)
                return 2
            cmd = [exe, "-sn", "-PR", "-n", "--max-rate", "50", "-oX", "-", args.target]
            if args.ot_probe:
                cmd = [exe, "-sT", "-Pn", "-n", "-T2", "--max-rate", "20", "--max-parallelism", "1", "-p",
                       "102,502,20000,44818,47808,4840,2404", "--script", "s7-info,modbus-discover,bacnet-info,enip-info",
                       "-oX", "-", args.target]
            print("Running:", " ".join(cmd))
            xml = subprocess.run(cmd, capture_output=True, text=True).stdout
        print("Imported %d hosts" % an.import_nmap_xml(xml))
        _finish(an, args, args.quiet)
        return 0
    if args.cmd == "live":
        an = Analyzer(_load_baseline(args.baseline), args.debug)
        an.source = "live: " + args.iface
        stop, errs = threading.Event(), []
        th = threading.Thread(target=run_capture, args=(an, args.iface, stop, args.bpf, args.save_pcap, errs), daemon=True)
        th.start()
        print("Capturing on %s%s ... Ctrl-C to stop. Alerts print as they fire." % (args.iface, " for %ds" % args.duration if args.duration else ""))
        t0 = last = time.time()
        shown = set()
        try:
            while th.is_alive():
                time.sleep(1)
                with an.lock:
                    new = [(k, v) for k, v in an.alerts.items() if k not in shown]
                for k, v in new:
                    shown.add(k)
                    print("[%s] %s %s -> %s  %s" % (v["severity"].upper(), v["kind"], v["src"], v["dst"], v["title"]))
                if args.duration and time.time() - t0 >= args.duration:
                    break
                if time.time() - last >= args.interval:
                    last = time.time()
                    write_reports(an.snapshot(), args.output)
                    print("... %d packets, %d assets, %d alerts (reports refreshed)" % (an.pkts, len([a for a in an.assets.values() if a.alive]), len(an.alerts)))
        except KeyboardInterrupt:
            pass
        stop.set()
        th.join(3)
        for e in errs:
            print(e, file=sys.stderr)
        if not an.pkts:
            return 1
        _finish(an, args, args.quiet)
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        pass
