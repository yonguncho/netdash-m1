# -*- coding: utf-8 -*-
"""서버 사양 수집 — SNMP(161/UDP) 경로.

SSH가 닫힌 서버는 사양(CPU·메모리·디스크)을 읽을 방법이 없었다.
Windows는 WMI(:wmi_collect)로 덮었지만, 리눅스·UNIX는 남는다.
대부분의 운영 서버는 감시용으로 **snmpd가 이미 떠 있으므로**(HOST-RESOURCES-MIB),
읽기 전용 GET만으로 사양을 얻을 수 있다.

  - SNMPv2c GET/GETBULK만 사용한다. 쓰기(SET)는 하지 않는다.
  - 외부 라이브러리 없이 BER를 직접 인코딩한다(폐쇄망 PyInstaller 배포).
  - UDP라 응답이 없으면 그냥 조용히 실패한다 → 짧은 타임아웃 + 1회 재시도로 끝낸다.
"""
import socket

from . import utils

SNMP_PORT = 161

# ── MIB OID ─────────────────────────────────────────────────────
_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
_SYS_NAME = "1.3.6.1.2.1.1.5.0"
_HR_PROC_LOAD = "1.3.6.1.2.1.25.3.3.1.2"      # 엔트리 수 = 논리 CPU 수
_HR_DEV_TYPE = "1.3.6.1.2.1.25.3.2.1.2"
_HR_DEV_DESCR = "1.3.6.1.2.1.25.3.2.1.3"
_HR_DEV_PROCESSOR = "1.3.6.1.2.1.25.3.1.3"
_HR_ST_TYPE = "1.3.6.1.2.1.25.2.3.1.2"
_HR_ST_DESCR = "1.3.6.1.2.1.25.2.3.1.3"
_HR_ST_UNITS = "1.3.6.1.2.1.25.2.3.1.4"
_HR_ST_SIZE = "1.3.6.1.2.1.25.2.3.1.5"
_HR_ST_USED = "1.3.6.1.2.1.25.2.3.1.6"
_ST_RAM = "1.3.6.1.2.1.25.2.1.2"
_ST_FIXED_DISK = "1.3.6.1.2.1.25.2.1.4"
_IF_PHYS_ADDR = "1.3.6.1.2.1.2.2.1.6"

# 디스크 합계에서 뺄 것 — 실제 저장 공간이 아니다(메모리 기반 FS·가상 장치)
_DISK_SKIP = ("tmpfs", "devtmpfs", "/dev/shm", "/run", "/sys", "/proc",
              "shared memory", "ram disk", "swap")


# ── BER 인코딩 ──────────────────────────────────────────────────
def _enc_len(n):
    if n < 0x80:
        return bytes([n])
    b = b""
    while n:
        b = bytes([n & 0xFF]) + b
        n >>= 8
    return bytes([0x80 | len(b)]) + b


def _tlv(tag, body):
    return bytes([tag]) + _enc_len(len(body)) + body


def _enc_int(v):
    # BER INTEGER는 2의 보수 최소 바이트 — 부호 비트를 직접 다루면 -1 같은
    # 경계값이 틀어진다(0xFF00 = -256). to_bytes에 맡기고 여분 바이트만 줄인다.
    b = int(v).to_bytes(int(v).bit_length() // 8 + 1, "big", signed=True)
    while len(b) > 1 and ((b[0] == 0x00 and not b[1] & 0x80)
                          or (b[0] == 0xFF and b[1] & 0x80)):
        b = b[1:]
    return _tlv(0x02, b)


def _enc_oid(oid):
    parts = [int(x) for x in str(oid).split(".") if x != ""]
    if len(parts) < 2:
        raise ValueError("OID가 too short: %s" % oid)
    body = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        if p < 0x80:
            body += bytes([p])
            continue
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.insert(0, (p & 0x7F) | 0x80)
            p >>= 7
        body += bytes(chunk)
    return _tlv(0x06, body)


# ── BER 디코딩 ──────────────────────────────────────────────────
def _read_len(buf, i):
    n = buf[i]
    i += 1
    if n < 0x80:
        return n, i
    cnt = n & 0x7F
    val = 0
    for _ in range(cnt):
        val = (val << 8) | buf[i]
        i += 1
    return val, i


def _dec_int(b):
    if not b:
        return 0
    v = int.from_bytes(b, "big", signed=True)
    return v


def _dec_uint(b):
    return int.from_bytes(b, "big", signed=False) if b else 0


def _dec_oid(b):
    if not b:
        return ""
    out = [b[0] // 40, b[0] % 40]
    acc = 0
    for c in b[1:]:
        acc = (acc << 7) | (c & 0x7F)
        if not c & 0x80:
            out.append(acc)
            acc = 0
    return ".".join(str(x) for x in out)


def _parse_varbinds(data):
    """응답 메시지 → [(oid, value)]. 파싱 실패하면 예외."""
    i = 0
    if data[0] != 0x30:
        raise ValueError("SNMP 응답 형식 오류")
    _, i = _read_len(data, 1)
    # version
    ln, i = _read_len(data, i + 1)
    i += ln
    # community
    ln, i = _read_len(data, i + 1)
    i += ln
    # PDU
    pdu_tag = data[i]
    if pdu_tag not in (0xA2, 0xA5, 0xA0, 0xA1):
        raise ValueError("SNMP PDU 태그 오류(0x%02x)" % pdu_tag)
    _, i = _read_len(data, i + 1)
    ln, i = _read_len(data, i + 1)          # request-id
    i += ln
    ln, j = _read_len(data, i + 1)          # error-status
    err = _dec_int(data[j:j + ln])
    i = j + ln
    ln, i = _read_len(data, i + 1)          # error-index
    i += ln
    if err:
        raise RuntimeError("SNMP 오류(error-status=%d)" % err)
    if data[i] != 0x30:
        raise ValueError("varbind 목록 형식 오류")
    total, i = _read_len(data, i + 1)
    end = i + total
    out = []
    while i < end:
        if data[i] != 0x30:
            break
        vb_len, i = _read_len(data, i + 1)
        vb_end = i + vb_len
        if data[i] != 0x06:
            break
        ln, j = _read_len(data, i + 1)
        oid = _dec_oid(data[j:j + ln])
        i = j + ln
        vtag = data[i]
        ln, j = _read_len(data, i + 1)
        raw = data[j:j + ln]
        i = vb_end
        if vtag in (0x80, 0x81, 0x82):      # noSuchObject/Instance, endOfMibView
            out.append((oid, None))
        elif vtag == 0x02:
            out.append((oid, _dec_int(raw)))
        elif vtag in (0x41, 0x42, 0x43, 0x46):   # Counter32/Gauge32/TimeTicks/Counter64
            out.append((oid, _dec_uint(raw)))
        elif vtag == 0x06:
            out.append((oid, _dec_oid(raw)))
        elif vtag == 0x05:
            out.append((oid, None))
        else:                                # OCTET STRING 등
            out.append((oid, raw))
    return out


# ── 전송 ────────────────────────────────────────────────────────
class _Session(object):
    def __init__(self, ip, community, timeout=2.0, retries=1):
        self.ip = ip
        self.community = (community or "public").encode("utf-8")
        self.timeout = timeout
        self.retries = retries
        self._rid = 1000

    def _pdu(self, tag, oids, a, b):
        self._rid += 1
        vbs = b"".join(_tlv(0x30, _enc_oid(o) + _tlv(0x05, b"")) for o in oids)
        pdu = _tlv(tag, _enc_int(self._rid) + _enc_int(a) + _enc_int(b)
                   + _tlv(0x30, vbs))
        return _tlv(0x30, _enc_int(1) + _tlv(0x04, self.community) + pdu)

    def _send(self, msg):
        last = None
        for _ in range(self.retries + 1):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.settimeout(self.timeout)
                s.sendto(msg, (self.ip, SNMP_PORT))
                data, _addr = s.recvfrom(65535)
                return _parse_varbinds(data)
            except socket.timeout as e:
                last = e
            except OSError as e:
                last = e
            finally:
                s.close()
        raise TimeoutError("SNMP 무응답: %s" % (last or ""))

    def get(self, oids):
        return self._send(self._pdu(0xA0, list(oids), 0, 0))

    def walk(self, base, max_rows=64):
        """GETBULK으로 base 하위를 훑는다 → [(oid, value)]."""
        out = []
        cur = base
        while len(out) < max_rows:
            try:
                vbs = self._send(self._pdu(0xA5, [cur], 0, 20))
            except (RuntimeError, ValueError):
                break
            if not vbs:
                break
            grew = False
            for oid, val in vbs:
                if not oid.startswith(base + ".") or val is None:
                    return out
                out.append((oid, val))
                cur = oid
                grew = True
            if not grew:
                break
        return out


# ── 수집 ────────────────────────────────────────────────────────
def collect(ip, community="public", timeout=2.0):
    """SNMP로 사양을 읽어 dict 반환. 응답이 없으면 예외.

    반환 키: hostname, os_info, mac, cpu_model, cpu_cores,
             mem_total_mb, disk_total_gb, disk_used_gb
    """
    s = _Session(ip, community, timeout=timeout)
    sys_vb = s.get([_SYS_DESCR, _SYS_NAME])           # 무응답이면 여기서 끝
    out = {}
    for oid, val in sys_vb:
        text = _text(val)
        if oid.startswith("1.3.6.1.2.1.1.1") and text:
            out["os_info"] = text[:200]
        elif oid.startswith("1.3.6.1.2.1.1.5") and text:
            out["hostname"] = text.split(".")[0][:100]

    # CPU — hrProcessorLoad 엔트리 수 = 논리 코어 수
    cores = len(s.walk(_HR_PROC_LOAD, max_rows=512))
    if cores:
        out["cpu_cores"] = cores
    model = _cpu_model(s)
    if model:
        out["cpu_model"] = model

    # 메모리·디스크 — hrStorage 테이블
    mem_mb, disk_gb, used_gb = _storage(s)
    if mem_mb:
        out["mem_total_mb"] = mem_mb
    if disk_gb:
        out["disk_total_gb"] = disk_gb
        out["disk_used_gb"] = used_gb

    mac = _first_mac(s)
    if mac:
        out["mac"] = mac
    utils.log_event("info", "snmp_collect_ok", ip=ip,
                    cores=out.get("cpu_cores"), mem_mb=out.get("mem_total_mb"))
    return out


def _text(val):
    if isinstance(val, bytes):
        return val.decode("utf-8", "replace").strip()
    return str(val).strip() if val is not None else ""


def _cpu_model(s):
    """hrDeviceType이 Processor인 항목의 hrDeviceDescr."""
    types = dict(s.walk(_HR_DEV_TYPE, max_rows=256))
    idx = [o.rsplit(".", 1)[-1] for o, v in types.items()
           if str(v) == _HR_DEV_PROCESSOR]
    if not idx:
        return ""
    descrs = dict(s.walk(_HR_DEV_DESCR, max_rows=256))
    for i in idx:
        d = _text(descrs.get(_HR_DEV_DESCR + "." + i))
        if d:
            # net-snmp는 "GenuineIntel: Intel(R) Xeon(R) ..." 형태로 준다
            return d.split(":", 1)[-1].strip()[:150] if ":" in d else d[:150]
    return ""


def _storage(s):
    """hrStorage 테이블 → (mem_total_mb, disk_total_gb, disk_used_gb)."""
    types = dict(s.walk(_HR_ST_TYPE, max_rows=128))
    if not types:
        return 0, 0.0, 0.0
    descrs = dict(s.walk(_HR_ST_DESCR, max_rows=128))
    units = dict(s.walk(_HR_ST_UNITS, max_rows=128))
    sizes = dict(s.walk(_HR_ST_SIZE, max_rows=128))
    useds = dict(s.walk(_HR_ST_USED, max_rows=128))

    ram_bytes, phys_bytes = 0, 0
    disk_total, disk_used = 0, 0
    for oid, kind in types.items():
        i = oid.rsplit(".", 1)[-1]
        u = units.get(_HR_ST_UNITS + "." + i) or 0
        sz = sizes.get(_HR_ST_SIZE + "." + i) or 0
        us = useds.get(_HR_ST_USED + "." + i) or 0
        if not (isinstance(u, int) and isinstance(sz, int)) or u <= 0 or sz <= 0:
            continue
        descr = _text(descrs.get(_HR_ST_DESCR + "." + i)).lower()
        if str(kind) == _ST_RAM:
            # 여러 RAM 엔트리를 더하면 캐시·버퍼가 겹쳐 과대 계산된다 → 최대값 사용,
            # 'physical'이 붙은 항목이 있으면 그것을 우선한다.
            b = sz * u
            if "physical" in descr or "실제" in descr:
                phys_bytes = max(phys_bytes, b)
            ram_bytes = max(ram_bytes, b)
        elif str(kind) == _ST_FIXED_DISK:
            if any(k in descr for k in _DISK_SKIP):
                continue
            disk_total += sz * u
            disk_used += (us if isinstance(us, int) and us > 0 else 0) * u

    mem_mb = int(round((phys_bytes or ram_bytes) / 1024.0 / 1024.0))
    gb = 1024.0 ** 3
    return mem_mb, round(disk_total / gb, 1), round(disk_used / gb, 1)


def _first_mac(s):
    for _oid, val in s.walk(_IF_PHYS_ADDR, max_rows=64):
        if isinstance(val, bytes) and len(val) == 6 and any(val):
            return ":".join("%02X" % c for c in val)
    return ""
