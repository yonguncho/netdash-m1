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
import random
import socket
import time

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

class SnmpError(Exception):
    """SNMP 조회 실패의 공통 상위 — 사유별로 조치가 다르다."""


class SnmpClosed(SnmpError):
    """서버는 살아 있는데 161에서 아무도 안 듣는다(ICMP port unreachable).

    → 그 서버에 snmpd가 없거나 꺼져 있다. 재시도해도 결과가 같다.
    """


class SnmpSilent(SnmpError):
    """아무 응답도 오지 않았다(타임아웃).

    → 방화벽이 UDP 161을 버리거나, 커뮤니티가 틀렸다(v2c는 무응답).
    """


class SnmpBadReply(SnmpError):
    """내 요청의 응답이 아니거나 해석할 수 없는 패킷(위조·잘림·쓰레기).

    교환을 중단시키지 않고 버린 뒤 진짜 응답을 계속 기다리는 데 쓴다.
    """


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


def _parse_varbinds(data, want_rid=None, want_community=None):
    """응답 메시지 → [(oid, value)].

    want_rid/want_community를 주면 **내가 보낸 요청의 응답인지 확인**한다.
    UDP는 아무나 답을 밀어 넣을 수 있어서, 이 확인이 없으면 경로상의 공격자가
    조작한 사양(os_info·cpu_cores·mem_total_mb…)을 자산 목록에 심을 수 있다.

    잘렸거나 남의 응답이면 SnmpBadReply — 호출자는 이걸 '버리고 계속 기다림'으로
    처리한다(예외로 교환 전체를 중단시키면 위조 패킷 하나로 수집이 죽는다).
    """
    try:
        return _parse_varbinds_inner(data, want_rid, want_community)
    except SnmpBadReply:
        raise
    except RuntimeError:
        raise                              # error-status는 진짜 에이전트의 응답이다
    except (IndexError, ValueError, TypeError) as e:
        # 잘린 패킷은 IndexError로 터진다 — 상위에서 '무응답'으로 오인되지 않게
        # 하나의 타입으로 모은다.
        raise SnmpBadReply("SNMP 응답 해석 실패: %s" % str(e)[:60])


def _parse_varbinds_inner(data, want_rid=None, want_community=None):
    i = 0
    if data[0] != 0x30:
        raise SnmpBadReply("SNMP 응답 형식 오류")
    _, i = _read_len(data, 1)
    # version
    ln, i = _read_len(data, i + 1)
    i += ln
    # community — 틀리면 내 요청의 응답이 아니다
    ln, j = _read_len(data, i + 1)
    comm = data[j:j + ln]
    if want_community is not None and comm != want_community:
        raise SnmpBadReply("커뮤니티 불일치 응답")
    i = j + ln
    # PDU
    pdu_tag = data[i]
    if pdu_tag not in (0xA2, 0xA5, 0xA0, 0xA1):
        raise SnmpBadReply("SNMP PDU 태그 오류(0x%02x)" % pdu_tag)
    _, i = _read_len(data, i + 1)
    ln, j = _read_len(data, i + 1)          # request-id
    rid = _dec_int(data[j:j + ln])
    if want_rid is not None and rid != want_rid:
        raise SnmpBadReply("다른 요청의 응답(request-id 불일치)")
    i = j + ln
    ln, j = _read_len(data, i + 1)          # error-status
    err = _dec_int(data[j:j + ln])
    i = j + ln
    ln, i = _read_len(data, i + 1)          # error-index
    i += ln
    if err:
        raise RuntimeError("SNMP 오류(error-status=%d)" % err)
    if data[i] != 0x30:
        raise SnmpBadReply("varbind 목록 형식 오류")
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
    def __init__(self, ip, community, timeout=2.0, retries=1, budget=45.0):
        self.ip = ip
        self.community = (community or "public").encode("utf-8")
        self.timeout = timeout
        self.retries = retries
        # 한 대에 쓸 총 시간 상한. 라운드 수만 제한하면, 매번 타임아웃 직전에
        # 한 줄씩만 주는 에이전트가 워커 하나를 수십 분간 붙잡는다.
        self.budget = budget
        self._deadline = time.monotonic() + budget
        # 요청 ID를 예측 가능하게(1001, 1002…) 두면 경로 밖 공격자도 맞히기 쉽다.
        self._rid = random.SystemRandom().randrange(1, 0x7FFFFF00)

    def out_of_time(self):
        return time.monotonic() >= self._deadline

    def _pdu(self, tag, oids, a, b):
        """(요청 바이트, request-id) — 응답 대조에 rid가 필요하다."""
        self._rid = (self._rid + 1) & 0x7FFFFFFF
        rid = self._rid
        vbs = b"".join(_tlv(0x30, _enc_oid(o) + _tlv(0x05, b"")) for o in oids)
        pdu = _tlv(tag, _enc_int(rid) + _enc_int(a) + _enc_int(b)
                   + _tlv(0x30, vbs))
        return _tlv(0x30, _enc_int(1) + _tlv(0x04, self.community) + pdu), rid

    def _send(self, msg_rid):
        # UDP라 '무응답'의 원인이 여러 가지인데, 하나는 갈라낼 수 있다.
        # 서버가 살아 있고 161을 아무도 안 들으면 ICMP port-unreachable이 오고,
        # 이때 Windows는 recv에서 ConnectionResetError(10054)를 낸다(실측 확인).
        # 방화벽이 조용히 버리거나 커뮤니티가 틀리면 그냥 타임아웃이다.
        # 원인이 다르면 조치도 다르므로 메시지를 나눈다. 10054는 재시도해도
        # 결과가 같으니 바로 끝낸다(서버마다 몇 초씩 낭비하지 않게).
        msg, rid = msg_rid
        last = None
        for _ in range(self.retries + 1):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.settimeout(self.timeout)
                # connect()로 상대를 고정하면 커널이 **다른 출처의 패킷을 버린다**.
                # 이게 없으면 아무나 임의의 주소·포트에서 답을 밀어 넣을 수 있다.
                s.connect((self.ip, SNMP_PORT))
                s.send(msg)
                end = time.monotonic() + self.timeout
                while True:
                    remain = end - time.monotonic()
                    if remain <= 0:
                        raise socket.timeout("timed out")
                    s.settimeout(remain)
                    data = s.recv(65535)
                    try:
                        return _parse_varbinds(data, want_rid=rid,
                                               want_community=self.community)
                    except SnmpBadReply:
                        # 위조·잘림·남의 응답 — 버리고 진짜 응답을 계속 기다린다.
                        # 여기서 예외를 올리면 쓰레기 패킷 하나로 수집이 죽는다.
                        continue
            except ConnectionResetError:
                raise SnmpClosed("161/UDP에서 응답할 프로세스가 없습니다"
                                 " — 서버에 snmpd가 떠 있지 않습니다")
            except socket.timeout as e:
                last = e
            except OSError as e:
                last = e
            finally:
                s.close()
        raise SnmpSilent("응답이 오지 않았습니다 — UDP 161 차단 또는 "
                         "커뮤니티 불일치(SNMPv2c는 커뮤니티가 틀리면 "
                         "응답하지 않습니다): %s" % (last or ""))

    def get(self, oids):
        return self._send(self._pdu(0xA0, list(oids), 0, 0))

    def walk(self, base, max_rows=64):
        """GETBULK으로 base 하위를 훑는다 → [(oid, value)].

        시간·행수 어느 쪽이든 상한에 닿으면 **지금까지 얻은 것을 반환**한다.
        중간에 응답이 끊겨도 예외로 올리지 않는다 — 부분 결과가 없는 것보다 낫다.
        """
        out = []
        cur = base
        while len(out) < max_rows:
            if self.out_of_time():
                utils.log_event("info", "snmp_walk_budget_exhausted",
                                ip=self.ip, base=base, rows=len(out))
                break
            try:
                vbs = self._send(self._pdu(0xA5, [cur], 0, 20))
            except SnmpError:
                break
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
                # 한 응답에 varbind를 수천 개 채워 넣으면 max_rows를 넘겨 버린다
                # (cpu_cores가 walk 길이라 조작된 사양이 그대로 저장된다).
                if len(out) >= max_rows:
                    return out
            if not grew:
                break
        return out


# ── 수집 ────────────────────────────────────────────────────────
def collect(ip, community="public", timeout=2.0, budget=45.0):
    """SNMP로 사양을 읽어 dict 반환. 응답이 없으면 예외.

    budget: 이 한 대에 쓸 총 시간(초) 상한. 라운드 수만 제한하면, 매 요청에
    타임아웃 직전 한 줄씩만 주는 에이전트가 수집 워커를 수십 분 붙잡는다.

    반환 키: hostname, os_info, mac, cpu_model, cpu_cores,
             mem_total_mb, disk_total_gb, disk_used_gb
    """
    s = _Session(ip, community, timeout=timeout, budget=budget)
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
