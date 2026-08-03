# -*- coding: utf-8 -*-
"""제품 정보 → 제조사(벤더사) 판별.

`fortigate`·`cisco_ios` 같은 값은 **제품 계열 또는 접속 드라이버 이름**이지
제조사가 아니다(FortiGate는 Fortinet의 방화벽 제품군, cisco_ios는 netmiko
드라이버 키). 화면에 그대로 내보내면 "벤더사: fortigate"가 되어 틀린 표기가 된다.

판별 순서 — 확실한 것부터:
  ① 드라이버/제품 키가 알려진 것이면 그대로 매핑(가장 확실)
  ② 수집된 모델명(`N9K-C9508`, `PA-3220`, `JL256A` …)의 형태로 추론
  ③ show version 등 OS 문자열의 제조사 키워드
어느 것도 못 찾으면 빈 문자열 — **추측해서 틀린 제조사를 적지 않는다.**

이 판별을 파이썬에 두는 이유: 화면(JS)에만 두면 엑셀 내보내기·보고서·관제가
각자 다른 표기를 갖게 된다(같은 기능에 경로가 둘이 되는 문제).
"""
import re

# ① 드라이버/제품 키 → 제조사
_BY_KEY = {
    # 방화벽
    "fortigate": "Fortinet",
    "fortios": "Fortinet",
    "paloalto": "Palo Alto Networks",
    "panos": "Palo Alto Networks",
    "pan_os": "Palo Alto Networks",
    # 스위치·라우터(netmiko device_type)
    "cisco_ios": "Cisco",
    "cisco_xe": "Cisco",
    "cisco_xr": "Cisco",
    "cisco_nxos": "Cisco",
    "cisco_asa": "Cisco",
    "arista_eos": "Arista",
    "juniper_junos": "Juniper",
    "juniper": "Juniper",
    "extreme_exos": "Extreme Networks",
    "hp_procurve": "HPE",
    "hp_comware": "HPE",
    "aruba_osswitch": "HPE Aruba",
    "aruba_os": "HPE Aruba",
    "aruba_cx": "HPE Aruba",
    "alteon": "Radware",
    "dell_os10": "Dell",
    "huawei": "Huawei",
    "mikrotik_routeros": "MikroTik",
}

# 제품 계열 표기 — '벤더' 컬럼에 드라이버 키를 그대로 쓰지 않기 위한 이름표
_PRODUCT = {
    "fortigate": "FortiGate",
    "paloalto": "PAN-OS",
    "cisco_ios": "Cisco IOS",
    "cisco_xe": "Cisco IOS-XE",
    "cisco_xr": "Cisco IOS-XR",
    "cisco_nxos": "Cisco NX-OS",
    "cisco_asa": "Cisco ASA",
    "arista_eos": "Arista EOS",
    "juniper_junos": "Junos",
    "extreme_exos": "EXOS",
    "hp_procurve": "ProCurve",
    "aruba_osswitch": "AOS-S",
    "aruba_os": "AOS-CX",
    "aruba_cx": "AOS-CX",
    "alteon": "Alteon",
}

# ② 모델명 패턴 → 제조사. 위에서부터 먼저 맞는 것을 쓴다(구체적인 것을 앞에).
_BY_MODEL = [
    (r"^(fg|fgt|fwf|fortigate)\b|^fg-?\d|fortigate", "Fortinet"),
    (r"^pa-?\d|^pan-|palo\s*alto", "Palo Alto Networks"),
    (r"^(n9k|n7k|n5k|n3k|n2k)-|nexus", "Cisco"),
    (r"^(ws-c|c9\d{3}|c3\d{3}|c2\d{3}|isr|asr|cbs\d)|catalyst|^cisco\b", "Cisco"),
    (r"^dcs-|arista", "Arista"),
    (r"^(ex|mx|srx|qfx|acx|ptx)\d|juniper", "Juniper"),
    (r"^(x4\d{2}|x6\d{2}|x8\d{2}|summit)|extreme", "Extreme Networks"),
    (r"^(jl|jg|jh|j9)\d|aruba", "HPE Aruba"),
    (r"procurve|^hp\b|hewlett", "HPE"),
    (r"alteon|radware", "Radware"),
    (r"^s\d{4}|huawei", "Huawei"),
    (r"powerconnect|^n\d{4}-on|dell", "Dell"),
]

# ③ OS 문자열 키워드 → 제조사
_BY_OS = [
    ("fortios", "Fortinet"), ("fortigate", "Fortinet"),
    ("pan-os", "Palo Alto Networks"), ("palo alto", "Palo Alto Networks"),
    ("nx-os", "Cisco"), ("ios-xe", "Cisco"), ("ios xe", "Cisco"),
    ("cisco", "Cisco"), ("arista", "Arista"), ("junos", "Juniper"),
    ("juniper", "Juniper"), ("extremexos", "Extreme Networks"),
    ("exos", "Extreme Networks"), ("aruba", "HPE Aruba"),
    ("procurve", "HPE"), ("hewlett", "HPE"), ("alteon", "Radware"),
]


def _norm(v):
    return str(v or "").strip().lower()


def from_key(vendor):
    """드라이버/제품 키 → 제조사. 모르면 ''."""
    return _BY_KEY.get(_norm(vendor), "")


def from_model(model):
    """모델명 → 제조사 추론. 모르면 ''."""
    m = _norm(model)
    if not m:
        return ""
    for pat, maker in _BY_MODEL:
        if re.search(pat, m):
            return maker
    return ""


def from_os(os_info):
    """OS 문자열(show version 등) → 제조사 추론. 모르면 ''."""
    s = _norm(os_info)
    if not s:
        return ""
    for kw, maker in _BY_OS:
        if kw in s:
            return maker
    return ""


def resolve(vendor=None, model=None, os_info=None):
    """제조사(벤더사)를 판별한다. 확실한 근거가 없으면 ''(빈 문자열).

    빈 문자열을 돌려주는 것이 중요하다 — 모르면서 아무 제조사나 적으면
    자산 목록이 조용히 틀린다.
    """
    return (from_key(vendor) or from_model(model) or from_os(os_info)
            or from_model(os_info) or "")


def product_label(vendor):
    """제품 계열 표기(FortiGate, Cisco NX-OS …). 모르면 원래 값 그대로."""
    v = _norm(vendor)
    return _PRODUCT.get(v, vendor or "")


def annotate(rows, vendor_key="vendor", model_key="model", os_key="os_version"):
    """목록 행들에 manufacturer·product 표기를 얹는다(제자리 수정 후 반환)."""
    for r in rows or []:
        try:
            r["manufacturer"] = resolve(r.get(vendor_key), r.get(model_key),
                                        r.get(os_key) or r.get("os_info"))
            r["product"] = product_label(r.get(vendor_key))
        except Exception:
            continue
    return rows
