# -*- coding: utf-8 -*-
"""관제 통합 대시보드용 통계 집계.

관제는 원래 '문제 목록'만 보여줬다. 목록은 무엇이 고장났는지는 알려주지만
**전체가 어떤 상태인지**는 못 보여준다(정상이 몇 대인지, 포트를 얼마나 쓰는지,
어느 벤더가 몇 대인지). 화면에서 세지 않아도 되게 여기서 미리 집계한다.

집계는 SQL로 한 번에 한다 — 장비가 수백 대일 때 파이썬에서 목록을 돌면
10초 폴링마다 전체를 훑게 된다.
"""
import re

from . import db, reachability


def _rows(conn, sql, args=()):
    try:
        return conn.execute(sql, args).fetchall()
    except Exception:
        return []


def _counter(rows, key="k", val="c"):
    """[(k, c)] → [{"name": k, "count": c}] (많은 순). 빈 이름은 '미지정'."""
    out = [{"name": (r[key] or "미지정"), "count": r[val]} for r in rows]
    out.sort(key=lambda x: -x["count"])
    return out


def _switch_stats(conn, db_path):
    total = 0
    by_status, by_vendor, by_kind = {}, [], []
    rs = _rows(conn, "SELECT IFNULL(status,'new') AS k, COUNT(*) AS c "
                     "FROM switches WHERE IFNULL(device_type,'')<>'Server' GROUP BY k")
    for r in rs:
        by_status[r["k"]] = r["c"]
        total += r["c"]
    # 드라이버 키(cisco_ios)가 아니라 제조사(Cisco)로 묶는다 — v6.17.0과 같은 원칙.
    # 같은 제조사의 다른 드라이버(cisco_ios/cisco_nxos)는 여기서 합쳐진다.
    from . import manufacturer
    vend_raw = _rows(conn,
        "SELECT IFNULL(vendor,'') AS k, COUNT(*) AS c "
        "FROM switches WHERE IFNULL(device_type,'')<>'Server' GROUP BY k")
    vend_map = {}
    for r in vend_raw:
        name = manufacturer.resolve(r["k"]) or (r["k"] or "미지정")
        vend_map[name] = vend_map.get(name, 0) + r["c"]
    by_vendor = sorted(({"name": k, "count": v} for k, v in vend_map.items()),
                       key=lambda x: -x["count"])
    by_kind = _counter(_rows(conn,
        "SELECT IFNULL(device_type,'') AS k, COUNT(*) AS c "
        "FROM switches WHERE IFNULL(device_type,'')<>'Server' GROUP BY k"))

    # 포트 사용률 — 최신 스냅샷만. up/down은 status 문자열이 벤더마다 달라
    # 'up'/'connected'를 up으로 본다(그 외는 down·미사용).
    ports = {"total": 0, "up": 0}
    pr = _rows(conn,
        "SELECT COUNT(*) AS total, "
        "SUM(CASE WHEN LOWER(IFNULL(status,'')) IN ('up','connected') THEN 1 ELSE 0 END) AS up "
        "FROM ports WHERE snapshot_id IN (SELECT MAX(snapshot_id) FROM ports GROUP BY switch_id)")
    if pr:
        ports["total"] = pr[0]["total"] or 0
        ports["up"] = pr[0]["up"] or 0
    ports["down"] = max(0, ports["total"] - ports["up"])
    ports["pct"] = round(ports["up"] * 100.0 / ports["total"]) if ports["total"] else 0

    alerts = {}
    for r in _rows(conn, "SELECT IFNULL(alert,'none') AS k, COUNT(*) AS c "
                         "FROM switches WHERE IFNULL(alert,'none')<>'none' GROUP BY k"):
        alerts[r["k"]] = r["c"]

    # 포트를 많이 쓰는 스위치 상위 — 증설 판단에 쓰인다.
    top = []
    for r in _rows(conn,
        "SELECT s.id AS sid, s.name AS name, COUNT(p.id) AS total, "
        "SUM(CASE WHEN LOWER(IFNULL(p.status,'')) IN ('up','connected') THEN 1 ELSE 0 END) AS up "
        "FROM ports p JOIN switches s ON s.id=p.switch_id "
        "WHERE p.snapshot_id IN (SELECT MAX(snapshot_id) FROM ports GROUP BY switch_id) "
        "GROUP BY s.id HAVING total>0 ORDER BY (1.0*up/total) DESC LIMIT 10"):
        t, u = r["total"] or 0, r["up"] or 0
        top.append({"id": r["sid"], "name": r["name"], "total": t, "up": u,
                    "pct": round(u * 100.0 / t) if t else 0})

    reach = {"up": 0, "down": 0}
    try:
        for _sid, ok in (reachability.get_state() or {}).items():
            reach["up" if ok else "down"] += 1
    except Exception:
        pass
    reach["unknown"] = max(0, total - reach["up"] - reach["down"])

    temps = []
    try:
        env = db.get_device_env_map(db_path, "switch")
        names = {s["id"]: s.get("name") for s in db.get_switches(db_path)}
        for sid, e in env.items():
            if e.get("max_temp_c") is not None:
                temps.append({"name": names.get(sid) or str(sid),
                              "temp_c": e["max_temp_c"], "level": e.get("level")})
        temps.sort(key=lambda x: -x["temp_c"])
    except Exception:
        pass

    # 포트 에러 '증가' 상위 — 누적값이 아니라 최근 24시간에 실제로 늘어난 양.
    # 끊어진 뒤 알리는 포트 DOWN과 달리, 나빠지는 중인 물리 링크를 먼저 찾는다.
    port_errors = []
    try:
        names = {s["id"]: s.get("name") for s in db.get_switches(db_path)}
        name_ids = {}
        for r in _rows(conn, "SELECT name, MIN(id) AS id, COUNT(*) AS c "
                             "FROM switches GROUP BY name"):
            if (r["c"] or 0) == 1:
                name_ids[r["name"]] = r["id"]
        for e in db.get_port_error_totals(db_path, hours=24, limit=10):
            nm = names.get(e["switch_id"]) or str(e["switch_id"])
            row = {"name": nm, "port": e["port"], "total": e["total"],
                   "in_err": e["in_err"], "out_err": e["out_err"],
                   "in_disc": e["in_disc"], "out_disc": e["out_disc"],
                   "crc": e["crc"], "last_ts": (e.get("last_ts") or "")[:16]}
            sid = name_ids.get(nm)
            if sid:
                row["id"] = sid            # 클릭 → 스위치 상세
            port_errors.append(row)
    except Exception:
        pass

    return {"total": total, "by_status": by_status, "by_vendor": by_vendor[:8],
            "by_kind": by_kind[:6], "ports": ports, "alerts": alerts,
            "reach": reach, "top_ports": top, "temps": temps[:8],
            "port_errors": port_errors}


def _firewall_stats(conn, db_path):
    total = 0
    by_status = {}
    for r in _rows(conn, "SELECT IFNULL(status,'new') AS k, COUNT(*) AS c "
                         "FROM firewalls GROUP BY k"):
        by_status[r["k"]] = r["c"]
        total += r["c"]
    from . import manufacturer
    fw_raw = _rows(conn,
        "SELECT IFNULL(vendor,'') AS k, COUNT(*) AS c FROM firewalls GROUP BY k")
    fw_map = {}
    for r in fw_raw:
        name = manufacturer.resolve(r["k"]) or (r["k"] or "미지정")
        fw_map[name] = fw_map.get(name, 0) + r["c"]
    by_vendor = sorted(({"name": k, "count": v} for k, v in fw_map.items()),
                       key=lambda x: -x["count"])

    ifaces = {"total": 0}
    ir = _rows(conn, "SELECT COUNT(*) AS c FROM firewall_interfaces")
    if ir:
        ifaces["total"] = ir[0]["c"] or 0

    vpn = {"tunnels": 0, "up": 0, "ssl_users": 0}
    policy = {"total": 0, "unused": 0, "disabled": 0}
    sensors = {"alarms": 0, "psu": 0}
    load, temps = [], []
    try:
        names = {f["id"]: (f.get("name"), f.get("host")) for f in db.list_firewalls(db_path)}
        for fid, e in (db.get_device_env_map(db_path, "firewall") or {}).items():
            nm = names.get(fid, (str(fid), ""))
            m = e.get("metrics") or {}
            if e.get("max_temp_c") is not None:
                temps.append({"name": nm[0], "temp_c": e["max_temp_c"], "level": e.get("level")})
            v = m.get("vpn") or {}
            vpn["tunnels"] += v.get("tunnel_total") or 0
            vpn["up"] += v.get("tunnel_up") or 0
            vpn["ssl_users"] += v.get("ssl_users") or 0
            p = m.get("policy") or {}
            for k in ("total", "unused", "disabled"):
                policy[k] += p.get(k) or 0
            s = m.get("sensors") or {}
            sensors["alarms"] += len(s.get("alarms") or [])
            sensors["psu"] += s.get("psu_count") or 0
            if any(m.get(k) is not None for k in ("cpu_pct", "mem_pct", "disk_pct")):
                load.append({"name": nm[0], "host": nm[1],
                             "cpu": m.get("cpu_pct"), "mem": m.get("mem_pct"),
                             "disk": m.get("disk_pct"), "sessions": m.get("sessions"),
                             "level": m.get("level")})
        load.sort(key=lambda x: -(x.get("cpu") or 0))
        temps.sort(key=lambda x: -x["temp_c"])
    except Exception:
        pass

    reach = {"up": 0, "down": 0}
    try:
        for _fid, ok in (reachability.get_fw_state() or {}).items():
            reach["up" if ok else "down"] += 1
    except Exception:
        pass
    reach["unknown"] = max(0, total - reach["up"] - reach["down"])

    vpn["down"] = max(0, vpn["tunnels"] - vpn["up"])

    # 장비별 상세 목록 — "어느 방화벽이"에 답하기 위한 재료.
    # 수집 상태(실패 사유 포함) / 정책 수(Firewall·Proxy) / VPN 터널 이름별 상태.
    fw_status_list, policy_rows, vpn_rows, devices = [], [], [], []
    # HA 폴백 재료 — SNMP가 HA를 못 준 장비도 ① REST ha_info(JSON)
    # ② 같은 호스트(VIP)를 공유하는 쌍이면 이중화로 표기한다.
    # (사용자 지적: 어떤 장비만 HA가 보임 — SNMP 유무에 따라 갈리던 것)
    import json as _json
    _host_count = {}
    try:
        for _f in db.list_firewalls(db_path):
            _h = (_f.get("host") or "").strip()
            if _h:
                _host_count[_h] = _host_count.get(_h, 0) + 1
    except Exception:
        pass
    license_rows, objects_rows = [], []
    import datetime as _dt
    _today = _dt.date.today()

    def _lic_level(expires, status):
        """만료일 → expired / imminent(90일) / ok."""
        if status == "expired":
            return "expired"
        if not expires:
            return "ok"
        try:
            days = (_dt.date.fromisoformat(expires) - _today).days
        except ValueError:
            return "ok"
        if days < 0:
            return "expired"
        return "imminent" if days <= 90 else "ok"
    try:
        env_map = db.get_device_env_map(db_path, "firewall") or {}
        for f in db.list_firewalls(db_path):
            fw_status_list.append({
                "id": f["id"], "name": f.get("name"), "host": f.get("host"),
                "status": f.get("status") or "new",
                "last_error": (f.get("last_error") or "")[:120],
                "last_collected": f.get("last_collected")})
            m = (env_map.get(f["id"]) or {}).get("metrics") or {}
            _e = env_map.get(f["id"]) or {}
            _v, _p, _s = m.get("vpn") or {}, m.get("policy") or {}, m.get("sensors") or {}
            if m:      # 지표가 있는 장비만 카드로(빈 카드 금지 — 사용자 요구)
                _tuns = _v.get("tunnels") or []
                _lc = None
                if m.get("model") or m.get("version"):
                    try:
                        from . import fortilifecycle
                        _lc = fortilifecycle.lookup(m.get("model"), m.get("version"))
                    except Exception:
                        _lc = None
                _ha = m.get("ha_mode")
                if not _ha or _ha == "standalone":
                    try:
                        _hi = _json.loads(f.get("ha_info") or "null")
                        if isinstance(_hi, dict) and _hi.get("mode"):
                            _ha = _hi["mode"]
                    except (ValueError, TypeError):
                        pass
                if (not _ha or _ha == "standalone") and                         _host_count.get((f.get("host") or "").strip(), 0) > 1:
                    _ha = "이중화(VIP 공유)"
                _dev_lic = [{"name": x.get("name"), "expires": x.get("expires"),
                             "level": _lic_level(x.get("expires"), x.get("status"))}
                            for x in (m.get("license") or [])]
                devices.append({
                    "id": f["id"], "name": f.get("name"), "host": f.get("host"),
                    "license": _dev_lic,
                    "cpu": m.get("cpu_pct"), "mem": m.get("mem_pct"),
                    "disk": m.get("disk_pct"), "sessions": m.get("sessions"),
                    "level": m.get("level"), "version": m.get("version"),
                    "model": m.get("model"), "lifecycle": _lc,
                    "ha": _ha if (_ha and _ha != "standalone") else None,
                    "uptime_sec": m.get("uptime_sec"), "ha_mode": m.get("ha_mode"),
                    "temp_c": _e.get("max_temp_c") or _s.get("max_temp_c"),
                    "psu_count": _s.get("psu_count"),
                    "alarms": _s.get("alarms") or [],
                    "vpn_total": _v.get("tunnel_total"), "vpn_up": _v.get("tunnel_up"),
                    "tunnels_down": [{"name": t.get("name"), "peer": t.get("peer")}
                                     for t in _tuns if t.get("status") != "up"][:12],
                    "tunnels_up": [t.get("name") for t in _tuns
                                   if t.get("status") == "up"][:12],
                    "policy_total": _p.get("total"), "proxy_total": _p.get("proxy_total")})
            p = m.get("policy") or {}
            if p.get("total") is not None:
                policy_rows.append({
                    "name": f.get("name"), "total": p.get("total") or 0,
                    "proxy_total": p.get("proxy_total"),
                    "unused": p.get("unused"), "disabled": p.get("disabled")})
                policy["proxy_total"] = (policy.get("proxy_total") or 0) + (p.get("proxy_total") or 0)
            # 라이선스 — 방화벽별 구독 목록(만료/임박 판정 포함)
            for lic in (m.get("license") or []):
                license_rows.append({
                    "fw": f.get("name"), "name": lic.get("name"),
                    "expires": lic.get("expires"),
                    "level": _lic_level(lic.get("expires"), lic.get("status"))})
            obj = m.get("objects") or {}
            if obj.get("total"):
                objects_rows.append(dict(obj, fw=f.get("name")))
            v = m.get("vpn") or {}
            tuns = v.get("tunnels") or []
            if tuns:
                vpn_rows.append({
                    "name": f.get("name"),
                    "up": [t.get("name") for t in tuns if t.get("status") == "up"][:30],
                    "down": [{"name": t.get("name"), "peer": t.get("peer")}
                             for t in tuns if t.get("status") != "up"][:30]})
    except Exception:
        pass

    return {"total": total, "by_status": by_status, "by_vendor": by_vendor,
            "reach": reach, "interfaces": ifaces, "vpn": vpn, "policy": policy,
            "sensors": sensors, "load": load, "temps": temps[:8],
            "fw_status_list": fw_status_list, "policy_rows": policy_rows,
            "vpn_rows": vpn_rows, "devices": devices,
            "license_rows": sorted(license_rows,
                                   key=lambda x: ({"expired": 0, "imminent": 1,
                                                   "ok": 2}[x["level"]],
                                                  x.get("expires") or "9999")),
            "license_bad": sum(1 for x in license_rows
                               if x["level"] in ("expired", "imminent")),
            "objects_rows": objects_rows}


def subnet_capacity(subnet):
    """대역이 담을 수 있는 호스트 IP 개수. 모르면 None(0을 쓰면 나눗셈이 깨진다).

    /31은 RFC 3021 링크(2개 모두 호스트), /32는 단일 호스트라 예외.
    그 외는 네트워크·브로드캐스트 2개를 뺀다.
    """
    if not subnet or "/" not in str(subnet):
        return None
    try:
        prefix = int(str(subnet).split("/", 1)[1].strip())
    except (TypeError, ValueError):
        return None
    if prefix < 0 or prefix > 32:
        return None
    size = 1 << (32 - prefix)
    return size if prefix >= 31 else size - 2


def _ip_sort_key(ip):
    """문자열 정렬은 .10을 .2보다 앞에 둔다 — 옥텟 숫자로 정렬한다."""
    try:
        parts = [int(p) for p in str(ip).split(".")]
        if len(parts) == 4:
            return tuple(parts)
    except (TypeError, ValueError):
        pass
    return (256, 0, 0, 0)


def facility_subnet_hosts(db_path, subnet, limit=2000):
    """한 대역의 설비 IP 목록(대역 클릭 → 리스트업). IP 숫자 순."""
    with db.get_db(db_path) as conn:
        # SQL에서 자르지 않고 다 읽어 정렬한 뒤 자른다. SQL LIMIT은 IP 순서와
        # 무관하게 잘라서, 큰 대역이면 '임의의 2000개'가 나온다. 설비 한 대역이
        # 수천 행을 넘는 일은 드물고, 그 정도 리스트 정렬은 순식간이다.
        rows = _rows(conn,
            "SELECT ip, mac, switch_name, port, online, direct, via, updated "
            "FROM facility_hosts WHERE IFNULL(subnet,'')=?", (subnet or "",))
        hosts = [{"ip": r["ip"], "mac": r["mac"] or "",
                  "switch_name": r["switch_name"] or "", "port": r["port"] or "",
                  "online": bool(r["online"]), "direct": bool(r["direct"]),
                  "via": r["via"] or "",
                  "updated": (r["updated"] or "")[:16]} for r in rows]
    hosts.sort(key=lambda h: _ip_sort_key(h["ip"]))
    total = len(hosts)
    truncated = total > limit
    hosts = hosts[:limit]
    cap = subnet_capacity(subnet)
    online = sum(1 for h in hosts if h["online"])
    return {"subnet": subnet, "hosts": hosts, "count": len(hosts),
            "total": total,
            "online": online, "offline": len(hosts) - online,
            "capacity": cap, "truncated": truncated}


def _facility_stats(conn, db_path=None):
    total = online = direct = 0
    r = _rows(conn, "SELECT COUNT(*) AS total, SUM(online) AS onl, "
                    "SUM(CASE WHEN direct=1 AND IFNULL(switch_name,'')<>'' THEN 1 ELSE 0 END) AS dir "
                    "FROM facility_hosts")
    if r:
        total = r[0]["total"] or 0
        online = r[0]["onl"] or 0
        direct = r[0]["dir"] or 0
    # 대역별 IP 사용 현황. 예전엔 LIMIT 12로 잘랐는데, 대역이 13개면 13번째가
    # 화면에서 조용히 사라져 '수집이 안 된 대역'과 구분되지 않았다. 전부 싣고,
    # 길면 화면이 카드 안 스크롤로 처리한다(개수는 카드 제목에 밝힌다).
    by_subnet = []
    for x in _rows(conn,
        "SELECT subnet AS k, COUNT(*) AS c, SUM(online) AS onl, "
        "SUM(CASE WHEN direct=1 AND IFNULL(switch_name,'')<>'' THEN 1 ELSE 0 END) AS dir "
        "FROM facility_hosts GROUP BY subnet ORDER BY c DESC"):
        c = x["c"] or 0
        onl = x["onl"] or 0
        cap = subnet_capacity(x["k"])
        by_subnet.append({"name": x["k"] or "미지정", "count": c,
                          "online": onl, "offline": c - onl,
                          "direct": x["dir"] or 0,
                          "capacity": cap,
                          # 사용률은 대역 크기를 알 때만. 모르면 화면이 '-'로 둔다
                          # (0%로 보내면 '텅 빈 대역'으로 오독된다).
                          "usage_pct": (round(c * 1000.0 / cap) / 10.0) if cap else None})
    by_switch = _counter(_rows(conn,
        "SELECT IFNULL(switch_name,'') AS k, COUNT(*) AS c FROM facility_hosts "
        "WHERE IFNULL(switch_name,'')<>'' GROUP BY k ORDER BY c DESC LIMIT 10"))
    # 최근 7일 연결 실패 다발 스위치 — 이벤트의 IP를 설비의 연결 스위치로 대조.
    # 특정 스위치 아래 설비만 자주 끊기면 스위치·포트·전원 쪽 문제를 의심할 수 있다.
    offline_by_switch = _counter(_rows(conn,
        "SELECT IFNULL(f.switch_name,'') AS k, COUNT(*) AS c "
        "FROM device_events e JOIN facility_hosts f ON f.ip = e.ip "
        "WHERE e.kind='device_offline' AND IFNULL(f.switch_name,'')<>'' "
        "  AND e.ts >= datetime('now','localtime','-7 days') "
        "GROUP BY k ORDER BY c DESC LIMIT 10"))
    offline_24h = 0
    r24 = _rows(conn, "SELECT COUNT(*) AS c FROM device_events "
                      "WHERE kind='device_offline' "
                      "  AND ts >= datetime('now','localtime','-1 day')")
    if r24:
        offline_24h = r24[0]["c"] or 0
    # 이름 → 스위치 id (클릭→상세 연동). 같은 이름이 여럿이면 특정 불가라 뺀다.
    name_ids = {}
    for r in _rows(conn, "SELECT name, MIN(id) AS id, COUNT(*) AS c FROM switches GROUP BY name"):
        if (r["c"] or 0) == 1:
            name_ids[r["name"]] = r["id"]
    for lst in (by_switch, offline_by_switch):
        for e in lst:
            sid = name_ids.get(e["name"])
            if sid:
                e["id"] = sid
    # 연결 실패 설비를 **TPS 구역(물리 위치)별**로 묶는다.
    # 스위치 이름만 보면 "어느 스위치"는 알아도 "어디로 가야 하나"를 모른다.
    # 호스트네임의 F{공장}B{건물}_{층}F{TPS} 패턴이 곧 현장 위치다.
    offline_by_location = _offline_by_tps_location(conn, db_path)

    return {"total": total, "online": online, "offline": max(0, total - online),
            "direct": direct, "indirect": max(0, total - direct),
            "by_subnet": by_subnet, "by_switch": by_switch,
            "offline_by_switch": offline_by_switch, "offline_24h": offline_24h,
            "offline_by_location": offline_by_location}


def _offline_by_tps_location(conn, db_path=None):
    """지금 연결 실패인 설비를 TPS 구역별로 집계 → [{label, phase, building,
    floor, tps, offline, total, switches[]}] (실패 많은 순).

    관제에서 필요한 건 '어느 스위치'가 아니라 **어디로 가야 하나**다.

    연결 스위치는 설비 현황 화면과 **같은 3단계**로 찾는다:
      ① 현재 MAC 기준 switch_name
      ② 과거 MAC 이력(get_mac_last_seen)
      ③ 포트 Description에 적힌 설비 IP(find_ports_by_description)
    끊긴 설비는 MAC이 에이징으로 지워져 ①이 비는 일이 흔하다 — 그것만 보면
    정작 '연결 실패'가 죄다 '위치 미확인'으로 떨어진다(사용자 지적).
    """
    from . import tps_location

    # 설비의 연결 스위치 이름 → 스위치 hostname/name (위치 파싱 재료)
    sw_meta = {}
    for r in _rows(conn, "SELECT name, hostname, location FROM switches"):
        if r["name"]:
            sw_meta[r["name"]] = dict(r)      # sqlite3.Row에는 .get()이 없다

    # 실패 설비 목록 — 스위치가 비는 것만 보강 대상으로 추린다
    rows = [dict(r) for r in _rows(conn,
        "SELECT ip, mac, IFNULL(switch_name,'') AS sw, online FROM facility_hosts")]
    weak = [h for h in rows if h["online"] == 0 and not h["sw"]]
    hist, desc = {}, {}
    if weak and db_path:
        try:
            hist = db.get_mac_last_seen(db_path, [h.get("mac") for h in weak]) or {}
        except Exception:
            hist = {}
        try:
            desc = db.find_ports_by_description(
                db_path, [h.get("ip") for h in weak if h.get("ip")]) or {}
        except Exception:
            desc = {}

    def _switch_of(h):
        if h["sw"]:
            return h["sw"]
        hx = re.sub(r"[^0-9a-f]", "", (h.get("mac") or "").lower())
        hh = hist.get(hx) if len(hx) == 12 else None
        # 업링크에서만 보인 이력은 '거기 꽂혀 있었다'가 아니라 '길목을 지났다' —
        # 위치로 쓰면 엉뚱한 구역이 된다(설비 현황도 같은 기준으로 구분한다).
        if hh and hh.get("switch_name") and not hh.get("via_uplink"):
            return hh["switch_name"]
        dm = desc.get(h.get("ip"))
        if dm and dm.get("switch_name"):
            return dm["switch_name"]
        return ""

    counts = {}
    for h in rows:
        key = _switch_of(h)
        c = counts.setdefault(key, [0, 0])
        c[1] += 1
        if h["online"] == 0:
            c[0] += 1

    agg = {}
    for sw, (off, tot) in counts.items():
        if not off:
            continue                      # 실패가 없는 구역은 관제에 올릴 것이 없다
        meta = sw_meta.get(sw) or {}
        info = tps_location.parse(meta.get("hostname") or sw)
        if info:
            key = info["label"]
            ent = agg.setdefault(key, {
                "label": key, "phase": info["phase"],
                "building": info["building_name"], "floor": info["floor"],
                "tps": info["tps"], "offline": 0, "total": 0, "switches": []})
        else:
            # 위치를 못 읽으면 스위치의 location 텍스트라도 쓰고, 그것도 없으면 미확인
            key = (meta.get("location") or "").strip() or "위치 미확인"
            ent = agg.setdefault(key, {
                "label": key, "phase": None, "building": "", "floor": None,
                "tps": "", "offline": 0, "total": 0, "switches": []})
        ent["offline"] += off
        ent["total"] += tot
        if sw and sw not in ent["switches"]:
            ent["switches"].append(sw)

    out = list(agg.values())
    out.sort(key=lambda x: (-x["offline"], x["label"]))
    return out[:12]


def build(db_path):
    """관제 대시보드 통계 전체. 실패한 구획은 비어도 나머지는 살린다."""
    out = {}
    with db.get_db(db_path) as conn:
        for key, fn in (("switches", lambda: _switch_stats(conn, db_path)),
                        ("firewalls", lambda: _firewall_stats(conn, db_path)),
                        ("facility", lambda: _facility_stats(conn, db_path))):
            try:
                out[key] = fn()
            except Exception:
                out[key] = {}
    return out
