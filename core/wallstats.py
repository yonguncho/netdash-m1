# -*- coding: utf-8 -*-
"""관제 통합 대시보드용 통계 집계.

관제는 원래 '문제 목록'만 보여줬다. 목록은 무엇이 고장났는지는 알려주지만
**전체가 어떤 상태인지**는 못 보여준다(정상이 몇 대인지, 포트를 얼마나 쓰는지,
어느 벤더가 몇 대인지). 화면에서 세지 않아도 되게 여기서 미리 집계한다.

집계는 SQL로 한 번에 한다 — 장비가 수백 대일 때 파이썬에서 목록을 돌면
10초 폴링마다 전체를 훑게 된다.
"""
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

    return {"total": total, "by_status": by_status, "by_vendor": by_vendor[:8],
            "by_kind": by_kind[:6], "ports": ports, "alerts": alerts,
            "reach": reach, "top_ports": top, "temps": temps[:8]}


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
                devices.append({
                    "id": f["id"], "name": f.get("name"), "host": f.get("host"),
                    "cpu": m.get("cpu_pct"), "mem": m.get("mem_pct"),
                    "disk": m.get("disk_pct"), "sessions": m.get("sessions"),
                    "level": m.get("level"), "version": m.get("version"),
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
            "vpn_rows": vpn_rows, "devices": devices}


def _facility_stats(conn):
    total = online = direct = 0
    r = _rows(conn, "SELECT COUNT(*) AS total, SUM(online) AS onl, "
                    "SUM(CASE WHEN direct=1 AND IFNULL(switch_name,'')<>'' THEN 1 ELSE 0 END) AS dir "
                    "FROM facility_hosts")
    if r:
        total = r[0]["total"] or 0
        online = r[0]["onl"] or 0
        direct = r[0]["dir"] or 0
    by_subnet = []
    for x in _rows(conn,
        "SELECT subnet AS k, COUNT(*) AS c, SUM(online) AS onl "
        "FROM facility_hosts GROUP BY subnet ORDER BY c DESC LIMIT 12"):
        c = x["c"] or 0
        by_subnet.append({"name": x["k"] or "미지정", "count": c,
                          "online": x["onl"] or 0, "offline": c - (x["onl"] or 0)})
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
    return {"total": total, "online": online, "offline": max(0, total - online),
            "direct": direct, "indirect": max(0, total - direct),
            "by_subnet": by_subnet, "by_switch": by_switch,
            "offline_by_switch": offline_by_switch, "offline_24h": offline_24h}


def build(db_path):
    """관제 대시보드 통계 전체. 실패한 구획은 비어도 나머지는 살린다."""
    out = {}
    with db.get_db(db_path) as conn:
        for key, fn in (("switches", lambda: _switch_stats(conn, db_path)),
                        ("firewalls", lambda: _firewall_stats(conn, db_path)),
                        ("facility", lambda: _facility_stats(conn))):
            try:
                out[key] = fn()
            except Exception:
                out[key] = {}
    return out
