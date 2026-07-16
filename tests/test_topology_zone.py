"""토폴로지 존(구성도 그룹) — 추론 + 명시 지정 우선순위."""


def test_infer_zone_tokens():
    from core.topology import infer_zone
    assert infer_zone("", "SKChem_HQ_4F_5420M_DMZ1_DA1") == "DMZ"
    assert infer_zone("", "SKChem_HQ_4F_5420M_SVR1_SW1") == "SERVERFARM"
    assert infer_zone("", "SKChem_HQ_ECO_5420_Eco-Lab1") == "ECO-LAB"
    assert infer_zone("", "SKChem_HUB_7F_X590_BB1") == "7F"
    assert infer_zone("", "SKChem_IBS_B1F_X590_BB1") == "B1F"
    assert infer_zone("", "random_host_no_zone") == ""
    # DMZ/SVR가 층보다 우선(4F에 있어도 DMZ로)
    assert infer_zone("", "X_4F_DMZ_1") == "DMZ"


def test_infer_zone_naming_convention():
    """언더스코어 명명규칙(사이트_층_존_장비타입_번호) 자동 분류 — v3.95."""
    from core.topology import infer_zone
    assert infer_zone("", "SKBA_F1_DMZ_SW_1") == "DMZ"
    assert infer_zone("", "SKBA_F1_VDI_NASSW_1") == "VDI NAS"   # 결합형: NASSW → NAS
    assert infer_zone("", "SKBA_F1_OA_FASW_3") == "OA"          # 장비타입 변형(FASW)
    assert infer_zone("", "CORE_SW_1") == "CORE"
    assert infer_zone("", "SKBA_2F_5420M_MES_SW_2") == "MES"    # 모델명(5420M) 제외
    # 명명규칙 형태가 아니면 기존 동작 유지(빈 값 → 미지정)
    assert infer_zone("", "random_host_no_zone") == ""
    # 의미토큰(DMZ 등)이 명명규칙보다 우선 — 기존 규칙 회귀 없음
    assert infer_zone("", "SKChem_HQ_4F_5420M_DMZ1_DA1") == "DMZ"
    assert infer_zone("", "SKChem_IBS_B1F_X590_BB1") == "B1F"


def test_update_switch_zone_persists(temp_db):
    from core import db
    sid = db.save_switch(temp_db, "SWZ", "10.0.0.9", "extreme")
    assert db.update_switch(temp_db, sid, zone="SERVERFARM")
    assert db.get_switch(temp_db, sid)["zone"] == "SERVERFARM"
    # 빈 문자열은 해제(유효)
    assert db.update_switch(temp_db, sid, zone="")
    assert (db.get_switch(temp_db, sid)["zone"] or "") == ""


def test_build_topology_zone_priority(temp_db):
    """명시 zone > hostname 토큰 추론 > 미지정."""
    from core import db, topology
    db.save_switch(temp_db, "SKChem_HQ_4F_5420M_DMZ1", "10.0.0.1", "extreme")
    s2 = db.save_switch(temp_db, "SVR_NODE", "10.0.0.2", "extreme")
    db.update_switch(temp_db, s2, zone="SERVERFARM(지정)")
    topo = topology.build_topology(temp_db)
    g = {n["name"]: n["group"] for n in topo["nodes"] if n.get("kind") == "sw"}
    assert g["SKChem_HQ_4F_5420M_DMZ1"] == "DMZ"        # 추론
    assert g["SVR_NODE"] == "SERVERFARM(지정)"           # 명시 우선(추론 SERVERFARM 무시)
