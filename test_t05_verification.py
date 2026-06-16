#!/usr/bin/env python
"""T-05 Verification: config_loader with nonexistent path"""

from core.config_loader import load_config

# 테스트 1: 존재하지 않는 파일 경로로 demo_mode=False 호출
print("=== T-05 Test 1: load_config('nonexistent_path_xyz.yaml', demo_mode=False) ===")
try:
    config = load_config('nonexistent_path_xyz.yaml', demo_mode=False)
    print(f"❌ ERROR: RuntimeError 발생해야 하는데 Config가 반환됨: {config}")
except RuntimeError as e:
    print(f"✅ EXPECTED: RuntimeError 발생: {e}")
except Exception as e:
    print(f"❌ UNEXPECTED: {type(e).__name__}: {e}")

# 테스트 2: 존재하지 않는 파일 경로로 demo_mode=True 호출
print("\n=== T-05 Test 2: load_config('nonexistent_path_xyz.yaml', demo_mode=True) ===")
try:
    config = load_config('nonexistent_path_xyz.yaml', demo_mode=True)
    print(f"✅ SUCCESS: 기본 Config 반환됨")
    print(f"  db_path: {config.db_path}")
    print(f"  flap_threshold: {config.flap_threshold}")
    print(f"  upload_max_mb: {config.upload_max_mb}")
    print(f"  api_token: {config.api_token}")
    if config.db_path == "netdash.db" and config.flap_threshold == 3:
        print("✅ PASS: 기본값 정상 반환")
    else:
        print("❌ FAIL: 기본값이 예상과 다름")
except Exception as e:
    print(f"❌ ERROR: {type(e).__name__}: {e}")

# 테스트 3: 기본 경로(config.yaml)로 호출 (demo_mode=False)
print("\n=== T-05 Test 3: load_config() 기본 인자로 호출 (demo_mode=False) ===")
try:
    config = load_config(demo_mode=False)
    print(f"✅ SUCCESS: Config 반환됨")
    print(f"  db_path: {config.db_path}")
    print(f"  api_token: {config.api_token}")
    print("✅ PASS: 기본 경로에서 정상 로드")
except FileNotFoundError as e:
    print(f"❌ FileNotFoundError: {e}")
except Exception as e:
    print(f"❌ ERROR: {type(e).__name__}: {e}")
