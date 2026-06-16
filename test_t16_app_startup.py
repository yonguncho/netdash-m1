#!/usr/bin/env python
"""T-16 Verification: /api/state with default config.yaml"""

import subprocess
import time
import requests
import sys
import os

# Step 1: 기본 config.yaml 상태 확인
print("=== Step 1: config.yaml 확인 ===")
with open("config.yaml") as f:
    config_content = f.read()
if "api_token" in config_content:
    print("✅ config.yaml에 api_token 설정 있음")
else:
    print("❌ config.yaml에 api_token 설정 없음 (Codex의 지적과 일치)")

# Step 2: 프로덕션 모드(--demo 없음)로 app.py 실행
print("\n=== Step 2: python app.py 실행 (프로덕션 모드) ===")
process = subprocess.Popen(
    [sys.executable, "app.py"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

# Step 3: 앱 시작 대기 (최대 5초)
print("앱 시작 대기 중...")
time.sleep(3)

# Step 4: 포트 자동 감지
port = None
try:
    # stderr에서 포트 번호 찾기
    stderr_output = process.stderr.readline() if process.poll() is None else ""

    # app.py 출력에서 포트 추출 (일반적인 Flask 출력 형식)
    # 또는 netstat으로 찾기
    import socket
    for p in range(8082, 8092):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('127.0.0.1', p))
        sock.close()
        if result == 0:
            port = p
            print(f"✅ 포트 감지: {port}")
            break
except Exception as e:
    print(f"포트 감지 실패: {e}")

if port is None:
    print("❌ 앱 시작 실패")
    stdout, stderr = process.communicate(timeout=2)
    print(f"STDOUT:\n{stdout}")
    print(f"STDERR:\n{stderr}")
    sys.exit(1)

# Step 5: 토큰 없이 /api/state 요청
print(f"\n=== Step 3: curl http://127.0.0.1:{port}/api/state (토큰 없음) ===")
try:
    response = requests.get(f"http://127.0.0.1:{port}/api/state", timeout=5)
    print(f"HTTP Status: {response.status_code}")
    print(f"Response: {response.json()}")

    if response.status_code == 200:
        if "switches" in response.json():
            print("✅ PASS: HTTP 200, switches 키 포함")
        else:
            print("❌ FAIL: HTTP 200이지만 switches 키 없음")
    elif response.status_code == 401:
        print("❌ FAIL: HTTP 401 (토큰 필요) - Codex의 지적 맞음")
    else:
        print(f"❌ UNEXPECTED: HTTP {response.status_code}")
except Exception as e:
    print(f"❌ 요청 실패: {e}")

# Step 6: 프로세스 종료
print("\n=== 정리 ===")
process.terminate()
try:
    process.wait(timeout=2)
except subprocess.TimeoutExpired:
    process.kill()
    print("앱 프로세스 강제 종료")
