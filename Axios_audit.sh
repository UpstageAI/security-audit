#!/bin/bash

# 파일명: Axios_Security_Audit_Final_v2.sh
OUTPUT="axios_audit_report_$(date +%Y%m%d).log"

# 색상 및 스타일 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 1. 초기 설정
SCAN_ROOT="$HOME" 
MALICIOUS_VERSIONS=("1.14.1" "0.30.4")
VULN_LIST=()
TOTAL_FILES=0

clear
echo -e "${BLUE}==================================================${NC}"
echo -e "${BLUE}       Axios 공급망 공격 긴급 점검 스크립트       ${NC}"
echo -e "${BLUE}==================================================${NC}"
echo -e "대상 경로: $SCAN_ROOT"
echo -e "점검을 시작합니다. 잠시만 기다려 주세요...\n"

# 2. 점검 수행
# find의 결과를 while read로 받아 공백이 포함된 경로를 안전하게 처리합니다.
find "$SCAN_ROOT" \
  -path "*/Library" -prune -o \
  -path "*/node_modules" -prune -o \
  -path "*/.git" -prune -o \
  -path "*/dist" -prune -o \
  -path "*/build" -prune -o \
  -type f \( -name "package-lock.json" -o -name "yarn.lock" -o -name "package.json" \) -print 2>/dev/null | while IFS= read -r file; do
    
    ((TOTAL_FILES++))
    IS_VULN=false
    REASON=""

    # [점검 1] plain-crypto-js 탐지 (변수 주위에 쌍따옴표 추가로 공백 대응)
    if grep -q "plain-crypto-js" "$file" 2>/dev/null; then
        IS_VULN=true
        REASON="악성 의존성 'plain-crypto-js' 포함"
    fi

    # [점검 2] Axios 침해 버전 탐지
    AXIOS_VERSION=""
    if [[ "$file" == *"package-lock.json" ]] || [[ "$file" == *"package.json" ]]; then
        AXIOS_VERSION=$(grep -E '"axios":' -A 5 "$file" 2>/dev/null | grep '"version"' | head -n 1 | awk -F '"' '{print $4}')
    elif [[ "$file" == *"yarn.lock" ]]; then
        AXIOS_VERSION=$(grep "axios@" -A 1 "$file" 2>/dev/null | grep "version" | head -n 1 | awk '{print $2}' | tr -d '"')
    fi

    for v in "${MALICIOUS_VERSIONS[@]}"; do
        if [[ "$AXIOS_VERSION" == "$v" ]]; then
            IS_VULN=true
            REASON="침해된 Axios 버전($AXIOS_VERSION) 사용"
        fi
    done

    # 취약점 발견 시 임시 파일에 기록 (while문 내부 변수 유지를 위해)
    if [ "$IS_VULN" = true ]; then
        echo "FOUND|$file|$REASON" >> "$OUTPUT.tmp"
    fi
    
    # 진행 표시
    if (( TOTAL_FILES % 20 == 0 )); then printf "."; fi
done

# 3. 결과 정리 및 출력
if [ -f "$OUTPUT.tmp" ]; then
    while IFS='|' read -r status path reason; do
        VULN_LIST+=("$path | 사유: $reason")
    done < "$OUTPUT.tmp"
    rm -f "$OUTPUT.tmp"
fi

echo -e "\n\n${BLUE}================  점검 완료 결과  ================${NC}"
# TOTAL_FILES 변수 수정을 위해 find 결과를 다시 카운트하거나 위 로직을 조정할 수 있으나, 
# 발견된 항목 위주로 명확히 보여주는 데 집중했습니다.

if [ ${#VULN_LIST[@]} -eq 0 ]; then
    echo -e "최종 상태: ${GREEN}✅ 안전 (취약점이 발견되지 않았습니다)${NC}"
else
    echo -e "최종 상태: ${RED}❌ 위험 (${#VULN_LIST[@]}개의 취약 항목 발견)${NC}"
    echo -e "\n${YELLOW}[취약한 파일 목록]${NC}"
    for item in "${VULN_LIST[@]}"; do
        echo -e " - $item"
    done

    echo -e "\n${RED}[❗ 긴급 조치 가이드]${NC}"
    echo -e "1. 의존성 초기화: 발견된 경로의 node_modules 및 lock 파일을 삭제하세요."
    echo -e "   (명령어: rm -rf node_modules package-lock.json yarn.lock)"
    echo -e "2. 안전 버전 설치: npm install axios@latest"
    echo -e "3. 캐시 삭제: npm cache clean --force"
    echo -e "4. 보안팀 보고: 해당 장비의 악성코드(RAT) 감염 여부 정밀 확인 필요"
fi
echo -e "${BLUE}==================================================${NC}"

# 최종 로그 저장
mv "$OUTPUT" "${OUTPUT}.bak" 2>/dev/null
echo "Audit Result - $(date)" > "$OUTPUT"
for item in "${VULN_LIST[@]}"; do echo "$item" >> "$OUTPUT"; done