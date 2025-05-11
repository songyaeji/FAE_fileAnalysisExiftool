# 📁 ExifTool 기반 파일 조작 탐지 도구

이 도구는 ExifTool과 xxd를 활용하여 파일의 메타데이터 및 헤더를 시각적으로 분석하고,
수상한 조작 흔적을 표시해주는 입문자용 보안 분석 GUI 툴입니다.

## 🔧 기능 요약
- 파일 메타데이터 추출 (ExifTool 사용)
- 파일 헤더(hex) 시각 출력 (xxd 사용)
- 조작 의심 요소 탐지 (예: 수정 시간 불일치, 수상한 툴명, GPS 정보 포함 여부)
- VirusTotal 해시 기반 연동 (클릭 한 번으로 확인 가능)

## ✅ 사용법

### 1. 의존성 도구 설치
- `ExifTool`, `xxd`가 시스템에 설치되어 있어야 합니다.

#### Ubuntu/macOS:
```bash
sudo apt install exiftool xxd
```

#### Windows:
- https://exiftool.org/ 에서 Windows용 실행 파일 다운로드 후 PATH 설정

### 2. 실행
```bash
python main.py
```

파일을 선택하면 결과가 GUI로 표시됩니다.

## 🔗 VirusTotal 연동
- 분석 파일의 SHA256 해시를 계산하여
- VirusTotal 웹사이트에서 검색 결과 확인 가능

## 📁 파일 구성 예시
```
exiftool-analyzer/
├── main.py
├── requirements.txt
└── README.md
```

## ✨ 향후 개선 아이디어
- 다양한 파일 포맷 지원 (PDF, ZIP 등)
- 메타데이터 자동 비교 알고리즘
- 색상 기반 hex 시각화 추가 (matplotlib 활용)