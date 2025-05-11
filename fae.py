import tkinter as tk
from tkinter import filedialog
import subprocess
import hashlib
import webbrowser
import os

# ----------- 분석 기능 구현 -----------
def get_metadata(file_path):
    result = subprocess.run(['exiftool', file_path], capture_output=True, text=True)
    return result.stdout

# Magic number 정의 테이블
MAGIC_NUMBERS = {
    "png": bytes.fromhex("89504E470D0A1A0A"),
    "jpg": [
        bytes.fromhex("FFD8FFE0"),
        bytes.fromhex("FFD8FFDB"),
        bytes.fromhex("FFD8FFE1")
    ],
    "pdf": bytes.fromhex("25504446"),  # %PDF
    "gif": [
        bytes.fromhex("474946383761"),  # GIF87a
        bytes.fromhex("474946383961")   # GIF89a
    ],
    "exe": bytes.fromhex("4D5A"),       # MZ
    "hwp": bytes.fromhex("D0CF11E0A1B11AE1"),  # Old HWP
    "doc": bytes.fromhex("D0CF11E0A1B11AE1"),
    "xls": bytes.fromhex("D0CF11E0A1B11AE1"),
    "ppt": bytes.fromhex("D0CF11E0A1B11AE1"),
    "docx": bytes.fromhex("504B0304"),  # ZIP-based OOXML formats
    "xlsx": bytes.fromhex("504B0304"),
    "pptx": bytes.fromhex("504B0304"),
    "txt": b""  # 일반 텍스트는 별도 시그니처 없음
}

def identify_magic(file_path):
    with open(file_path, 'rb') as f:
        file_head = f.read(16)

    for ftype, magic in MAGIC_NUMBERS.items():
        if magic == b"":
            continue  # txt와 같은 포맷은 패스
        if isinstance(magic, list):
            for sig in magic:
                if file_head.startswith(sig):
                    return ftype, len(sig)
        else:
            if file_head.startswith(magic):
                return ftype, len(magic)
    return "unknown", 0

def get_hex_header(file_path, byte_count=64):
    try:
        with open(file_path, 'rb') as f:
            content = f.read(byte_count)

        file_type, magic_len = identify_magic(file_path)

        lines = []
        highlight_positions = []

        for i in range(0, len(content), 16):
            chunk = content[i:i+16]
            hex_bytes = []
            ascii_repr = []
            for j, b in enumerate(chunk):
                hex_bytes.append(f"{b:02x}")
                ascii_repr.append(chr(b) if 32 <= b <= 126 else '.')

            hex_str = ' '.join(hex_bytes)
            ascii_str = ''.join(ascii_repr)
            line = f"{i:08x}: {hex_str:<47}  {ascii_str}"

            for j in range(min(magic_len - i, 16) if i < magic_len else 0):
                start = 10 + j * 3
                end = start + 2
                highlight_positions.append((len(lines), start, end))

            lines.append(line)

        return '\n'.join(lines), highlight_positions, file_type

    except Exception as e:
        return f"⚠️ 오류 발생: {e}", [], "unknown"

def detect_suspicious_tags(metadata_text, detected_format, format_mismatch):
    actions = []
    if "HexEdit" in metadata_text or "HackerTool" in metadata_text:
        actions.append("⚠️ 수상한 툴로 생성됨. 파일을 열지 마세요.")
    if "GPS" in metadata_text:
        actions.append("⚠️ GPS 정보가 포함되어 있습니다.")
    if "Modify Date" in metadata_text and "Create Date" in metadata_text:
        actions.append("⚠️ 수정 시간과 생성 시간 간에 차이가 있습니다.")
    if detected_format in ["exe", "hwp"]:
        actions.append("⚠️ 민감한 실행 파일 또는 문서 형식입니다. 열기 전에 주의하세요.")
    if format_mismatch:
        actions.append("⚠️ 확장자와 Magic Number 기반 포맷이 다릅니다. 포맷 위조 가능성이 있습니다.")
    return actions

def get_sha256(file_path):
    with open(file_path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def open_virustotal(file_path):
    sha = get_sha256(file_path)
    url = f"https://www.virustotal.com/gui/file/{sha}"
    webbrowser.open(url)

# ----------- 포맷 검증 -----------
def check_format_mismatch(file_path, detected_by_hex, metadata_text):
    ext = os.path.splitext(file_path)[1][1:].lower()
    mime_line = next((line for line in metadata_text.splitlines() if "MIME Type" in line), None)
    filetype_line = next((line for line in metadata_text.splitlines() if "File Type" in line), None)

    issues = []
    mismatch = False

    if detected_by_hex == "unknown":
        issues.append("⚠️ Magic Number로 파일 포맷을 인식할 수 없습니다.")
        mismatch = True
    elif detected_by_hex != ext:
        issues.append(f"⚠️ 확장자 '{ext}'와(과) Magic Number 포맷 '{detected_by_hex}'가 불일치합니다. 원래 포맷은 '{detected_by_hex}'으로 보이며, 확장자를 변경하거나 파일을 열지 않는 것이 좋습니다.")
        mismatch = True
    else:
        issues.append(f"✅ 파일 확장자와 포맷 일치: {ext}")

    if filetype_line and detected_by_hex not in filetype_line.lower():
        key, val = filetype_line.split(':', 1)
        issues.append(f"⚠️ 메타데이터 File Type 항목 {key.strip()}: {val.strip()} 이(가) 실제 포맷 '{detected_by_hex}' 와 다를 수 있음")
        mismatch = True

    if mime_line and detected_by_hex not in mime_line.lower():
        key, val = mime_line.split(':', 1)
        issues.append(f"⚠️ 메타데이터 MIME Type 항목 {key.strip()}: {val.strip()} 이(가) 실제 포맷 '{detected_by_hex}' 와 다를 수 있음")
        mismatch = True

    return '\n'.join(issues), mismatch

# ----------- GUI 구성 -----------
def select_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    meta = get_metadata(file_path)
    hexdata, highlights, detected_format = get_hex_header(file_path)
    format_check, mismatch_flag = check_format_mismatch(file_path, detected_format, meta)
    suspicious_actions = detect_suspicious_tags(meta, detected_format, mismatch_flag)

    result_window.delete("1.0", tk.END)

    for idx, line in enumerate(hexdata.split('\n')):
        result_window.insert(tk.END, line + "\n")

    for line_idx, start_col, end_col in highlights:
        start = f"{line_idx + 1}.{start_col}"
        end = f"{line_idx + 1}.{end_col}"
        result_window.tag_add("highlight", start, end)

    result_window.insert(tk.END, f"\n[Metadata]\n{meta}\n")
    result_window.insert(tk.END, f"\n[포맷 검증]\n{format_check}\n")
    result_window.insert(tk.END, "\n[결과 요약]\n")
    if suspicious_actions:
        for action in suspicious_actions:
            result_window.insert(tk.END, action + "\n")
    else:
        result_window.insert(tk.END, "✅ 특이사항 없음. 파일 구조와 메타데이터가 일치합니다.\n")

    vt_button.config(command=lambda: open_virustotal(file_path))

# 메인 윈도우 생성
root = tk.Tk()
root.title("파일 조작 탐지기 - ExifTool 기반")
root.geometry("800x600")

select_button = tk.Button(root, text="파일 선택", command=select_file)
select_button.pack(pady=10)

result_window = tk.Text(root, height=30, font=("Consolas", 10))
result_window.tag_configure("highlight", background="yellow", foreground="black")
result_window.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

vt_button = tk.Button(root, text="VirusTotal로 검색")
vt_button.pack(pady=5)

root.mainloop()