import tkinter as tk
from tkinter import filedialog
import subprocess
import hashlib
import webbrowser

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
    ]
}

def identify_magic(file_path):
    with open(file_path, 'rb') as f:
        file_head = f.read(16)  # 넉넉히 읽기

    for ftype, magic in MAGIC_NUMBERS.items():
        if isinstance(magic, list):
            for sig in magic:
                if file_head.startswith(sig):
                    return ftype, len(sig)
        else:
            if file_head.startswith(magic):
                return ftype, len(magic)
    return "unknown", 0

def get_hex_header(file_path, byte_count=64):
    """
    파일 앞부분을 hexdump 형태로 출력하고, 해당 포맷의 magic number 길이에 따라 색상 강조 위치 반환
    """
    try:
        with open(file_path, 'rb') as f:
            content = f.read(byte_count)

        file_type, magic_len = identify_magic(file_path)

        lines = []
        highlight_positions = []  # (line_idx, start_col, end_col)

        for i in range(0, len(content), 16):
            chunk = content[i:i+16]
            hex_bytes = []
            ascii_repr = []
            for j, b in enumerate(chunk):
                byte_offset = i + j
                hex_bytes.append(f"{b:02x}")
                ascii_repr.append(chr(b) if 32 <= b <= 126 else '.')

            hex_str = ' '.join(hex_bytes)
            ascii_str = ''.join(ascii_repr)
            line = f"{i:08x}: {hex_str:<47}  {ascii_str}"

            # 강조 위치 계산
            for j in range(min(magic_len - i, 16) if i < magic_len else 0):
                start = 10 + j * 3
                end = start + 2
                highlight_positions.append((len(lines), start, end))

            lines.append(line)

        return '\n'.join(lines), highlight_positions

    except Exception as e:
        return f"⚠️ 오류 발생: {e}", []

def detect_suspicious_tags(metadata_text):
    warnings = []
    if "HexEdit" in metadata_text or "HackerTool" in metadata_text:
        warnings.append("⚠️ 수상한 툴로 생성됨")
    if "GPS" in metadata_text:
        warnings.append("⚠️ GPS 정보 포함됨")
    if "Modify Date" in metadata_text and "Create Date" in metadata_text:
        warnings.append("⚠️ 수정 시간과 생성 시간 차이 발생 가능성 있음")
    return warnings

def get_sha256(file_path):
    with open(file_path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def open_virustotal(file_path):
    sha = get_sha256(file_path)
    url = f"https://www.virustotal.com/gui/file/{sha}"
    webbrowser.open(url)

# ----------- GUI 구성 -----------
def select_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    meta = get_metadata(file_path)
    hexdata, highlights = get_hex_header(file_path)
    warnings = detect_suspicious_tags(meta)

    result_window.delete("1.0", tk.END)

    for idx, line in enumerate(hexdata.split('\n')):
        result_window.insert(tk.END, line + "\n")

    for line_idx, start_col, end_col in highlights:
        start = f"{line_idx + 1}.{start_col}"
        end = f"{line_idx + 1}.{end_col}"
        result_window.tag_add("highlight", start, end)

    result_window.insert(tk.END, f"\n[Metadata]\n{meta}\n")
    result_window.insert(tk.END, "\n[경고 탐지 결과]\n")
    for w in warnings:
        result_window.insert(tk.END, w + "\n")

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