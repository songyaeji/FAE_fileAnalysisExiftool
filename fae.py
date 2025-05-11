# 파일명: main.py
import tkinter as tk
from tkinter import filedialog
import subprocess
import hashlib
import webbrowser

# ----------- 분석 기능 구현 -----------
def get_metadata(file_path):
    result = subprocess.run(['exiftool', file_path], capture_output=True, text=True)
    return result.stdout

def get_hex_header(file_path, byte_count=64):
    result = subprocess.run(['xxd', '-l', str(byte_count), file_path], capture_output=True, text=True)
    return result.stdout

def detect_suspicious_tags(metadata_text):
    warnings = []
    if "HexEdit" in metadata_text or "HackerTool" in metadata_text:
        warnings.append("\u26a0\ufe0f 수상한 툴로 생성됨")
    if "GPS" in metadata_text:
        warnings.append("\u26a0\ufe0f GPS 정보 포함됨")
    if "Modify Date" in metadata_text and "Create Date" in metadata_text:
        warnings.append("\u26a0\ufe0f 수정 시간과 생성 시간 차이 발생 가능성 있음")
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
    hexdata = get_hex_header(file_path)
    warnings = detect_suspicious_tags(meta)

    result_window.delete("1.0", tk.END)
    result_window.insert(tk.END, f"[Hex Header]\n{hexdata}\n")
    result_window.insert(tk.END, f"\n[Metadata]\n{meta}\n")
    result_window.insert(tk.END, "\n[\uacbd\uace0 \ud0d0\uc9c0 \uacb0\uacfc]\n")
    for w in warnings:
        result_window.insert(tk.END, w + "\n")

    # VirusTotal 버튼 기능 재정의
    vt_button.config(command=lambda: open_virustotal(file_path))

# 메인 윈도우 생성
root = tk.Tk()
root.title("파일 조작 탐지기 - ExifTool 기반")
root.geometry("800x600")

select_button = tk.Button(root, text="\ud30c\uc77c \uc120\ud0dd", command=select_file)
select_button.pack(pady=10)

result_window = tk.Text(root, height=30, font=("Consolas", 10))
result_window.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

vt_button = tk.Button(root, text="VirusTotal\ub85c \uac80\uc0c9")
vt_button.pack(pady=5)

root.mainloop()