__version__ = "1.0"
__author__ = "Mikan"
__license__ = "MIT"

import atexit
import requests
import os
import sys
import json
import base64
import fitz
import pygame
import lzma
import time
import tempfile
import shutil
import hashlib
import webbrowser
from pathlib import Path
import subprocess

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

import customtkinter as ctk
from tkinter import filedialog, messagebox, colorchooser, simpledialog
from PIL import Image, ImageTk

APP_MAGIC = b"MKND"
VERSION = 1

def derive_keys(password: str, salt: bytes, iterations: int = 200_000):
    key_material = PBKDF2(password.encode('utf-8'), salt, dkLen=64, count=iterations, hmac_hash_module=SHA256)
    return key_material[:32], key_material[32:64]

def compress_bytes(data: bytes) -> bytes:
    return lzma.compress(data)

def decompress_bytes(data: bytes) -> bytes:
    return lzma.decompress(data)

def encrypt_aes_gcm(key: bytes, plaintext: bytes):
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, ct, tag

def decrypt_aes_gcm(key: bytes, nonce: bytes, ct: bytes, tag: bytes):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)

def encrypt_chacha20(key: bytes, plaintext: bytes):
    nonce = get_random_bytes(12)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, ct, tag

def decrypt_chacha20(key: bytes, nonce: bytes, ct: bytes, tag: bytes):
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)

class MKNDContainer:
    @staticmethod
    def pack_files(file_paths, password, icon_path=None, iterations=200_000):
        container = {"files": {}, "created_at": int(time.time())}
        for path in file_paths:
            path = Path(path)
            with open(path, "rb") as f:
                raw = f.read()
            compressed = compress_bytes(raw)
            salt = get_random_bytes(16)
            aes_key, chacha_key = derive_keys(password, salt, iterations)
            aes_nonce, aes_ct, aes_tag = encrypt_aes_gcm(aes_key, compressed)
            ch_nonce, ch_ct, ch_tag = encrypt_chacha20(chacha_key, aes_ct)
            container["files"][path.name] = {
                "salt": base64.b64encode(salt).decode(),
                "iterations": iterations,
                "aes": {"nonce": base64.b64encode(aes_nonce).decode(),
                        "tag": base64.b64encode(aes_tag).decode()},
                "chacha": {"nonce": base64.b64encode(ch_nonce).decode(),
                           "tag": base64.b64encode(ch_tag).decode()},
                "ciphertext": base64.b64encode(ch_ct).decode(),
                "original_mtime": int(path.stat().st_mtime),
                "size": len(raw)
            }
        if icon_path:
            try:
                with open(icon_path,"rb") as f:
                    container["icon_b64"] = base64.b64encode(f.read()).decode()
                    container["icon_name"] = Path(icon_path).name
            except:
                pass
        return container

    @staticmethod
    def save_container(container, dest_path):
        meta_json = json.dumps(container, ensure_ascii=False).encode("utf-8")
        meta_len = len(meta_json)
        with open(dest_path, "wb") as f:
            f.write(APP_MAGIC)
            f.write(VERSION.to_bytes(4,"big"))
            f.write(meta_len.to_bytes(4,"big"))
            f.write(meta_json)

    @staticmethod
    def load(mkndec_path):
        with open(mkndec_path,"rb") as f:
            data = f.read()
        p=0
        if data[p:p+4] != APP_MAGIC:
            raise ValueError("Not a valid mkndec file")
        p+=4
        ver = int.from_bytes(data[p:p+4],"big"); p+=4
        meta_len = int.from_bytes(data[p:p+4],"big"); p+=4
        meta_json = data[p:p+meta_len]
        container = json.loads(meta_json.decode("utf-8"))
        return container

    @staticmethod
    def decrypt_file(filemeta, password):
        salt = base64.b64decode(filemeta["salt"])
        iterations = filemeta.get("iterations",200_000)
        aes_key, chacha_key = derive_keys(password, salt, iterations)
        ch_nonce = base64.b64decode(filemeta["chacha"]["nonce"])
        ch_tag = base64.b64decode(filemeta["chacha"]["tag"])
        aes_nonce = base64.b64decode(filemeta["aes"]["nonce"])
        aes_tag = base64.b64decode(filemeta["aes"]["tag"])
        ch_ct = base64.b64decode(filemeta["ciphertext"])
        aes_ct = decrypt_chacha20(chacha_key, ch_nonce, ch_ct, ch_tag)
        compressed = decrypt_aes_gcm(aes_key, aes_nonce, aes_ct, aes_tag)
        return decompress_bytes(compressed)

    @staticmethod
    def update_file_bytes_in_container(container, filename, new_bytes, password, iterations=200_000):
        compressed = compress_bytes(new_bytes)
        salt = get_random_bytes(16)
        aes_key, chacha_key = derive_keys(password, salt, iterations)
        aes_nonce, aes_ct, aes_tag = encrypt_aes_gcm(aes_key, compressed)
        ch_nonce, ch_ct, ch_tag = encrypt_chacha20(chacha_key, aes_ct)
        container["files"][filename] = {
            "salt": base64.b64encode(salt).decode(),
            "iterations": iterations,
            "aes": {"nonce": base64.b64encode(aes_nonce).decode(),
                    "tag": base64.b64encode(aes_tag).decode()},
            "chacha": {"nonce": base64.b64encode(ch_nonce).decode(),
                       "tag": base64.b64encode(ch_tag).decode()},
            "ciphertext": base64.b64encode(ch_ct).decode(),
            "original_mtime": int(time.time()),
            "size": len(new_bytes)
        }
        return container

    @staticmethod
    def rename_file_in_container(container, old_name, new_name):
        if old_name not in container["files"]:
            raise KeyError("old_name not found")
        if new_name in container["files"]:
            raise KeyError("new_name already exists")
        container["files"][new_name] = container["files"].pop(old_name)
        return container

class MKNDecApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.file_paths = []
        self.icon_file = None
        self.loaded_package_path = None
        self.loaded_package_meta = None
        self.restored_bytes = None
        self.palette_color = "#1abc9c"
        self.current_image_label = None

        self.title("MKNDCrypter")

        # GitHubからアイコンをダウンロードして設定
        self.icon_file = self.download_icon_temp(
            "https://raw.githubusercontent.com/mikan2ndyeeeeeeey-svg/MKNDCrypter/main/icon.ico"
        )
        try:
            self.iconbitmap(self.icon_file)
        except Exception as e:
            print(f"アイコン設定失敗: {e}")

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self._create_widgets()
        self.after(10, lambda: self.state("zoomed"))

    def download_icon_temp(self, url: str) -> str:
        """GitHub から icon.ico をダウンロードして実行フォルダに置き、終了時に削除"""
        icon_path = Path.cwd() / "icon.ico"
        try:
            r = requests.get(url)
            r.raise_for_status()
            with open(icon_path, "wb") as f:
                f.write(r.content)
            # プログラム終了時に削除
            atexit.register(lambda: icon_path.unlink(missing_ok=True))
        except Exception as e:
            print("アイコンダウンロード失敗:", e)
        return str(icon_path)

    def _create_widgets(self):
        left = ctk.CTkFrame(self, width=460)
        left.pack(side="left", fill="both", expand=False, padx=12, pady=12)
        ctk.CTkLabel(left, text="Create .mkndec (Pack)", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(6,8))
        self.file_label = ctk.CTkLabel(left, text="選択ファイル: なし", anchor="w")
        self.file_label.pack(fill="x", padx=8, pady=4)
        ctk.CTkButton(left, text="ファイルを選択", command=self.select_source_file).pack(padx=8, pady=4)
        ctk.CTkButton(left, text="アイコンを選択", command=self.select_icon).pack(padx=8, pady=4)
        self.password_entry = ctk.CTkEntry(left, placeholder_text="パスワード（Pack/Unpack共通）", show="*")
        self.password_entry.pack(fill="x", padx=8, pady=4)
        self.savepath_entry = ctk.CTkEntry(left, placeholder_text="保存先ディレクトリを選択")
        self.savepath_entry.pack(fill="x", padx=8, pady=4)
        ctk.CTkButton(left, text="保存先選択", command=self.select_save_dir).pack(padx=8, pady=4)
        ctk.CTkButton(left, text="Create .mkndec を作成", command=self.create_mkndec).pack(padx=8, pady=8)

        right = ctk.CTkFrame(self)
        right.pack(side="right", fill="both", expand=True, padx=12, pady=12)
        ctk.CTkLabel(right, text="Open .mkndec (Unpack / View / Edit)", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(6,8))
        ctk.CTkButton(right, text=".mkndec のあるディレクトリを選択", command=self.select_mkndec_dir).pack(padx=8, pady=6)
        self.combobox_mkndec = ctk.CTkComboBox(right, values=[], width=600)
        self.combobox_mkndec.pack(fill="x", padx=8, pady=4)
        ctk.CTkButton(right, text="開く", command=self.open_selected_mkndec).pack(padx=8, pady=4)
        self.combobox_files = ctk.CTkComboBox(right, values=[], width=600)
        self.combobox_files.pack(fill="x", padx=8, pady=4)
        actions_row = ctk.CTkFrame(right)
        actions_row.pack(fill="x", padx=8, pady=4)
        ctk.CTkButton(actions_row, text="プレビュー/編集", command=self.preview_file).pack(side="left", padx=6)
        ctk.CTkButton(actions_row, text="復元して保存", command=self.restore_file_to_disk).pack(side="left", padx=6)
        ctk.CTkButton(actions_row, text="変更をパッケージに保存", command=self.save_changes_to_package).pack(side="left", padx=6)
        ctk.CTkButton(actions_row, text="名前変更 (リネーム)", command=self.rename_selected_file).pack(side="left", padx=6)
        ctk.CTkButton(actions_row, text="インポート (追加)", command=self.import_new_file).pack(side="left", padx=6)
        ctk.CTkButton(actions_row, text="ファイル削除", command=self.delete_selected_file).pack(side="left", padx=6)
        self.run_file_button = ctk.CTkButton(actions_row, text="実行", command=self.run_selected_file)
        self.run_file_button.pack(side="left", padx=6)
        self.viewer_area = ctk.CTkFrame(right)
        self.viewer_area.pack(fill="both", expand=True, padx=8, pady=8)
        self.viewer_text = ctk.CTkTextbox(self.viewer_area)
        self.viewer_image_label = None
        bottom = ctk.CTkFrame(self, height=60)
        bottom.pack(side="bottom", fill="x", padx=12, pady=6)
        self.mode_switch = ctk.CTkSwitch(
        bottom,
        text="ライトモード",
        command=self.toggle_mode,
        font=ctk.CTkFont(size=14, weight="bold")
    )
        self.mode_switch.pack(side="left", padx=8) 
        self.color_btn = ctk.CTkButton(bottom, text="アクセント色を選択", command=self.change_palette)
        self.color_btn.pack(side="left", padx=8)

        def open_link(url):
            import webbrowser
            webbrowser.open(url)

        link_frame = ctk.CTkFrame(bottom)
        link_frame.pack(side="right", padx=8)
        bold_font = ctk.CTkFont(size=14, weight="bold")
        link_label = ctk.CTkLabel(link_frame, text="Github", cursor="hand2", text_color="#1abc9c", font=bold_font)
        link_label.pack(side="right", padx=4)
        link_label.bind("<Button-1>", lambda e: open_link("https://github.com/mikan2ndyeeeeeeey-svg/MKNDCrypter"))
        discord_label = ctk.CTkLabel(link_frame, text="Discord", cursor="hand2", text_color="#7289da", font=bold_font)
        discord_label.pack(side="right", padx=4)
        discord_label.bind("<Button-1>", lambda e: open_link("https://discord.gg/BgM77WshrK"))

    def select_source_file(self):
        paths = filedialog.askopenfilenames(title="ファイル選択")
        if paths:
            self.file_paths = paths
            self.file_label.configure(text=f"{len(paths)} ファイル選択済み")

    def select_icon(self):
        path = filedialog.askopenfilename(filetypes=[("ICO files","*.ico"),("All files","*.*")])
        if path:
            self.icon_file = path
            messagebox.showinfo("アイコン選択", f"{path} を選択しました")

    def select_save_dir(self):
        dir_path = filedialog.askdirectory(title="保存先ディレクトリ選択")
        if dir_path:
            self.savepath_entry.delete(0,"end")
            self.savepath_entry.insert(0, dir_path)

    def create_mkndec(self):
        if not self.file_paths:
            messagebox.showwarning("未選択", "ファイルを選択してください")
            return
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("パスワード必須", "パスワードを入力してください")
            return
        save_dir = self.savepath_entry.get().strip() or os.getcwd()
        save_path = Path(save_dir) / "package.mkndec"
        container = MKNDContainer.pack_files(self.file_paths, password, self.icon_file)
        MKNDContainer.save_container(container, save_path)
        messagebox.showinfo("完了", f"{save_path} に保存しました")

    def select_mkndec_dir(self):
        dir_path = filedialog.askdirectory(title=".mkndec があるディレクトリを選択")
        if not dir_path:
            return
        mknd_files = [str(Path(dir_path)/f) for f in os.listdir(dir_path) if f.endswith(".mkndec")]
        if not mknd_files:
            messagebox.showinfo("情報", ".mkndec ファイルが見つかりませんでした")
            self.combobox_mkndec.configure(values=[])
            self.combobox_mkndec.set("")
            return
        self.combobox_mkndec.configure(values=mknd_files)
        self.combobox_mkndec.set(mknd_files[0])
        self.combobox_mkndec.update()

    def open_selected_mkndec(self):
        path = self.combobox_mkndec.get()
        if not path:
            return
        try:
            meta = MKNDContainer.load(path)
            self.loaded_package_meta = meta
            self.loaded_package_path = path
            files = list(meta["files"].keys())
            self.combobox_files.configure(values=files)
            if files:
                self.combobox_files.set(files[0])
            self.combobox_files.update()
            messagebox.showinfo("完了", f"{len(files)} ファイルを読み込みました")
        except Exception as e:
            messagebox.showerror("エラー", str(e))

    def require_password_or_prompt(self):
        pw = self.password_entry.get().strip()
        if not pw:
            pw = simpledialog.askstring("パスワード入力", "パッケージのパスワードを入力してください", show="*")
        return pw

    def preview_file(self):
        try:
            if not self.loaded_package_meta:
                messagebox.showwarning("未選択", ".mkndec を読み込んでください")
                return
            
            fname = self.combobox_files.get()
            if not fname:
                messagebox.showwarning("未選択", "パッケージ内ファイルを選択してください")
                return
                
            password = self.require_password_or_prompt()
            if not password:
                messagebox.showwarning("パスワード必須", "パスワードを必要とします")
                return
                
            filemeta = self.loaded_package_meta["files"].get(fname)
            if not filemeta:
                messagebox.showerror("エラー", "ファイル情報が見つかりません")
                return
                
            data = MKNDContainer.decrypt_file(filemeta, password)
            self.restored_bytes = data
            ext = Path(fname).suffix.lower()

            for w in self.viewer_area.winfo_children():
                w.destroy()

            if ext in [".txt",".py",".md",".json",".csv",".log",".ini"]:
                self.viewer_text = ctk.CTkTextbox(self.viewer_area)
                self.viewer_text.pack(fill="both", expand=True, padx=6, pady=6)
                text = data.decode("utf-8", errors="replace")
                self.viewer_text.insert("0.0", text)

            elif ext in [".png",".jpg",".jpeg",".bmp",".gif",".webp"]:
                tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=ext)
                tmp_file.write(data)
                tmp_file.close()
                img = Image.open(tmp_file.name)
                img.thumbnail((800, 800))
                photo = ImageTk.PhotoImage(img)
                lbl = ctk.CTkLabel(self.viewer_area, image=photo)
                lbl.image = photo
                lbl.pack(expand=True)
                try:
                    os.unlink(tmp_file.name)
                except:
                    pass

            elif ext == ".pdf":
                tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
                doc = fitz.open(stream=data, filetype="pdf")
                page = doc[0]
                pix = page.get_pixmap()
                pix.save(tmp_file.name)
                img = Image.open(tmp_file.name)
                img.thumbnail((800, 800))
                photo = ImageTk.PhotoImage(img)
                lbl = ctk.CTkLabel(self.viewer_area, image=photo)
                lbl.image = photo
                lbl.pack(expand=True)
                try:
                    os.unlink(tmp_file.name)
                except:
                    pass

            elif ext in [".mp3", ".wav"]:
                tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=ext)
                tmp_file.write(data)
                tmp_file.close()
                
                def play_audio():
                    pygame.mixer.init()
                    pygame.mixer.music.load(tmp_file.name)
                    pygame.mixer.music.play()
                
                btn = ctk.CTkButton(self.viewer_area, text="再生", command=play_audio)
                btn.pack(pady=20)
                atexit.register(lambda: os.unlink(tmp_file.name))

            else:
                lbl = ctk.CTkLabel(self.viewer_area, text=f"{len(data)} bytes (プレビュー非対応)")
                lbl.pack(expand=True)

        except Exception as e:
            messagebox.showerror("エラー", f"プレビューに失敗しました: {e}")

    def save_changes_to_package(self):
        if not self.loaded_package_meta or not self.loaded_package_path:
            messagebox.showwarning("未選択", ".mkndec を読み込んでください")
            return
        fname = self.combobox_files.get()
        if not fname:
            messagebox.showwarning("未選択", "パッケージ内ファイルを選択してください")
            return
        data_to_save = None
        for w in self.viewer_area.winfo_children():
            try:
                text = w.get("0.0", "end-1c")
                data_to_save = text.encode("utf-8")
                break
            except Exception:
                continue
        if data_to_save is None:
            if self.restored_bytes is None:
                messagebox.showwarning("未保存", "編集データが見つかりません")
                return
            data_to_save = self.restored_bytes
        password = self.require_password_or_prompt()
        if not password:
            messagebox.showwarning("パスワード必須", "パスワードを必要とします")
            return
        try:
            MKNDContainer.update_file_bytes_in_container(self.loaded_package_meta, fname, data_to_save, password)
            MKNDContainer.save_container(self.loaded_package_meta, self.loaded_package_path)
            messagebox.showinfo("保存完了", f"{fname} の変更をパッケージに保存しました")
        except Exception as e:
            messagebox.showerror("保存エラー", str(e))

    def rename_selected_file(self):
        if not self.loaded_package_meta or not self.loaded_package_path:
            messagebox.showwarning("未選択", ".mkndec を読み込んでください")
            return
        old = self.combobox_files.get()
        if not old:
            return
        new = simpledialog.askstring("名前変更", "新しいファイル名を入力してください（拡張子を含む）", initialvalue=old)
        if not new:
            return
        try:
            MKNDContainer.rename_file_in_container(self.loaded_package_meta, old, new)
            MKNDContainer.save_container(self.loaded_package_meta, self.loaded_package_path)
            files = list(self.loaded_package_meta["files"].keys())
            self.combobox_files.configure(values=files)
            self.combobox_files.set(new)
            messagebox.showinfo("完了", f"{old} を {new} にリネームしました")
        except Exception as e:
            messagebox.showerror("リネーム失敗", str(e))

    def import_new_file(self):
        if not self.loaded_package_meta or not self.loaded_package_path:
            messagebox.showwarning("未選択", ".mkndec を読み込んでください")
            return
        paths = filedialog.askopenfilenames(title="追加するファイルを選択")
        if not paths:
            return
        password = self.require_password_or_prompt()
        if not password:
            messagebox.showwarning("パスワード必須", "パスワードを入力してください")
            return
        added = 0
        try:
            for p in paths:
                p = Path(p)
                base = p.name
                name, ext = os.path.splitext(base)
                final_name = base
                counter = 1
                while final_name in self.loaded_package_meta["files"]:
                    final_name = f"{name}({counter}){ext}"
                    counter += 1
                tmp_container = MKNDContainer.pack_files([p], password)
                file_entry = tmp_container["files"].pop(p.name)
                self.loaded_package_meta["files"][final_name] = file_entry
                added += 1
            MKNDContainer.save_container(self.loaded_package_meta, self.loaded_package_path)
            files = list(self.loaded_package_meta["files"].keys())
            self.combobox_files.configure(values=files)
            if files:
                self.combobox_files.set(files[-1])
            messagebox.showinfo("追加完了", f"{added} ファイルを追加しました")
        except Exception as e:
            messagebox.showerror("インポート失敗", str(e))

    def delete_selected_file(self):
        if not self.loaded_package_meta or not self.loaded_package_path:
            messagebox.showwarning("未選択", ".mkndec を読み込んでください")
            return
        fname = self.combobox_files.get()
        if not fname:
            messagebox.showwarning("未選択", "削除するファイルを選択してください")
            return
        confirm = messagebox.askyesno("確認", f"パッケージから {fname} を削除しますか？")
        if not confirm:
            return
        try:
            if fname in self.loaded_package_meta["files"]:
                del self.loaded_package_meta["files"][fname]
                MKNDContainer.save_container(self.loaded_package_meta, self.loaded_package_path)
                files = list(self.loaded_package_meta["files"].keys())
                self.combobox_files.configure(values=files)
                self.combobox_files.set(files[0] if files else "")
                self.restored_bytes = None
                for w in self.viewer_area.winfo_children():
                    w.destroy()
                messagebox.showinfo("削除完了", f"{fname} を削除しました")
            else:
                messagebox.showerror("エラー", f"{fname} は見つかりませんでした")
        except Exception as e:
            messagebox.showerror("削除失敗", str(e))

    def restore_file_to_disk(self):
        if not self.restored_bytes:
            messagebox.showwarning("未選択", "先にプレビューして復号してください")
            return
        save_path = filedialog.asksaveasfilename(title="復元先を選択", initialfile=self.combobox_files.get())
        if save_path:
            with open(save_path,"wb") as f:
                f.write(self.restored_bytes)
            messagebox.showinfo("保存完了", f"{save_path} に保存しました")

    def run_selected_file(self):
        fname = self.combobox_files.get()
        if not fname:
            return
        if self.restored_bytes is None:
            messagebox.showwarning("未復号", "先にプレビューして復号してください")
            return
        ext = Path(fname).suffix.lower()
        if ext not in [".exe",".py",".bat",".cmd"]:
            messagebox.showwarning("実行不可", "このファイルは実行できません")
            return
        tmp_dir = Path(tempfile.gettempdir()) / "mkndec_run"
        tmp_dir.mkdir(exist_ok=True)
        tmp_path = tmp_dir / fname
        with open(tmp_path, "wb") as f:
            f.write(self.restored_bytes)
        try:
            if ext == ".py":
                subprocess.Popen([sys.executable, str(tmp_path)])
            else:
                subprocess.Popen(str(tmp_path), shell=True)
            messagebox.showinfo("実行", "ファイルを実行しました（実行中）")
        except Exception as e:
            messagebox.showerror("実行エラー", str(e))

    def toggle_mode(self):
        if self.mode_switch.get():
            ctk.set_appearance_mode("light")
            self.mode_switch.configure(text="ダークモード")
        else:
            ctk.set_appearance_mode("dark")
            self.mode_switch.configure(text="ライトモード")

    def change_palette(self):
        color = colorchooser.askcolor(title="アクセント色を選択")
        if color and color[1]:
            self.palette_color = color[1]

if __name__ == "__main__":
    app = MKNDecApp()
    app.mainloop()
