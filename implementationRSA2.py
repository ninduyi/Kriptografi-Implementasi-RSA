"""
=============================================================================
SISTEM SLIP GAJI DIGITAL TERENKRIPSI BERBASIS RSA (MANUAL DARI NOL)
Mata Kuliah: Kriptografi
Implementasi: RSA Murni (Tanpa Library Kripto Eksternal) + GUI Tkinter
=============================================================================
"""

import sys
import os
import json
import random
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime

# =============================================================================
# BAGIAN 1: RSA MATH ENGINE (DIKERJAKAN SECARA MANUAL DARI TEORI BILANGAN)
# =============================================================================

class RSAMathEngine:
    """
    Mesin Komputasi Teori Bilangan RSA:
    - gcd & Extended Euclidean Algorithm
    - Modular Exponentiation (Square-and-Multiply)
    - Miller-Rabin Primality Test
    - Byte Chunking / Data Blocking
    """

    @staticmethod
    def gcd(a: int, b: int) -> int:
        """Menghitung Pembagi Bersama Terbesar (PBB) dengan Algoritma Euclidean."""
        while b != 0:
            a, b = b, a % b
        return a

    @staticmethod
    def extended_gcd(a: int, b: int):
        """
        Extended Euclidean Algorithm:
        Mencari kombinasi linier: a*x + b*y = gcd(a, b)
        """
        if a == 0:
            return b, 0, 1
        gcd_val, x1, y1 = RSAMathEngine.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd_val, x, y

    @staticmethod
    def mod_inverse(e: int, phi: int) -> int:
        """
        Menghitung Private Key d sebagai balikan modulo (modular inverse):
        e * d = 1 (mod phi)
        """
        gcd_val, x, _ = RSAMathEngine.extended_gcd(e, phi)
        if gcd_val != 1:
            raise ValueError("Balikan modulo tidak ditemukan. e dan phi tidak relatif prima.")
        return (x % phi + phi) % phi

    @staticmethod
    def mod_pow(base: int, exp: int, mod: int) -> int:
        """
        Metode Pemangkatan Modular Efisien (Square-and-Multiply).
        Kompleksitas O(log exp), mencegah memori meluap (overflow).
        """
        result = 1
        base = base % mod
        while exp > 0:
            if exp % 2 == 1:
                result = (result * base) % mod
            exp = exp // 2
            base = (base * base) % mod
        return result

    @staticmethod
    def is_prime_miller_rabin(n: int, k: int = 12) -> bool:
        """Uji Keprimaan Miller-Rabin manual terhadap bilangan bulat n."""
        if n < 2:
            return False
        if n in (2, 3):
            return True
        if n % 2 == 0:
            return False

        # Tulis n - 1 = 2^s * d
        d = n - 1
        s = 0
        while d % 2 == 0:
            d //= 2
            s += 1

        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = RSAMathEngine.mod_pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            
            composite = True
            for _ in range(s - 1):
                x = RSAMathEngine.mod_pow(x, 2, n)
                if x == n - 1:
                    composite = False
                    break
            if composite:
                return False
        return True

    @staticmethod
    def generate_prime(bits: int = 64) -> int:
        """Membangkitkan bilangan prima acak sebesar n-bit."""
        small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
        while True:
            p = random.getrandbits(bits) | (1 << (bits - 1)) | 1
            if any(p % sp == 0 and p != sp for sp in small_primes):
                continue
            if RSAMathEngine.is_prime_miller_rabin(p):
                return p

    @classmethod
    def generate_keypair(cls, bits: int = 64):
        """
        Membangkitkan pasangan kunci RSA lengkap:
        Output: p, q, n, phi, e, d
        """
        p = cls.generate_prime(bits)
        q = cls.generate_prime(bits)
        while p == q:
            q = cls.generate_prime(bits)

        n = p * q
        phi = (p - 1) * (q - 1)

        # Pemilihan Public Key e standar
        e = 65537
        if cls.gcd(e, phi) != 1:
            e = 3
            while cls.gcd(e, phi) != 1:
                e += 2

        d = cls.mod_inverse(e, phi)
        return p, q, n, phi, e, d

    @classmethod
    def encrypt_bytes(cls, plaintext_bytes: bytes, e: int, n: int):
        """
        Membagi data byte ke dalam blok mi < n, lalu mengenkripsi:
        ci = (mi ^ e) mod n
        """
        block_size = max(1, (n.bit_length() - 1) // 8)
        ciphertext_blocks = []
        block_metadata = []

        for i in range(0, len(plaintext_bytes), block_size):
            chunk = plaintext_bytes[i:i + block_size]
            m_int = int.from_bytes(chunk, byteorder='big')
            c_int = cls.mod_pow(m_int, e, n)
            ciphertext_blocks.append(str(c_int))
            block_metadata.append({
                "index": i // block_size,
                "byte_len": len(chunk),
                "m_int": m_int,
                "c_int": c_int
            })

        return ciphertext_blocks, block_size, block_metadata

    @classmethod
    def decrypt_bytes(cls, ciphertext_blocks: list, block_sizes: list, d: int, n: int):
        """
        Mendekripsi setiap blok:
        mi = (ci ^ d) mod n
        Lalu merekonstruksi untaian byte utuh.
        """
        decrypted_bytes = bytearray()
        trace_blocks = []

        for idx, (c_str, b_len) in enumerate(zip(ciphertext_blocks, block_sizes)):
            c_int = int(c_str)
            m_int = cls.mod_pow(c_int, d, n)
            chunk = m_int.to_bytes(b_len, byteorder='big')
            decrypted_bytes.extend(chunk)
            trace_blocks.append({
                "index": idx,
                "c_int": c_int,
                "m_int": m_int,
                "byte_len": b_len
            })

        return bytes(decrypted_bytes), trace_blocks


# =============================================================================
# BAGIAN 2: ANTARMUKA GRAFIS PENGGUNA (TKINTER GUI)
# =============================================================================

class SecurePayrollApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Sistem Pengamanan Slip Gaji - Kriptografi Asimetris RSA")
        self.geometry("1060x800")
        self.minsize(940, 700)

        self.current_keys = {
            "p": None, "q": None, "n": None, "phi": None, "e": None, "d": None
        }
        self.loaded_encrypted_data = None

        self._configure_styles()
        self._build_ui()

    def _configure_styles(self):
        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self.style.configure(".", font=("Segoe UI", 9))
        self.style.configure("TNotebook.Tab", font=("Segoe UI", 10, "bold"), padding=[14, 6])
        self.style.configure("Accent.TButton", font=("Segoe UI", 9, "bold"), background="#1d4ed8", foreground="white")
        self.style.map("Accent.TButton", background=[("active", "#1e40af")])
        self.style.configure("Success.TButton", font=("Segoe UI", 9, "bold"), background="#047857", foreground="white")
        self.style.map("Success.TButton", background=[("active", "#065f46")])

    def _build_ui(self):
        # Header Utama
        header = tk.Frame(self, bg="#0f172a", height=72)
        header.pack(fill=tk.X, side=tk.TOP)
        header.pack_propagate(False)

        lbl_title = tk.Label(
            header, text="SISTEM DISTRIBUSI SLIP GAJI TERENKRIPSI (RSA ENGINE)",
            font=("Segoe UI", 13, "bold"), fg="#f8fafc", bg="#0f172a"
        )
        lbl_title.pack(anchor=tk.W, padx=20, pady=(12, 2))

        lbl_sub = tk.Label(
            header, text="Implementasi Kriptografi Public Key Manual: Kerahasiaan Data Payroll HRD ke Karyawan",
            font=("Segoe UI", 9), fg="#94a3b8", bg="#0f172a"
        )
        lbl_sub.pack(anchor=tk.W, padx=20)

        # Tab Kontrol
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)

        self.tab_karyawan = ttk.Frame(self.notebook, padding=12)
        self.tab_hrd = ttk.Frame(self.notebook, padding=12)
        self.tab_inspector = ttk.Frame(self.notebook, padding=12)

        self.notebook.add(self.tab_karyawan, text=" 👤 Portal Karyawan ")
        self.notebook.add(self.tab_hrd, text=" 🏢 Portal HRD")
        self.notebook.add(self.tab_inspector, text=" 🔬 RSA Math Inspector ")

        self._build_karyawan_tab()
        self._build_hrd_tab()
        self._build_inspector_tab()

    # -------------------------------------------------------------------------
    # TAB 1: PORTAL KARYAWAN
    # -------------------------------------------------------------------------
    def _build_karyawan_tab(self):
        paned = ttk.PanedWindow(self.tab_karyawan, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        left_side = ttk.Frame(paned, padding=(0, 0, 10, 0))
        right_side = ttk.Frame(paned, padding=(10, 0, 0, 0))
        paned.add(left_side, weight=1)
        paned.add(right_side, weight=1)

        # Manajemen Kunci Karyawan
        box_key = ttk.LabelFrame(left_side, text=" 1. Generator Pasangan Kunci RSA Karyawan ", padding=10)
        box_key.pack(fill=tk.X, pady=(0, 10))

        bar_btn = ttk.Frame(box_key)
        bar_btn.pack(fill=tk.X, pady=(0, 6))

        ttk.Button(bar_btn, text="🔑 Generate New Key (64-bit)", style="Accent.TButton",
                   command=self._handle_generate_keys).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(bar_btn, text="💾 Ekspor Kunci (.json)", command=self._handle_save_keys).pack(side=tk.LEFT)

        ttk.Label(box_key, text="Public Key (e, n)").pack(anchor=tk.W, pady=(4, 0))
        self.txt_emp_pub = tk.Text(box_key, height=3, font=("Consolas", 8), bg="#f8fafc", wrap=tk.CHAR)
        self.txt_emp_pub.pack(fill=tk.X, pady=(2, 6))

        ttk.Label(box_key, text="Private Key (d, n)").pack(anchor=tk.W)
        self.txt_emp_priv = tk.Text(box_key, height=3, font=("Consolas", 8), bg="#fef2f2", wrap=tk.CHAR)
        self.txt_emp_priv.pack(fill=tk.X, pady=(2, 4))

        # Dekripsi File
        box_dec = ttk.LabelFrame(left_side, text=" 2. Dekripsi Dokumen Slip Gaji (.enc) ", padding=10)
        box_dec.pack(fill=tk.BOTH, expand=True)

        ttk.Button(box_dec, text="📂 Load File Terenkripsi (.enc)", command=self._handle_load_enc_file).pack(anchor=tk.W, pady=(0, 4))
        self.lbl_enc_file_info = ttk.Label(box_dec, text="Status File: Belum ada File diload", foreground="#64748b")
        self.lbl_enc_file_info.pack(anchor=tk.W, pady=(0, 8))

        ttk.Label(box_dec, text="Private Key Dekripsi (d):").pack(anchor=tk.W)
        self.ent_dec_d = ttk.Entry(box_dec, font=("Consolas", 9))
        self.ent_dec_d.pack(fill=tk.X, pady=(2, 6))

        ttk.Label(box_dec, text="Modulus (n):").pack(anchor=tk.W)
        self.ent_dec_n = ttk.Entry(box_dec, font=("Consolas", 9))
        self.ent_dec_n.pack(fill=tk.X, pady=(2, 10))

        ttk.Button(box_dec, text="🔓 Dekripsi & Validasi Slip Gaji", style="Success.TButton",
                   command=self._handle_decrypt_payroll).pack(fill=tk.X, ipady=4)

        # Pratinjau Slip Gaji
        box_view = ttk.LabelFrame(right_side, text=" 3. Preview Dokumen Slip Gaji ", padding=10)
        box_view.pack(fill=tk.BOTH, expand=True)

        self.txt_slip_display = tk.Text(box_view, font=("Courier New", 9), bg="#ffffff", fg="#0f172a", wrap=tk.NONE)
        scroll_v = ttk.Scrollbar(box_view, orient=tk.VERTICAL, command=self.txt_slip_display.yview)
        self.txt_slip_display.configure(yscrollcommand=scroll_v.set)
        
        scroll_v.pack(side=tk.RIGHT, fill=tk.Y)
        self.txt_slip_display.pack(fill=tk.BOTH, expand=True)
        self._display_blank_payroll_template()

    # -------------------------------------------------------------------------
    # TAB 2: PORTAL HRD (DILENGKAPI FORMAT NOMINAL TITIK)
    # -------------------------------------------------------------------------
    def _build_hrd_tab(self):
        container = ttk.Frame(self.tab_hrd)
        container.pack(fill=tk.BOTH, expand=True)

        # Form Entri Data Gaji
        col_form = ttk.LabelFrame(container, text=" Formulir Komponen Gaji Karyawan (HRD) ", padding=12)
        col_form.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))

        # Konfigurasi Input: label, field_name, default_value, is_numeric
        specs = [
            ("NIK Karyawan", "nik", "IT-2024-001", False),
            ("Nama Lengkap", "nama", "Ahmad Fauzan", False),
            ("Jabatan / Posisi", "jabatan", "Senior Network & Security Engineer", False),
            ("Periode Penggajian", "periode", "Oktober 2026", False),
            ("Gaji Pokok (Rp)", "gaji_pokok", "12.500.000", True),
            ("Tunjangan Operasional (Rp)", "tunjangan", "3.500.000", True),
            ("Potongan BPJS (Rp)", "potongan_bpjs", "450.000", True),
            ("Potongan Pajak PPh 21 (Rp)", "potongan_pph", "650.000", True),
            ("Catatan HRD", "catatan", "Semoga berkah!.", False)
        ]

        self.hrd_entries = {}
        for row_idx, (lbl_txt, f_name, def_val, is_num) in enumerate(specs):
            ttk.Label(col_form, text=lbl_txt + ":").grid(row=row_idx, column=0, sticky=tk.W, pady=4, padx=4)
            ent = ttk.Entry(col_form, font=("Segoe UI", 9))
            ent.insert(0, def_val)
            ent.grid(row=row_idx, column=1, sticky=tk.EW, pady=4, padx=4)

            # Event format ribuan langsung saat diketik
            if is_num:
                ent.bind("<KeyRelease>", self._format_currency_on_release)

            self.hrd_entries[f_name] = ent

        col_form.columnconfigure(1, weight=1)

        # Sisi Kanan: Public Key & Eksekusi Enkripsi
        col_ops = ttk.Frame(container)
        col_ops.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(8, 0))

        box_target_key = ttk.LabelFrame(col_ops, text=" Public Key Karyawan", padding=10)
        box_target_key.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(box_target_key, text="Eksponen Publik (e):").pack(anchor=tk.W)
        self.ent_hrd_e = ttk.Entry(box_target_key, font=("Consolas", 9))
        self.ent_hrd_e.pack(fill=tk.X, pady=(2, 6))

        ttk.Label(box_target_key, text="Modulus (n):").pack(anchor=tk.W)
        self.ent_hrd_n = ttk.Entry(box_target_key, font=("Consolas", 9))
        self.ent_hrd_n.pack(fill=tk.X, pady=(2, 8))

        ttk.Button(box_target_key, text="📥 Salin Otomatis dari Tab Karyawan",
                   command=self._handle_copy_keys_to_hrd).pack(fill=tk.X)

        box_enc_action = ttk.LabelFrame(col_ops, text=" Operasi Enkripsi RSA ", padding=10)
        box_enc_action.pack(fill=tk.BOTH, expand=True)

        ttk.Button(box_enc_action, text="🔒 Enkripsi Data Slip Gaji Sekarang", style="Accent.TButton",
                   command=self._handle_encrypt_payroll).pack(fill=tk.X, ipady=3, pady=(0, 8))

        ttk.Label(box_enc_action, text="Daftar Blok Ciphertext [c1, c2, ...]:").pack(anchor=tk.W)
        self.txt_ciphertext_preview = tk.Text(box_enc_action, height=8, font=("Consolas", 8), bg="#f8fafc", wrap=tk.CHAR)
        self.txt_ciphertext_preview.pack(fill=tk.BOTH, expand=True, pady=(2, 8))

        self.btn_export_enc = ttk.Button(box_enc_action, text="📤 Simpan Dokumen Terenkripsi (.enc)",
                                         state=tk.DISABLED, command=self._handle_export_enc_file)
        self.btn_export_enc.pack(fill=tk.X)

    # -------------------------------------------------------------------------
    # TAB 3: RSA MATH INSPECTOR
    # -------------------------------------------------------------------------
    def _build_inspector_tab(self):
        container = ttk.Frame(self.tab_inspector)
        container.pack(fill=tk.BOTH, expand=True)

        top_info = ttk.Label(
            container,
            text="Riwayat Langkah Komputasi & Bukti Matematis RSA:",
            font=("Segoe UI", 10, "bold"), foreground="#0f172a"
        )
        top_info.pack(anchor=tk.W, pady=(0, 6))

        self.txt_math_log = tk.Text(container, font=("Consolas", 9), bg="#0f172a", fg="#38bdf8", wrap=tk.WORD)
        scroll_log = ttk.Scrollbar(container, orient=tk.VERTICAL, command=self.txt_math_log.yview)
        self.txt_math_log.configure(yscrollcommand=scroll_log.set)
        
        scroll_log.pack(side=tk.RIGHT, fill=tk.Y)
        self.txt_math_log.pack(fill=tk.BOTH, expand=True)

        self._log_math("=== RSA MATH INSPECTOR AKTIF ===")
        self._log_math("Lakukan aksi pada Portal Karyawan atau Portal HRD.")
        self._log_math("Segala perhitungan dan komputasi akan muncul pada log ini.\n")

    # =========================================================================
    # LOGIKA PEMBANTU & FORMAT ANGKA RIBUAN
    # =========================================================================

    def _format_currency_on_release(self, event):
        """Memformat input angka secara dinamis dengan pemisah ribuan titik."""
        widget = event.widget
        cursor_pos = widget.index(tk.INSERT)
        val = widget.get().replace(".", "").strip()

        if not val:
            return

        if val.isdigit():
            formatted = f"{int(val):,}".replace(",", ".")
            widget.delete(0, tk.END)
            widget.insert(0, formatted)
            widget.icursor(cursor_pos + 1 if len(formatted) > len(val) else cursor_pos)

    def _parse_amount(self, text_val: str) -> float:
        """Mengonversi format teks bertitik menjadi bilangan float murni."""
        clean = text_val.replace(".", "").strip()
        return float(clean) if clean else 0.0

    def _log_math(self, text: str):
        self.txt_math_log.insert(tk.END, text + "\n")
        self.txt_math_log.see(tk.END)

    def _display_blank_payroll_template(self):
        self.txt_slip_display.delete("1.0", tk.END)
        self.txt_slip_display.insert(tk.END, 
            "+-------------------------------------------------------------------+\n"
            "|               SLIP GAJI BELUM TERDEKRIPSI                         |\n"
            "|       Silahkan load file .enc dan jalankan proses dekripsi         |\n"
            "+-------------------------------------------------------------------+\n"
        )

    # =========================================================================
    # EVENT HANDLERS
    # =========================================================================

    def _handle_generate_keys(self):
        try:
            self._log_math("\n" + "="*70)
            self._log_math(f"[{datetime.now().strftime('%H:%M:%S')}] PROSES PEMBANGKITAN KUNCI KARYAWAN")
            self._log_math("="*70)

            p, q, n, phi, e, d = RSAMathEngine.generate_keypair(bits=64)

            self.current_keys = {
                "p": p, "q": q, "n": n, "phi": phi, "e": e, "d": d
            }

            pub_txt = f"e: {e}\nn: {n}"
            priv_txt = f"d: {d}\nn: {n}"

            self.txt_emp_pub.delete("1.0", tk.END)
            self.txt_emp_pub.insert(tk.END, pub_txt)

            self.txt_emp_priv.delete("1.0", tk.END)
            self.txt_emp_priv.insert(tk.END, priv_txt)

            self.ent_dec_d.delete(0, tk.END)
            self.ent_dec_d.insert(0, str(d))
            self.ent_dec_n.delete(0, tk.END)
            self.ent_dec_n.insert(0, str(n))

            # Logging edukatif
            self._log_math("1. Pemilihan Bilangan Prima (Miller-Rabin Test):")
            self._log_math(f"   p = {p}")
            self._log_math(f"   q = {q}")
            self._log_math("2. Menghitung Modulus n = p * q:")
            self._log_math(f"   n = {n} ({n.bit_length()} bit)")
            self._log_math("3. Menghitung Totient Euler phi(n) = (p-1)*(q-1):")
            self._log_math(f"   phi(n) = {phi}")
            self._log_math("4. Public Key e:")
            self._log_math(f"   e = {e}")
            self._log_math(f"   Uji Relatif Prima: gcd(e, phi) = {RSAMathEngine.gcd(e, phi)}")
            self._log_math("5. Private Key d (Extended Euclidean Algorithm):")
            self._log_math(f"   d = {d}")
            self._log_math(f"   Verifikasi Invers: (e * d) mod phi = {(e * d) % phi} (Harus = 1)")
            self._log_math(">> Pasangan kunci berhasil dibangkitkan!")

            messagebox.showinfo("Sukses", "Pasangan kunci RSA berhasil digenerate!\nPublic Key siap diberikan ke HRD.")
        except Exception as ex:
            messagebox.showerror("Error", f"Gagal membangkitkan kunci: {str(ex)}")

    def _handle_save_keys(self):
        if not self.current_keys["n"]:
            messagebox.showwarning("Peringatan", "Bangkitkan pasangan kunci terlebih dahulu!")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json")],
            title="Simpan Kunci Karyawan"
        )
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(self.current_keys, f, indent=4)
                messagebox.showinfo("Tersimpan", f"Kunci berhasil disimpan ke:\n{file_path}")
            except Exception as ex:
                messagebox.showerror("Error", str(ex))

    def _handle_copy_keys_to_hrd(self):
        if not self.current_keys["n"]:
            messagebox.showwarning("Peringatan", "Karyawan belum melakukan generate kunci!")
            return
        self.ent_hrd_e.delete(0, tk.END)
        self.ent_hrd_e.insert(0, str(self.current_keys["e"]))
        self.ent_hrd_n.delete(0, tk.END)
        self.ent_hrd_n.insert(0, str(self.current_keys["n"]))
        messagebox.showinfo("Tersalin", "Public Key Karyawan berhasil diload ke formulir HRD!")

    def _handle_encrypt_payroll(self):
        try:
            e_str = self.ent_hrd_e.get().strip()
            n_str = self.ent_hrd_n.get().strip()
            if not e_str or not n_str:
                messagebox.showerror("Error", "Harap masukkan Public Key Karyawan (e dan n)!")
                return

            e = int(e_str)
            n = int(n_str)

            # Membaca input finansial dengan penghapusan format titik
            gaji_pokok = self._parse_amount(self.hrd_entries["gaji_pokok"].get())
            tunjangan = self._parse_amount(self.hrd_entries["tunjangan"].get())
            potongan_bpjs = self._parse_amount(self.hrd_entries["potongan_bpjs"].get())
            potongan_pph = self._parse_amount(self.hrd_entries["potongan_pph"].get())
            take_home_pay = (gaji_pokok + tunjangan) - (potongan_bpjs + potongan_pph)

            payroll_dict = {
                "nik": self.hrd_entries["nik"].get().strip(),
                "nama": self.hrd_entries["nama"].get().strip(),
                "jabatan": self.hrd_entries["jabatan"].get().strip(),
                "periode": self.hrd_entries["periode"].get().strip(),
                "rincian": {
                    "gaji_pokok": gaji_pokok,
                    "tunjangan": tunjangan,
                    "potongan_bpjs": potongan_bpjs,
                    "potongan_pph": potongan_pph,
                    "take_home_pay": take_home_pay
                },
                "catatan": self.hrd_entries["catatan"].get().strip(),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

            raw_bytes = json.dumps(payroll_dict, ensure_ascii=False).encode("utf-8")
            ciphertext_blocks, block_size, metadata = RSAMathEngine.encrypt_bytes(raw_bytes, e, n)

            self.generated_encrypted_payload = {
                "target_nik": payroll_dict["nik"],
                "algorithm": "RSA-Manual-NoFramework",
                "block_byte_size": block_size,
                "block_lengths": [m["byte_len"] for m in metadata],
                "ciphertext": ciphertext_blocks
            }

            self.txt_ciphertext_preview.delete("1.0", tk.END)
            self.txt_ciphertext_preview.insert(tk.END, ",\n".join(ciphertext_blocks))
            self.btn_export_enc.config(state=tk.NORMAL)

            self._log_math("\n" + "="*70)
            self._log_math(f"[{datetime.now().strftime('%H:%M:%S')}] EKSEKUSI ENKRIPSI DI PORTAL HRD")
            self._log_math("="*70)
            self._log_math(f"Panjang Data Asli: {len(raw_bytes)} byte")
            self._log_math(f"Batas Ukuran Blok (m_i < n): {block_size} byte")
            self._log_math(f"Total Blok Dihasilkan: {len(ciphertext_blocks)} blok")
            for sample in metadata[:2]:
                self._log_math(f"  * Blok #{sample['index']}:")
                self._log_math(f"    - Integer Plaintext m_{sample['index']} = {sample['m_int']}")
                self._log_math(f"    - Rumus: c = (m ^ {e}) mod {n}")
                self._log_math(f"    - Integer Ciphertext c_{sample['index']} = {sample['c_int']}")

            messagebox.showinfo("Sukses", f"Enkripsi Berhasil!\nTotal {len(ciphertext_blocks)} blok data terlindungi.")
        except Exception as ex:
            messagebox.showerror("Error", f"Enkripsi gagal: {str(ex)}")

    def _handle_export_enc_file(self):
        if not hasattr(self, 'generated_encrypted_payload'):
            return

        default_fname = f"slip_gaji_{self.generated_encrypted_payload['target_nik']}.enc"
        file_path = filedialog.asksaveasfilename(
            initialfile=default_fname,
            defaultextension=".enc",
            filetypes=[("Encrypted File", "*.enc")],
            title="Simpan File Terenkripsi"
        )
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(self.generated_encrypted_payload, f, indent=2)
                messagebox.showinfo("Berhasil", f"File terenkripsi disimpan ke:\n{file_path}")
            except Exception as ex:
                messagebox.showerror("Error", str(ex))

    def _handle_load_enc_file(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Encrypted File", "*.enc"), ("All Files", "*.*")],
            title="load File Terenkripsi"
        )
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if "ciphertext" not in data or "block_lengths" not in data:
                    raise ValueError("Format File rusak atau tidak sesuai!")

                self.loaded_encrypted_data = data
                fname = os.path.basename(file_path)
                self.lbl_enc_file_info.config(
                    text=f"File: {fname} (Target NIK: {data.get('target_nik', '-')}, {len(data['ciphertext'])} blok)",
                    foreground="#047857"
                )
                messagebox.showinfo("Diload", f"File {fname} berhasil diload.")
            except Exception as ex:
                messagebox.showerror("Gagal", f"Format file tidak valid: {str(ex)}")

    def _handle_decrypt_payroll(self):
        try:
            if not self.loaded_encrypted_data:
                messagebox.showwarning("Peringatan", "load File terenkripsi (.enc) terlebih dahulu!")
                return

            d_str = self.ent_dec_d.get().strip()
            n_str = self.ent_dec_n.get().strip()
            if not d_str or not n_str:
                messagebox.showerror("Error", "Harap lengkapi Private Key (d) dan Modulus (n)!")
                return

            d = int(d_str)
            n = int(n_str)

            ciphertext_blocks = self.loaded_encrypted_data["ciphertext"]
            block_lengths = self.loaded_encrypted_data["block_lengths"]

            decrypted_bytes, trace = RSAMathEngine.decrypt_bytes(ciphertext_blocks, block_lengths, d, n)
            payroll = json.loads(decrypted_bytes.decode("utf-8"))

            self._render_payroll_card(payroll)

            self._log_math("\n" + "="*70)
            self._log_math(f"[{datetime.now().strftime('%H:%M:%S')}] EKSEKUSI DEKRIPSI DI PORTAL KARYAWAN")
            self._log_math("="*70)
            self._log_math(f"Jumlah Blok Didekripsi: {len(ciphertext_blocks)}")
            for sample in trace[:2]:
                self._log_math(f"  * Blok #{sample['index']}:")
                self._log_math(f"    - Ciphertext Input: {sample['c_int']}")
                self._log_math(f"    - Rumus: m = (c ^ {d}) mod {n}")
                self._log_math(f"    - Plaintext Integer Pulih: {sample['m_int']}")

            messagebox.showinfo("Sukses", "Dekripsi berhasil! Slip gaji telah diverifikasi.")
        except json.JSONDecodeError:
            messagebox.showerror("Dekripsi Gagal", "Private Key salah! Data byte yang dipulihkan rusak.")
        except Exception as ex:
            messagebox.showerror("Error", f"Gagal mendekripsi: {str(ex)}")

    def _render_payroll_card(self, data: dict):
        r = data["rincian"]
        card_text = (
            "=====================================================================\n"
            "                 PT. TEKNOLOGI INFORMASI NUSANTARA                   \n"
            "                     SLIP GAJI RESMI KARYAWAN                        \n"
            "               STATUS KEAMANAN: RAHASIA / TERVERIFIKASI             \n"
            "=====================================================================\n"
            f" NIK              : {data.get('nik')}\n"
            f" Nama Karyawan    : {data.get('nama')}\n"
            f" Jabatan / Divisi : {data.get('jabatan')}\n"
            f" Periode Gaji     : {data.get('periode')}\n"
            f" Tanggal Terbit   : {data.get('timestamp')}\n"
            "---------------------------------------------------------------------\n"
            " RINCIAN PENDAPATAN (EARNINGS):\n"
            f"  + Gaji Pokok                         : Rp {r['gaji_pokok']:>14,.2f}\n"
            f"  + Tunjangan Operasional              : Rp {r['tunjangan']:>14,.2f}\n"
            f"  TOTAL PENDAPATAN KOTOR (GROSS)       : Rp {(r['gaji_pokok'] + r['tunjangan']):>14,.2f}\n"
            "---------------------------------------------------------------------\n"
            " RINCIAN PEMOTONGAN (DEDUCTIONS):\n"
            f"  - Iuran Jaminan Sosial (BPJS)        : Rp {r['potongan_bpjs']:>14,.2f}\n"
            f"  - Pajak Penghasilan (PPh 21)         : Rp {r['potongan_pph']:>14,.2f}\n"
            f"  TOTAL POTONGAN                      : Rp {(r['potongan_bpjs'] + r['potongan_pph']):>14,.2f}\n"
            "=====================================================================\n"
            f" GAJI BERSIH DITERIMA (TAKE HOME PAY)  : Rp {r['take_home_pay']:>14,.2f}\n"
            "=====================================================================\n"
            f" Catatan HRD:\n \"{data.get('catatan')}\"\n"
            "---------------------------------------------------------------------\n"
            " File didekripsi secara lokal menggunakan Private Key sah milik karyawan.\n"
            "=====================================================================\n"
        )
        self.txt_slip_display.delete("1.0", tk.END)
        self.txt_slip_display.insert(tk.END, card_text)


if __name__ == "__main__":
    app = SecurePayrollApp()
    app.mainloop()