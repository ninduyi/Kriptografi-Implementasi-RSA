import sys
import os
import json
import random
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime

# =============================================================================
# BAGIAN 1: RSA MATH ENGINE
# =============================================================================

class RSAMathEngine:
    """
    Kelas mesin matematika RSA murni:
    1. Primality Test (Miller-Rabin)
    2. Prime Generator
    3. GCD & Extended Euclidean Algorithm (Invers Modulo)
    4. Modular Exponentiation (Square-and-Multiply)
    5. Chunking / Blocking Encoding
    """

    @staticmethod
    def gcd(a: int, b: int) -> int:
        """PBB"""
        while b != 0:
            a, b = b, a % b
        return a

    @staticmethod
    def extended_gcd(a: int, b: int):
        """
        Extended Euclidean Algorithm:
        Mencari nilai x dan y sehingga: a*x + b*y = gcd(a, b)
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
        Menghitung Private Key d sebagai invers modulo:
        e * d = 1 (mod phi)
        """
        gcd_val, x, _ = RSAMathEngine.extended_gcd(e, phi)
        if gcd_val != 1:
            raise ValueError("Invers modulo tidak ditemukan; e dan phi tidak relatif prima.")
        return (x % phi + phi) % phi

    @staticmethod
    def mod_pow(base: int, exp: int, mod: int) -> int:
        """
        Modular Exponentiation menggunakan metode Square-and-Multiply:
        Menghitung (base ^ exp) % mod secara efisien dalam O(log exp).
        Mencegah terjadinya integer overflow.
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
    def is_prime_miller_rabin(n: int, k: int = 10) -> bool:
        """
        Uji Keprimaan Miller-Rabin manual:
        Menguji apakah n adalah bilangan prima secara probabilistik.
        """
        if n < 2:
            return False
        if n in (2, 3):
            return True
        if n % 2 == 0:
            return False

        # Tulis n - 1 sebagai 2^s * d
        d = n - 1
        s = 0
        while d % 2 == 0:
            d //= 2
            s += 1

        # Lakukan k iterasi uji saksi (witness)
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
        """Membuat bilangan prima acak berukuran n-bit."""
        small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
        while True:
            # Pastikan bit tertinggi dan terendah bernilai 1 (ganjil dan sesuai rentang bit)
            p = random.getrandbits(bits) | (1 << (bits - 1)) | 1
            # Saring awal dengan bilangan prima kecil untuk efisiensi
            if any(p % sp == 0 and p != sp for sp in small_primes):
                continue
            if RSAMathEngine.is_prime_miller_rabin(p, k=15):
                return p

    @classmethod
    def generate_keypair(cls, bits: int = 64):
        """
        Membuat pasangan kunci RSA:
        Returns: (p, q, n, phi, e, d)
        """
        p = cls.generate_prime(bits)
        q = cls.generate_prime(bits)
        while p == q:
            q = cls.generate_prime(bits)

        n = p * q
        phi = (p - 1) * (q - 1)

        # Pemilihan e standar: 65537 atau dicari iteratif
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
        Memecah byte menjadi blok-blok m_i < n, lalu mengenkripsinya:
        c_i = (m_i ^ e) mod n
        """
        # Ukuran blok byte maksimum: (bit_length - 1) // 8 byte
        # Menjamin secara matematis m_i < n
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
        m_i = (c_i ^ d) mod n
        Lalu merekonstruksi kembali byte aslinya.
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
# BAGIAN 2: GUI
# =============================================================================

class SecurePayrollApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Digital Payroll Slip - RSA Cryptographic System")
        self.geometry("1040x780")
        self.minsize(920, 680)

        # Inisialisasi State Penyimpanan Sementara
        self.current_keys = {
            "p": None, "q": None, "n": None, "phi": None, "e": None, "d": None
        }
        self.loaded_encrypted_data = None

        self._configure_styles()
        self._build_ui()

    def _configure_styles(self):
        self.style = ttk.Style(self)
        self.style.theme_use("clam")

        # Custom Styling Elemen
        self.style.configure(".", font=("Segoe UI", 9))
        self.style.configure("TNotebook.Tab", font=("Segoe UI", 10, "bold"), padding=[12, 6])
        self.style.configure("Header.TLabel", font=("Segoe UI", 14, "bold"), foreground="#1e293b")
        self.style.configure("SubHeader.TLabel", font=("Segoe UI", 10, "bold"), foreground="#334155")
        self.style.configure("Accent.TButton", font=("Segoe UI", 9, "bold"), background="#2563eb", foreground="white")
        self.style.map("Accent.TButton", background=[("active", "#1d4ed8")])
        self.style.configure("Success.TButton", font=("Segoe UI", 9, "bold"), background="#059669", foreground="white")
        self.style.map("Success.TButton", background=[("active", "#047857")])

    def _build_ui(self):
        # Header Banner Aplikasi
        banner = tk.Frame(self, bg="#1e293b", height=70)
        banner.pack(fill=tk.X, side=tk.TOP)
        banner.pack_propagate(False)

        lbl_title = tk.Label(
            banner, text="SECURE DIGITAL PAYROLL SYSTEM",
            font=("Segoe UI", 14, "bold"), fg="#ffffff", bg="#1e293b"
        )
        lbl_title.pack(anchor=tk.W, padx=20, pady=(10, 2))

        lbl_subtitle = tk.Label(
            banner, text="Pembagian Slip Gaji Karyawan dari HRD yang Terenkripsi",
            font=("Segoe UI", 9), fg="#94a3b8", bg="#1e293b"
        )
        lbl_subtitle.pack(anchor=tk.W, padx=20)

        # Tab Bar (Notebook)
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)

        # Inisialisasi 3 Tab Utama
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
        # Split menjadi 2 kolom: Kiri (Kunci & Aksi) | Kanan (Kartu Slip Gaji)
        paned = ttk.PanedWindow(self.tab_karyawan, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        left_frame = ttk.Frame(paned, padding=(0, 0, 10, 0))
        right_frame = ttk.Frame(paned, padding=(10, 0, 0, 0))
        paned.add(left_frame, weight=1)
        paned.add(right_frame, weight=1)

        # --- Section 1: Key Management Karyawan ---
        grp_key = ttk.LabelFrame(left_frame, text=" 1. Generator Pasangan Kunci RSA Karyawan ", padding=10)
        grp_key.pack(fill=tk.X, pady=(0, 10))

        btn_bar = ttk.Frame(grp_key)
        btn_bar.pack(fill=tk.X, pady=(0, 6))

        ttk.Button(btn_bar, text="🔑 Generate New Key Pair (64-bit)", style="Accent.TButton",
                   command=self._handle_generate_keys).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_bar, text="💾 Simpan Kunci", command=self._handle_save_keys).pack(side=tk.LEFT)

        ttk.Label(grp_key, text="Public Key Karyawan (e, n):").pack(anchor=tk.W, pady=(4, 0))
        self.txt_emp_pub = tk.Text(grp_key, height=3, font=("Consolas", 8), bg="#f8fafc", wrap=tk.CHAR)
        self.txt_emp_pub.pack(fill=tk.X, pady=(2, 6))

        ttk.Label(grp_key, text="Private Key Karyawan (d, n):").pack(anchor=tk.W)
        self.txt_emp_priv = tk.Text(grp_key, height=3, font=("Consolas", 8), bg="#fef2f2", wrap=tk.CHAR)
        self.txt_emp_priv.pack(fill=tk.X, pady=(2, 4))

        # --- Section 2: Dekripsi Slip Gaji ---
        grp_decrypt = ttk.LabelFrame(left_frame, text=" 2. Dekripsi File Slip Gaji (.enc) ", padding=10)
        grp_decrypt.pack(fill=tk.BOTH, expand=True)

        dec_btn_bar = ttk.Frame(grp_decrypt)
        dec_btn_bar.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(dec_btn_bar, text="📂 Load File .enc", command=self._handle_load_enc_file).pack(side=tk.LEFT, padx=(0, 5))

        self.lbl_enc_file_info = ttk.Label(grp_decrypt, text="Status file: Belum ada file", foreground="#64748b")
        self.lbl_enc_file_info.pack(anchor=tk.W, pady=(0, 8))

        ttk.Label(grp_decrypt, text="Input Private Key (d):").pack(anchor=tk.W)
        self.ent_dec_d = ttk.Entry(grp_decrypt, font=("Consolas", 9))
        self.ent_dec_d.pack(fill=tk.X, pady=(2, 6))

        ttk.Label(grp_decrypt, text="Input Modulus (n):").pack(anchor=tk.W)
        self.ent_dec_n = ttk.Entry(grp_decrypt, font=("Consolas", 9))
        self.ent_dec_n.pack(fill=tk.X, pady=(2, 10))

        ttk.Button(grp_decrypt, text="🔓 Dekripsi & Tampilkan Slip Gaji", style="Success.TButton",
                   command=self._handle_decrypt_payroll).pack(fill=tk.X, ipady=4)

        # --- Section 3: Visual Payroll Card (Sisi Kanan) ---
        grp_slip = ttk.LabelFrame(right_frame, text=" 3. Tampilan Slip Gaji Resmi (Hasil Dekripsi) ", padding=10)
        grp_slip.pack(fill=tk.BOTH, expand=True)

        self.txt_slip_display = tk.Text(grp_slip, font=("Courier New", 9), bg="#ffffff", fg="#0f172a", wrap=tk.NONE)
        scroll_slip_y = ttk.Scrollbar(grp_slip, orient=tk.VERTICAL, command=self.txt_slip_display.yview)
        self.txt_slip_display.configure(yscrollcommand=scroll_slip_y.set)
        
        scroll_slip_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.txt_slip_display.pack(fill=tk.BOTH, expand=True)
        self._display_blank_payroll_template()

    # -------------------------------------------------------------------------
    # TAB 2: PORTAL HRD
    # -------------------------------------------------------------------------
    def _build_hrd_tab(self):
        container = ttk.Frame(self.tab_hrd)
        container.pack(fill=tk.BOTH, expand=True)

        # Kolom Kiri: Form Input Gaji
        left_col = ttk.LabelFrame(container, text=" Form Rincian Gaji Karyawan", padding=12)
        left_col.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))

        entries_spec = [
            ("ID Karyawan", "id", "IT-2024-001"),
            ("Nama Lengkap", "nama", "Masukkan Nama"),
            ("Jabatan / Posisi", "jabatan", "Senior Network & Security Engineer"),
            ("Periode Penggajian", "periode", "Oktober 2026"),
            ("Gaji Pokok (Rp)", "gaji_pokok", "12500000"),
            ("Tunjangan Jabatan & Makan (Rp)", "tunjangan", "3500000"),
            ("Potongan BPJS (Rp)", "potongan_bpjs", "450000"),
            ("Potongan Pajak PPh 21 (Rp)", "potongan_pph", "650000"),
            ("Catatan HRD", "catatan", "Semoga berkah.")
        ]

        self.hrd_entries = {}
        for row_idx, (label_txt, field_name, default_val) in enumerate(entries_spec):
            ttk.Label(left_col, text=label_txt + ":").grid(row=row_idx, column=0, sticky=tk.W, pady=4, padx=4)
            ent = ttk.Entry(left_col, font=("Segoe UI", 9))
            ent.insert(0, default_val)
            ent.grid(row=row_idx, column=1, sticky=tk.EW, pady=4, padx=4)
            self.hrd_entries[field_name] = ent

        left_col.columnconfigure(1, weight=1)

        # Kolom Kanan: Public Key Target & Enkripsi
        right_col = ttk.Frame(container)
        right_col.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(8, 0))

        grp_target_key = ttk.LabelFrame(right_col, text=" Public Key Karyawan ", padding=10)
        grp_target_key.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(grp_target_key, text="Public Exponent (e):").pack(anchor=tk.W)
        self.ent_hrd_e = ttk.Entry(grp_target_key, font=("Consolas", 9))
        self.ent_hrd_e.pack(fill=tk.X, pady=(2, 6))

        ttk.Label(grp_target_key, text="Modulus Karyawan (n):").pack(anchor=tk.W)
        self.ent_hrd_n = ttk.Entry(grp_target_key, font=("Consolas", 9))
        self.ent_hrd_n.pack(fill=tk.X, pady=(2, 8))

        ttk.Button(grp_target_key, text="📥 Salin Otomatis dari Tab Karyawan", command=self._handle_copy_keys_to_hrd).pack(fill=tk.X)

        grp_encrypt = ttk.LabelFrame(right_col, text=" Enkripsi RSA ", padding=10)
        grp_encrypt.pack(fill=tk.BOTH, expand=True)

        ttk.Button(grp_encrypt, text="🔒 Enkripsi Data Slip Gaji Sekarang", style="Accent.TButton",
                   command=self._handle_encrypt_payroll).pack(fill=tk.X, ipady=3, pady=(0, 8))

        ttk.Label(grp_encrypt, text="Hasil Ciphertext Per Blok [c1, c2, ...]:").pack(anchor=tk.W)
        self.txt_ciphertext_preview = tk.Text(grp_encrypt, height=8, font=("Consolas", 8), bg="#f8fafc", wrap=tk.CHAR)
        self.txt_ciphertext_preview.pack(fill=tk.BOTH, expand=True, pady=(2, 8))

        self.btn_export_enc = ttk.Button(grp_encrypt, text="📤 Simpan File .enc", state=tk.DISABLED,
                                         command=self._handle_export_enc_file)
        self.btn_export_enc.pack(fill=tk.X)

    # -------------------------------------------------------------------------
    # TAB 3: RSA MATH INSPECTOR
    # -------------------------------------------------------------------------
    def _build_inspector_tab(self):
        container = ttk.Frame(self.tab_inspector)
        container.pack(fill=tk.BOTH, expand=True)

        top_info = ttk.Label(
            container,
            text="History Log Step Perhitungan RSA:",
            font=("Segoe UI", 10, "bold"), foreground="#1e293b"
        )
        top_info.pack(anchor=tk.W, pady=(0, 6))

        self.txt_math_log = tk.Text(container, font=("Consolas", 9), bg="#0f172a", fg="#38bdf8", wrap=tk.WORD)
        scroll_log = ttk.Scrollbar(container, orient=tk.VERTICAL, command=self.txt_math_log.yview)
        self.txt_math_log.configure(yscrollcommand=scroll_log.set)
        
        scroll_log.pack(side=tk.RIGHT, fill=tk.Y)
        self.txt_math_log.pack(fill=tk.BOTH, expand=True)

        self._log_math("=== RSA MATH INSPECTOR READY ===")
        self._log_math("Jalankan key generator, enkripsi di tab HRD, atau dekripsi di tab Karyawan.")
        self._log_math("Semua tahapan perhitungan dicatat dalam Log ini.\n")

    # =========================================================================
    # EVENT HANDLERS & LOGIC
    # =========================================================================

    def _log_math(self, text: str):
        self.txt_math_log.insert(tk.END, text + "\n")
        self.txt_math_log.see(tk.END)

    def _display_blank_payroll_template(self):
        self.txt_slip_display.delete("1.0", tk.END)
        self.txt_slip_display.insert(tk.END, 
            "+-------------------------------------------------------------------+\n"
            "|               SLIP GAJI BELUM TERDEKRIPSI                         |\n"
            "|         Silahkan load file .enc dan gunakan Private Key           |\n"
            "+-------------------------------------------------------------------+\n"
        )

    def _handle_generate_keys(self):
        try:
            self._log_math("\n" + "="*70)
            self._log_math(f"[{datetime.now().strftime('%H:%M:%S')}] MEMULAI PEMBANGKITAN KUNCI RSA KARYAWAN")
            self._log_math("="*70)

            # Generate primes 64-bit
            p, q, n, phi, e, d = RSAMathEngine.generate_keypair(bits=64)

            self.current_keys = {
                "p": p, "q": q, "n": n, "phi": phi, "e": e, "d": d
            }

            # Update UI Fields
            pub_str = f"e: {e}\nn: {n}"
            priv_str = f"d: {d}\nn: {n}"

            self.txt_emp_pub.delete("1.0", tk.END)
            self.txt_emp_pub.insert(tk.END, pub_str)

            self.txt_emp_priv.delete("1.0", tk.END)
            self.txt_emp_priv.insert(tk.END, priv_str)

            # Isi kolom dekripsi default
            self.ent_dec_d.delete(0, tk.END)
            self.ent_dec_d.insert(0, str(d))
            self.ent_dec_n.delete(0, tk.END)
            self.ent_dec_n.insert(0, str(n))

            # Logging Edukatif Matematis ke Tab Inspector
            self._log_math(f"1. Bilangan Prima Terpilih:")
            self._log_math(f"   p = {p}")
            self._log_math(f"   q = {q}")
            self._log_math(f"2. Menghitung Modulus n = p * q:")
            self._log_math(f"   n = {n} ({n.bit_length()} bits)")
            self._log_math(f"3. Menghitung Fungsi Totient Euler phi(n) = (p-1)*(q-1):")
            self._log_math(f"   phi(n) = {phi}")
            self._log_math(f"4. Pemilihan Public Key e:")
            self._log_math(f"   e = {e}")
            self._log_math(f"   Uji Relatif Prima: gcd(e, phi) = {RSAMathEngine.gcd(e, phi)} (Terpenuhi)")
            self._log_math(f"5. Menghitung Private Key d dengan Extended Euclidean Algorithm:")
            self._log_math(f"   d = {d}")
            self._log_math(f"   Verifikasi Invers: (e * d) mod phi = {(e * d) % phi} (Harus bernilai 1)")
            self._log_math(">> Pasangan kunci berhasil dibangkitkan secara valid!")

            messagebox.showinfo("Sukses", "Key Pair RSA 128-bit berhasil digenerate!\nPublic key siap diberikan ke HRD.")
        except Exception as ex:
            messagebox.showerror("Error", f"Gagal membangkitkan kunci: {str(ex)}")

    def _handle_save_keys(self):
        if not self.current_keys["n"]:
            messagebox.showwarning("Peringatan", "Silakan generate pasangan kunci terlebih dahulu!")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("Text Files", "*.txt")],
            title="Simpan Pasangan Kunci Karyawan"
        )
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(self.current_keys, f, indent=4)
                messagebox.showinfo("Tersimpan", f"Kunci berhasil disimpan ke:\n{file_path}")
            except Exception as ex:
                messagebox.showerror("Error", f"Gagal menyimpan berkas: {str(ex)}")

    def _handle_copy_keys_to_hrd(self):
        if not self.current_keys["n"]:
            messagebox.showwarning("Peringatan", "Karyawan belum melakukan generate kunci!")
            return
        self.ent_hrd_e.delete(0, tk.END)
        self.ent_hrd_e.insert(0, str(self.current_keys["e"]))
        self.ent_hrd_n.delete(0, tk.END)
        self.ent_hrd_n.insert(0, str(self.current_keys["n"]))
        messagebox.showinfo("Tersalin", "Public key Karyawan berhasil diload ke formulir HRD!")

    def _handle_encrypt_payroll(self):
        try:
            e_str = self.ent_hrd_e.get().strip()
            n_str = self.ent_hrd_n.get().strip()
            if not e_str or not n_str:
                messagebox.showerror("Error", "Harap masukkan Public Key Karyawan (e dan n)!")
                return

            e = int(e_str)
            n = int(n_str)

            # Ambil data dari form HRD
            gaji_pokok = float(self.hrd_entries["gaji_pokok"].get().strip())
            tunjangan = float(self.hrd_entries["tunjangan"].get().strip())
            potongan_bpjs = float(self.hrd_entries["potongan_bpjs"].get().strip())
            potongan_pph = float(self.hrd_entries["potongan_pph"].get().strip())

            take_home_pay = (gaji_pokok + tunjangan) - (potongan_bpjs + potongan_pph)

            payroll_dict = {
                "id": self.hrd_entries["id"].get().strip(),
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
                "timestamp": datetime.now().isoformat()
            }

            # Serialisasi ke byte UTF-8
            raw_json_str = json.dumps(payroll_dict, ensure_ascii=False)
            raw_bytes = raw_json_str.encode("utf-8")

            # Eksekusi Enkripsi RSA Manual
            ciphertext_blocks, block_size, metadata = RSAMathEngine.encrypt_bytes(raw_bytes, e, n)

            # Siapkan paket dokumen enkripsi
            self.generated_encrypted_payload = {
                "target_nik": payroll_dict["id"],
                "algorithm": "Manual-RSA-Square-Multiply",
                "block_byte_size": block_size,
                "block_lengths": [m["byte_len"] for m in metadata],
                "ciphertext": ciphertext_blocks
            }

            # Tampilkan di preview ciphertext
            self.txt_ciphertext_preview.delete("1.0", tk.END)
            self.txt_ciphertext_preview.insert(tk.END, ",\n".join(ciphertext_blocks))
            self.btn_export_enc.config(state=tk.NORMAL)

            # Logging ke Tab Inspector
            self._log_math("\n" + "="*70)
            self._log_math(f"[{datetime.now().strftime('%H:%M:%S')}] PROSES ENKRIPSI SLIP GAJI DI SISI HRD")
            self._log_math("="*70)
            self._log_math(f"Ukuran Data Asli: {len(raw_bytes)} bytes")
            self._log_math(f"Ukuran Maksimal Blok (m_i < n): {block_size} bytes")
            self._log_math(f"Jumlah Blok Dihasilkan: {len(ciphertext_blocks)} blok")
            self._log_math("Contoh Perhitungan 2 Blok Pertama:")
            for sample in metadata[:2]:
                self._log_math(f"  * Blok #{sample['index']}:")
                self._log_math(f"    - Nilai Integer m_{sample['index']} = {sample['m_int']}")
                self._log_math(f"    - Rumus: c_{sample['index']} = (m_{sample['index']} ^ {e}) mod {n}")
                self._log_math(f"    - Nilai Ciphertext c_{sample['index']} = {sample['c_int']}")

            messagebox.showinfo("Sukses", f"Enkripsi RSA Berhasil!\nTotal {len(ciphertext_blocks)} blok data terlindungi.")
        except Exception as ex:
            messagebox.showerror("Error Enkripsi", f"Terjadi kesalahan saat enkripsi: {str(ex)}")

    def _handle_export_enc_file(self):
        if not hasattr(self, 'generated_encrypted_payload'):
            return

        default_filename = f"slip_gaji_{self.generated_encrypted_payload['target_nik']}.enc"
        file_path = filedialog.asksaveasfilename(
            initialfile=default_filename,
            defaultextension=".enc",
            filetypes=[("Encrypted File", "*.enc"), ("JSON File", "*.json")],
            title="Ekspor Berkas Slip Gaji Terenkripsi"
        )
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(self.generated_encrypted_payload, f, indent=2)
                messagebox.showinfo("Ekspor Berhasil", f"Berkas terenkripsi disimpan ke:\n{file_path}\nKirimkan file ini ke karyawan.")
            except Exception as ex:
                messagebox.showerror("Gagal Ekspor", str(ex))

    def _handle_load_enc_file(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Encrypted File", "*.enc"), ("JSON File", "*.json"), ("All Files", "*.*")],
            title="Pilih Berkas Slip Gaji Terenkripsi"
        )
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if "ciphertext" not in data or "block_lengths" not in data:
                    raise ValueError("Format berkas .enc tidak valid!")

                self.loaded_encrypted_data = data
                fname = os.path.basename(file_path)
                self.lbl_enc_file_info.config(
                    text=f"Berkas: {fname} (Target ID: {data.get('target_nik', '-')}, {len(data['ciphertext'])} blok)",
                    foreground="#059669"
                )
                messagebox.showinfo("Berkas Dimuat", f"Berkas {fname} berhasil dimuat.")
            except Exception as ex:
                messagebox.showerror("Gagal Membaca Berkas", f"File korup atau salah format: {str(ex)}")

    def _handle_decrypt_payroll(self):
        try:
            if not self.loaded_encrypted_data:
                messagebox.showwarning("Peringatan", "Pilih berkas slip gaji terenkripsi (.enc) terlebih dahulu!")
                return

            d_str = self.ent_dec_d.get().strip()
            n_str = self.ent_dec_n.get().strip()
            if not d_str or not n_str:
                messagebox.showerror("Error", "Harap masukkan Private Key (d) dan Modulus (n) milik Anda!")
                return

            d = int(d_str)
            n = int(n_str)

            ciphertext_blocks = self.loaded_encrypted_data["ciphertext"]
            block_lengths = self.loaded_encrypted_data["block_lengths"]

            # Dekripsi Blok RSA Manual
            decrypted_bytes, trace = RSAMathEngine.decrypt_bytes(ciphertext_blocks, block_lengths, d, n)

            # Decode UTF-8 & Parse JSON
            raw_json_str = decrypted_bytes.decode("utf-8")
            payroll = json.loads(raw_json_str)

            # Format Tampilan Kartu Slip Gaji
            self._render_payroll_card(payroll)

            # Log ke Tab Inspector
            self._log_math("\n" + "="*70)
            self._log_math(f"[{datetime.now().strftime('%H:%M:%S')}] PROSES DEKRIPSI SLIP GAJI DI SISI KARYAWAN")
            self._log_math("="*70)
            self._log_math(f"Jumlah Blok Didekripsi: {len(ciphertext_blocks)}")
            self._log_math("Contoh Perhitungan Dekripsi 2 Blok Pertama:")
            for sample in trace[:2]:
                self._log_math(f"  * Blok #{sample['index']}:")
                self._log_math(f"    - Ciphertext Input: {sample['c_int']}")
                self._log_math(f"    - Rumus: m_{sample['index']} = (c_{sample['index']} ^ d) mod n")
                self._log_math(f"    - Plaintext Integer Pulih: {sample['m_int']}")

            messagebox.showinfo("Berhasil", "Slip Gaji berhasil didekripsi dan diverifikasi!")
        except json.JSONDecodeError:
            messagebox.showerror("Dekripsi Gagal", "Private Key salah! Dekripsi menghasilkan data byte yang rusak / tidak sah.")
        except Exception as ex:
            messagebox.showerror("Error Dekripsi", f"Gagal mendekripsi: {str(ex)}")

    def _render_payroll_card(self, data: dict):
        rincian = data["rincian"]
        card_text = (
            "=====================================================================\n"
            "                 PT. TEKNOLOGI INFORMASI JAYA                   \n"
            "                     SLIP GAJI KARYAWAN                        \n"
            "               STATUS KEAMANAN: TERVERIFIKASI             \n"
            "=====================================================================\n"
            f" ID              : {data.get('id')}\n"
            f" Nama Karyawan    : {data.get('nama')}\n"
            f" Jabatan / Divisi : {data.get('jabatan')}\n"
            f" Periode Gaji     : {data.get('periode')}\n"
            f" Tanggal Terbit   : {data.get('timestamp')}\n"
            "---------------------------------------------------------------------\n"
            " RINCIAN PENDAPATAN (EARNINGS):\n"
            f"  + Gaji Pokok                         : Rp {rincian['gaji_pokok']:>14,.2f}\n"
            f"  + Tunjangan Jabatan & Operasional    : Rp {rincian['tunjangan']:>14,.2f}\n"
            f"  TOTAL PENDAPATAN KOTOR (GROSS)       : Rp {(rincian['gaji_pokok'] + rincian['tunjangan']):>14,.2f}\n"
            "---------------------------------------------------------------------\n"
            " RINCIAN PEMOTONGAN (DEDUCTIONS):\n"
            f"  - Iuran Jaminan Sosial (BPJS)        : Rp {rincian['potongan_bpjs']:>14,.2f}\n"
            f"  - Pajak Penghasilan (PPh 21)         : Rp {rincian['potongan_pph']:>14,.2f}\n"
            f"  TOTAL POTONGAN                      : Rp {(rincian['potongan_bpjs'] + rincian['potongan_pph']):>14,.2f}\n"
            "=====================================================================\n"
            f" GAJI BERSIH DITERIMA (TAKE HOME PAY)  : Rp {rincian['take_home_pay']:>14,.2f}\n"
            "=====================================================================\n"
            f" Catatan HRD:\n \"{data.get('catatan')}\"\n"
            "---------------------------------------------------------------------\n"
            " Berkas didekripsi secara lokal menggunakan Private Key sah milik karyawan.\n"
            "=====================================================================\n"
        )
        self.txt_slip_display.delete("1.0", tk.END)
        self.txt_slip_display.insert(tk.END, card_text)


# =============================================================================
# ENTRY POINT UTAMA
# =============================================================================
if __name__ == "__main__":
    app = SecurePayrollApp()
    app.mainloop()