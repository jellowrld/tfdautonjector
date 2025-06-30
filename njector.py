import os
import psutil
import traceback
import threading
import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk
from ctypes import *

PAGE_READWRITE = 0x04
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
VIRTUAL_MEM = (0x1000 | 0x2000)
LIST_MODULES_ALL = 0x03

class DLLInjectorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Jell's TFD Njector")
        self.root.geometry("580x325")
        self.root.configure(bg="#1e1e1e")
        self.dll_path = tk.StringVar()
        self.injection_done = False
        self.injected_pid = None
        self.injected_dll_base = None

        self.setup_winapi()
        self.build_ui()
        self.load_last_dll_path()  # Load last DLL path on startup
        self.start_auto_inject_thread()

    def build_ui(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")

        self.style.configure("TLabel", background="#1e1e1e", foreground="#ffffff", font=("Segoe UI", 10))
        self.style.configure("TButton", background="#2e2e2e", foreground="#ffffff", font=("Segoe UI", 10), borderwidth=0, padding=6)
        self.style.map("TButton", background=[('active', '#3e3e3e')])
        self.style.configure("TEntry", fieldbackground="#2e2e2e", foreground="#ffffff", insertcolor="#ffffff")

        ttk.Label(self.root, text="💉 DLL to inject:").pack(pady=(15, 5))
        entry_frame = tk.Frame(self.root, bg="#1e1e1e")
        entry_frame.pack(padx=10)

        entry = ttk.Entry(entry_frame, textvariable=self.dll_path, width=52, font=("Segoe UI", 10))
        entry.pack(side="left", padx=(0, 5))

        ttk.Button(entry_frame, text="📂 Browse", command=self.browse_dll).pack(side="left")

        ttk.Button(self.root, text="🚀 Launch TFD", command=self.launch_game).pack(pady=(20, 5))

        self.console = scrolledtext.ScrolledText(self.root, height=10, bg="#2e2e2e", fg="#ffffff", insertbackground="#ffffff",
                                                  font=("Consolas", 9), bd=0, relief="flat")
        self.console.pack(padx=10, pady=(15, 10), fill="both", expand=True)
        self.console.config(state='disabled')

    def log(self, message):
        self.console.config(state='normal')
        self.console.insert('end', message + '\n')
        self.console.yview('end')
        self.console.config(state='disabled')
        print(message)

    def browse_dll(self):
        file_path = filedialog.askopenfilename(filetypes=[("DLL files", "*.dll")])
        if file_path:
            self.dll_path.set(file_path)
            self.save_last_dll_path(file_path)  # Save path after browsing

    def launch_game(self):
        try:
            os.system("start steam://run/2074920")
            self.log("[+] Launch command sent to Steam.")
        except Exception as e:
            self.log(f"[!] Failed to launch game: {e}")

    def get_process_info_by_name(self, process_name):
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] == process_name:
                return proc
        return None

    def setup_winapi(self):
        self.kernel32 = windll.kernel32
        self.psapi = windll.psapi

        self.kernel32.OpenProcess.argtypes = [c_ulong, c_bool, c_ulong]
        self.kernel32.OpenProcess.restype = c_void_p

        self.kernel32.VirtualAllocEx.argtypes = [c_void_p, c_void_p, c_size_t, c_ulong, c_ulong]
        self.kernel32.VirtualAllocEx.restype = c_void_p

        self.kernel32.WriteProcessMemory.argtypes = [c_void_p, c_void_p, c_void_p, c_size_t, POINTER(c_size_t)]
        self.kernel32.WriteProcessMemory.restype = c_bool

        self.kernel32.GetModuleHandleW.argtypes = [c_wchar_p]
        self.kernel32.GetModuleHandleW.restype = c_void_p

        self.kernel32.GetProcAddress.argtypes = [c_void_p, c_char_p]
        self.kernel32.GetProcAddress.restype = c_void_p

        self.kernel32.CreateRemoteThread.argtypes = [c_void_p, c_void_p, c_size_t, c_void_p, c_void_p, c_ulong, POINTER(c_ulong)]
        self.kernel32.CreateRemoteThread.restype = c_void_p

        self.psapi.EnumProcessModulesEx.argtypes = [c_void_p, POINTER(c_void_p), c_ulong, POINTER(c_ulong), c_ulong]
        self.psapi.EnumProcessModulesEx.restype = c_bool

        self.psapi.GetModuleBaseNameW.argtypes = [c_void_p, c_void_p, c_wchar_p, c_ulong]
        self.psapi.GetModuleBaseNameW.restype = c_ulong

    def save_last_dll_path(self, path):
        try:
            with open("last_dll_path.txt", "w") as f:
                f.write(path)
        except Exception as e:
            self.log(f"[!] Failed to save last DLL path: {e}")

    def load_last_dll_path(self):
        try:
            if os.path.isfile("last_dll_path.txt"):
                with open("last_dll_path.txt", "r") as f:
                    path = f.read().strip()
                    if os.path.isfile(path):
                        self.dll_path.set(path)
        except Exception as e:
            self.log(f"[!] Failed to load last DLL path: {e}")

    def inject_dll(self):
        dll_path = self.dll_path.get().strip()
        if not os.path.isfile(dll_path): 
            self.log("[!] DLL path is invalid or file does not exist.")
            return

        self.save_last_dll_path(dll_path)  # Save path before injection starts

        target_proc = self.get_process_info_by_name("M1-Win64-Shipping.exe")
        if not target_proc:
            self.log("[!] Target process not found.")
            return

        PID = target_proc.info['pid']
        dll_bytes = dll_path.encode('ascii') + b'\x00'
        dll_length = len(dll_bytes)

        h_process = self.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, PID)
        if not h_process:
            self.log(f"[!] Could not open process {PID}")
            return

        alloc_address = self.kernel32.VirtualAllocEx(h_process, None, dll_length, VIRTUAL_MEM, PAGE_READWRITE)
        if not alloc_address:
            self.log("[!] Memory allocation failed.")
            return

        bytes_written = c_size_t(0)
        if not self.kernel32.WriteProcessMemory(h_process, alloc_address, dll_bytes, dll_length, byref(bytes_written)):
            self.log("[!] Failed to write DLL path into memory.")
            return

        h_kernel32 = self.kernel32.GetModuleHandleW("kernel32.dll")
        h_loadlib = self.kernel32.GetProcAddress(h_kernel32, b"LoadLibraryA")
        if not h_loadlib:
            self.log("[!] Could not resolve LoadLibraryA.")
            return

        thread_id = c_ulong(0)
        if not self.kernel32.CreateRemoteThread(h_process, None, 0, h_loadlib, alloc_address, 0, byref(thread_id)):
            self.log("[!] Remote thread creation failed.")
            return

        self.log("[+] DLL injected.")
        self.injected_pid = PID
        self.injection_done = True
        threading.Timer(3.0, self.locate_injected_dll, [dll_path, h_process]).start()

    def locate_injected_dll(self, dll_path, h_process):
        dll_name = os.path.basename(dll_path)
        module_handles = (c_void_p * 1024)()
        cb = sizeof(module_handles)
        cb_needed = c_ulong(0)

        if not self.psapi.EnumProcessModulesEx(h_process, module_handles, cb, byref(cb_needed), LIST_MODULES_ALL):
            return

        module_count = cb_needed.value // sizeof(c_void_p)
        for i in range(module_count):
            mod_name = create_unicode_buffer(260)
            self.psapi.GetModuleBaseNameW(h_process, module_handles[i], mod_name, sizeof(mod_name) // 2)
            if mod_name.value.lower() == dll_name.lower():
                self.injected_dll_base = module_handles[i]
                self.log(f"[+] DLL loaded at: 0x{self.injected_dll_base:08X}")
                return

    def monitor_uninject(self):
        import time
        while True:
            if self.injection_done and self.injected_pid and not psutil.pid_exists(self.injected_pid):
                self.uninject_dll()
                break
            time.sleep(1)

    def uninject_dll(self):
        if not self.injected_dll_base:
            return
        h_freelib = self.kernel32.GetProcAddress(self.kernel32.GetModuleHandleW("kernel32.dll"), b"FreeLibrary")
        if not h_freelib:
            self.log("[!] Could not resolve FreeLibrary.")
            return

        h_process = self.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.injected_pid)
        thread_id = c_ulong(0)
        if self.kernel32.CreateRemoteThread(h_process, None, 0, h_freelib, self.injected_dll_base, 0, byref(thread_id)):
            self.log("[+] DLL automatically uninjected.")
        else:
            self.log("[!] Failed to auto-uninject.")

    def start_auto_inject_thread(self):
        def monitor():
            import time
            while True:
                if not self.injection_done:
                    proc = self.get_process_info_by_name("M1-Win64-Shipping.exe")
                    if proc:
                        self.log("[i] Target process found. Injecting...")
                        self.inject_dll()
                        threading.Thread(target=self.monitor_uninject, daemon=True).start()
                time.sleep(2)
        threading.Thread(target=monitor, daemon=True).start()

if __name__ == '__main__':
    try:
        root = tk.Tk()
        app = DLLInjectorGUI(root)
        root.mainloop()
    except Exception:
        print("[!] Uncaught Exception:\n" + traceback.format_exc())
