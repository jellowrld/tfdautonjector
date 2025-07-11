import os
import psutil
import threading
import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk
from ctypes import *
import platform
import logging
import traceback
from pathlib import Path
import pefile
import random
import hashlib

# Windows API constants
PAGE_EXECUTE_READWRITE = 0x40
PROCESS_ALL_ACCESS = 0x1F0FFF
VIRTUAL_MEM = 0x3000  # MEM_COMMIT | MEM_RESERVE
MEM_RELEASE = 0x8000
LIST_MODULES_ALL = 0x03
CONTEXT_CONTROL = 0x10001

class DLLInjectorGUI:
    def __init__(self, root):
        if platform.system() != "Windows":
            raise OSError("This tool only supports Windows.")

        self.root = root
        self.root.title("Jell's TFD Manual DLL Injector (Enhanced)")
        self.root.geometry("600x350")
        self.root.configure(bg="#1e1e1e")
        self.dll_path = tk.StringVar()
        self.injection_done = False
        self.injected_pid = None
        self.injected_dll_base = None
        self.lock = threading.Lock()

        self.setup_logging()
        self.setup_winapi()
        self.build_ui()
        self.load_last_dll_path()
        self.start_auto_inject_thread()

    def setup_logging(self):
        self.logger = logging.getLogger("DLLInjector")
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        config_dir = Path(os.path.expanduser("~/.dll_injector"))
        config_dir.mkdir(exist_ok=True)
        file_handler = logging.FileHandler(config_dir / "injector.log")
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

    def log(self, message, level="info"):
        def update_gui():
            self.console.config(state="normal")
            self.console.insert("end", f"{message}\n")
            self.console.yview("end")
            self.console.config(state="disabled")
        self.root.after(0, update_gui)
        getattr(self.logger, level.lower())(message)

    def setup_winapi(self):
        self.kernel32 = windll.kernel32
        self.psapi = windll.psapi

        self.kernel32.OpenProcess.argtypes = [c_ulong, c_bool, c_ulong]
        self.kernel32.OpenProcess.resType = c_void_p

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

        self.kernel32.VirtualFreeEx.argtypes = [c_void_p, c_void_p, c_size_t, c_ulong]
        self.kernel32.VirtualFreeEx.restype = c_bool

        self.kernel32.CloseHandle.argtypes = [c_void_p]
        self.kernel32.CloseHandle.restype = c_bool

        self.psapi.EnumProcessModulesEx.argtypes = [c_void_p, POINTER(c_void_p), c_ulong, POINTER(c_ulong), c_ulong]
        self.psapi.EnumProcessModulesEx.restype = c_bool

        self.psapi.GetModuleBaseNameW.argtypes = [c_void_p, c_void_p, c_wchar_p, c_ulong]
        self.psapi.GetModuleBaseNameW.restype = c_ulong

        self.kernel32.OpenThread.argtypes = [c_ulong, c_bool, c_ulong]
        self.kernel32.OpenThread.restype = c_void_p

        self.kernel32.SuspendThread.argtypes = [c_void_p]
        self.kernel32.SuspendThread.restype = c_ulong

        self.kernel32.ResumeThread.argtypes = [c_void_p]
        self.kernel32.ResumeThread.restype = c_ulong

        self.kernel32.GetThreadContext.argtypes = [c_void_p, POINTER(c_void_p)]
        self.kernel32.GetThreadContext.restype = c_bool

        self.kernel32.SetThreadContext.argtypes = [c_void_p, POINTER(c_void_p)]
        self.kernel32.SetThreadContext.restype = c_bool

    def build_ui(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TLabel", background="#1e1e1e", foreground="#ffffff", font=("Segoe UI", 10))
        self.style.configure("TButton", background="#2e2e2e", foreground="#ffffff", font=("Segoe UI", 10), borderwidth=0, padding=6)
        self.style.map("TButton", background=[("active", "#3e3e3e")])
        self.style.configure("TEntry", fieldbackground="#2e2e2e", foreground="#ffffff", insertcolor="#ffffff")

        ttk.Label(self.root, text="⚠️ Use responsibly. For educational purposes only.", foreground="#ff4444").pack(pady=(10, 5))
        ttk.Label(self.root, text="💉 DLL to inject:").pack(pady=(5, 5))
        entry_frame = tk.Frame(self.root, bg="#1e1e1e")
        entry_frame.pack(padx=10, fill="x")
        entry = ttk.Entry(entry_frame, textvariable=self.dll_path, width=50, font=("Segoe UI", 10))
        entry.pack(side="left", padx=(0, 5))
        ttk.Button(entry_frame, text="📂 Browse", command=self.browse_dll).pack(side="left")

        ttk.Label(self.root, text="🎮 Target process:").pack(pady=(10, 5))
        self.process_name = tk.StringVar(value="M1-Win64-Shipping.exe")
        ttk.Entry(self.root, textvariable=self.process_name, width=50, font=("Segoe UI", 10)).pack(padx=10)

        ttk.Button(self.root, text="🚀 Launch TFD", command=self.launch_game).pack(pady=(10, 5))

        self.console = scrolledtext.ScrolledText(self.root, height=10, bg="#2e2e2e", fg="#ffffff", 
                                                insertbackground="#ffffff", font=("Consolas", 9), bd=0, relief="flat")
        self.console.pack(padx=10, pady=(10, 10), fill="both", expand=True)
        self.console.config(state="disabled")

    def browse_dll(self):
        file_path = filedialog.askopenfilename(filetypes=[("DLL files", "*.dll")])
        if file_path:
            self.dll_path.set(file_path)
            self.save_last_dll_path(file_path)

    def launch_game(self):
        try:
            os.system("start steam://run/2074920")
            self.log("Launch command sent to Steam.")
        except Exception as e:
            self.log(f"Failed to launch game: {e}", level="error")

    def save_last_dll_path(self, path):
        try:
            config_dir = Path(os.path.expanduser("~/.dll_injector"))
            config_dir.mkdir(exist_ok=True)
            with open(config_dir / "last_dll_path.txt", "w") as f:
                f.write(path)
            self.log(f"Saved DLL path: {path}")
        except Exception as e:
            self.log(f"Failed to save DLL path: {e}", level="error")

    def load_last_dll_path(self):
        try:
            config_file = Path(os.path.expanduser("~/.dll_injector/last_dll_path.txt"))
            if config_file.is_file():
                with open(config_file, "r") as f:
                    path = f.read().strip()
                    if os.path.isfile(path):
                        self.dll_path.set(path)
                        self.log(f"Loaded DLL path: {path}")
        except Exception as e:
            self.log(f"Failed to load DLL path: {e}", level="error")

    def get_process_info_by_name(self, process_name):
        for proc in psutil.process_iter(["pid", "name"]):
            if proc.info["name"].lower() == process_name.lower():
                return proc
        return None

    def wait_for_process_stable(self, process_name):
 import time
        for _ in range(10):
            proc = self.get_process_info_by_name(process_name)
            if proc and psutil.pid_exists(proc.info["pid"]):
                try:
                    proc.memory_maps()  # Check if main module is loaded
                    time.sleep(1)
                    return proc
                except:
                    pass
            time.sleep(1)
        return None

    def encrypt_data(self, data):
        # Simple XOR encryption (for educational purposes)
        return bytes(b ^ 0xFF for b in data)

    def generate_decrypt_shellcode(self, data_addr, data_size):
        # Simple XOR decryption shellcode (x64)
        # mov rax, data_addr
        # mov rcx, data_size
        # loop: xor byte ptr [rax], 0xFF
        # inc rax
        # loop loop
        # ret
        shellcode = (
            b"\x48\xB8" + c_uint64(data_addr).value.to_bytes(8, "little") +  # mov rax, data_addr
            b"\x48\xB9" + c_uint64(data_size).value.to_bytes(8, "little") +  # mov rcx, data_size
            b"\x80\x30\xFF" +  # xor byte ptr [rax], 0xFF
            b"\x48\xFF\xC0" +  # inc rax
            b"\xE2\xF9" +      # loop loop
            b"\xC3"            # ret
        )
        return shellcode

    def get_api_address(self, h_module, api_name):
        # Hash-based API resolution to avoid hardcoded strings
        api_hash = hashlib.sha256(api_name.encode()).hexdigest()
        # In a real implementation, iterate exports to match hash
        # Simplified: use GetProcAddress with original name
        return self.kernel32.GetProcAddress(h_module, api_name.encode())

    def apply_relocations(self, pe, h_process, remote_base, delta):
        reloc_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']]
        if not reloc_dir.VirtualAddress:
            return

        is_32bit = pe.OPTIONAL_HEADER.Magic == 0x10B
        reloc_data = pe.get_data(reloc_dir.VirtualAddress, reloc_dir.Size)
        offset = 0
        while offset < reloc_dir.Size:
            block = pe.__unpack_data__(pefile.Structure(pe.__IMAGE_BASE_RELOCATION_format__), reloc_data[offset:])
            offset += sizeof(pefile.Structure(pe.__IMAGE_BASE_RELOCATION_format__))
            entry_count = (block.SizeOfBlock - sizeof(pefile.Structure(pe.__IMAGE_BASE_RELOCATION_format__))) // 2
            for i in range(entry_count):
                entry = pe.__unpack_data__(pefile.Structure(pe.__IMAGE_REL_BASED_format__), reloc_data[offset:offset+2])
                offset += 2
                if (is_32bit and entry.Type == 3) or (not is_32bit and entry.Type == 10):  # IMAGE_REL_BASED_HIGHLOW or DIR64
                    reloc_addr = remote_base + block.VirtualAddress + entry.Offset
                    size = sizeof(c_uint32) if is_32bit else sizeof(c_uint64)
                    value_type = c_uint32 if is_32bit else c_uint64
                    old_value = value_type()
                    self.kernel32.ReadProcessMemory(h_process, reloc_addr, byref(old_value), size, None)
                    new_value = old_value.value + delta
                    self.kernel32.WriteProcessMemory(h_process, reloc_addr, byref(value_type(new_value)), size, None)

    def resolve_imports(self, pe, h_process, remote_base):
        import_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']]
        if not import_dir.VirtualAddress:
            return True

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode()
            h_module = self.kernel32.GetModuleHandleW(dll_name)
            if not h_module:
                h_module = self.kernel32.LoadLibraryW(dll_name)
                if not h_module:
                    self.log(f"Failed to load {dll_name}: {self.get_last_error()}", level="error")
                    return False

            for imp in entry.imports:
                if imp.name:
                    func_addr = self.get_api_address(h_module, imp.name.decode())
                    if not func_addr:
                        self.log(f"Failed to resolve {imp.name.decode()} in {dll_name}: {self.get_last_error()}", level="error")
                        return False
                    size = sizeof(c_uint32) if pe.OPTIONAL_HEADER.Magic == 0x10B else sizeof(c_uint64)
                    self.kernel32.WriteProcessMemory(h_process, remote_base + imp.address, byref(c_uint64(func_addr)), size, None)

        # Handle delayed imports (simplified)
        delay_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT']]
        if delay_dir.VirtualAddress:
            # Similar logic to regular imports (omitted for brevity)
            pass

        return True

    def hijack_thread(self, h_process, thread_id, entry_point):
        h_thread = self.kernel32.OpenThread(PROCESS_ALL_ACCESS, False, thread_id)
        if not h_thread:
            self.log(f"Failed to open thread: {self.get_last_error()}", level="error")
            return False

        try:
            self.kernel32.SuspendThread(h_thread)
            context = CONTEXT()
            context.ContextFlags = CONTEXT_CONTROL
            if not self.kernel32.GetThreadContext(h_thread, byref(context)):
                self.log(f"Failed to get thread context: {self.get_last_error()}", level="error")
                return False

            context.Rip = entry_point
            if not self.kernel32.SetThreadContext(h_thread, byref(context)):
                self.log(f"Failed to set thread context: {self.get_last_error()}", level="error")
                return False

            self.kernel32.ResumeThread(h_thread)
            return True
        finally:
            self.kernel32.CloseHandle(h_thread)

    def manual_map_dll(self, dll_path, pid):
        try:
            pe = pefile.PE(dll_path, fast_load=True)
            image_size = pe.OPTIONAL_HEADER.SizeOfImage
            entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint

            h_process = self.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not h_process:
                self.log(f"Could not open process {pid}: {self.get_last_error()}", level="error")
                return False

            try:
                # Randomize memory allocation with padding
                padding = random.randint(0, 4096)
                remote_base = self.kernel32.VirtualAllocEx(h_process, None, image_size + padding, VIRTUAL_MEM, PAGE_EXECUTE_READWRITE)
                if not remote_base:
                    self.log(f"Memory allocation failed: {self.get_last_error()}", level="error")
                    return False

                # Write headers (encrypted)
                headers = self.encrypt_data(pe.generate_image())
                if not self.kernel32.WriteProcessMemory(h_process, remote_base, headers, len(headers), None):
                    self.log(f"Failed to write headers: {self.get_last_error()}", level="error")
                    return False

                # Write sections (encrypted) and decryption shellcode
                for section in pe.sections:
                    section_data = self.encrypt_data(section.get_data())
                    section_addr = remote_base + section.VirtualAddress
                    if not self.kernel32.WriteProcessMemory(h_process, section_addr, section_data, len(section_data), None):
                        self.log(f"Failed to write section {section.Name.decode()}: {self.get_last_error()}", level="error")
                        return False

                    # Write decryption shellcode for each section
                    shellcode = self.generate_decrypt_shellcode(section_addr, len(section_data))
                    shellcode_addr = remote_base + image_size + padding - 4096
                    if not self.kernel32.WriteProcessMemory(h_process, shellcode_addr, shellcode, len(shellcode), None):
                        self.log(f"Failed to write decryption shellcode: {self.get_last_error()}", level="error")
                        return False

                    # Execute decryption shellcode via thread hijacking
                    threads = psutil.Process(pid).threads()
                    if not threads:
                        self.log("No threads found for hijacking.", level="error")
                        return False
                    if not self.hijack_thread(h_process, threads[0].id, shellcode_addr):
                        return False

                # Handle relocations
                if pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']].VirtualAddress:
                    delta = remote_base - pe.OPTIONAL_HEADER.ImageBase
                    self.apply_relocations(pe, h_process, remote_base, delta)

                # Resolve imports
                if not self.resolve_imports(pe, h_process, remote_base):
                    self.log("Failed to resolve imports.", level="error")
                    return False

                # Execute DllMain via thread hijacking
                dllmain_addr = remote_base + entry_point
                if not self.hijack_thread(h_process, threads[0].id, dllmain_addr):
                    self.log("Failed to execute DllMain.", level="error")
                    return False

                with self.lock:
                    self.injected_dll_base = remote_base
                self.log(f"DLL manually mapped at 0x{remote_base:08X}")
                return True

            finally:
                self.kernel32.CloseHandle(h_process)

        except Exception as e:
            self.log(f"Manual mapping failed: {e}", level="error")
            return False

    def get_last_error(self):
        err = self.kernel32.GetLastError()
        return f"Error {err}"

    def inject_dll(self):
        dll_path = self.dll_path.get().strip()
        if not os.path.isfile(dll_path):
            self.log("DLL path is invalid or file does not exist.", level="error")
            return

        self.save_last_dll_path(dll_path)
        target_proc = self.wait_for_process_stable(self.process_name.get())
        if not target_proc:
            self.log("Target process not found or not stable.", level="error")
            return

        PID = target_proc.info["pid"]
        if self.manual_map_dll(dll_path, PID):
            with self.lock:
                self.injected_pid = PID
                self.injection_done = True
            threading.Timer(3.0, self.locate_injected_dll, [dll_path, PID]).start()

    def locate_injected_dll(self, dll_path, pid):
        dll_name = os.path.basename(dll_path)
        h_process = self.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not h_process:
            self.log(f"Could not open process for module enumeration: {self.get_last_error()}", level="error")
            return

        try:
            module_handles = (c_void_p * 1024)()
            cb = sizeof(module_handles)
            cb_needed = c_ulong(0)

            if not self.psapi.EnumProcessModulesEx(h_process, module_handles, cb, byref(cb_needed), LIST_MODULES_ALL):
                self.log(f"Failed to enumerate modules: {self.get_last_error()}", level="error")
                return

            module_count = cb_needed.value // sizeof(c_void_p)
            for i in range(module_count):
                mod_name = create_unicode_buffer(260)
                self.psapi.GetModuleBaseNameW(h_process, module_handles[i], mod_name, sizeof(mod_name) // 2)
                if mod_name.value.lower() == dll_name.lower():
                    with self.lock:
                        self.injected_dll_base = module_handles[i]
                    self.log(f"DLL located at: 0x{self.injected_dll_base:08X}")
                    return
            self.log("Could not locate injected DLL (expected for manual mapping).", level="warning")
        finally:
            self.kernel32.CloseHandle(h_process)

    def uninject_dll(self):
        with self.lock:
            if not self.injected_dll_base or not self.injected_pid:
                return

        h_process = self.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.injected_pid)
        if not h_process:
            self.log(f"Could not open process for uninjection: {self.get_last_error()}", level="error")
            return

        try:
            if self.kernel32.VirtualFreeEx(h_process, self.injected_dll_base, 0, MEM_RELEASE):
                self.log("DLL memory freed.")
            else:
                self.log(f"Failed to free DLL memory: {self.get_last_error()}", level="error")
        finally:
            with self.lock:
                self.injection_done = False
                self.injected_pid = None
                self.injected_dll_base = None
            self.kernel32.CloseHandle(h_process)

    def monitor_uninject(self):
        while True:
            with self.lock:
                if self.injection_done and self.injected_pid and not psutil.pid_exists(self.injected_pid):
                    self.log("Target process terminated. Freeing DLL memory.")
                    self.uninject_dll()
                    break
            time.sleep(1)

    def start_auto_inject_thread(self):
        def monitor():
            while True:
                with self.lock:
                    if not self.injection_done:
                        proc = self.get_process_info_by_name(self.process_name.get())
                        if proc:
                            self.log(f"Target process found (PID: {proc.info['pid']}). Injecting...")
                            self.inject_dll()
                            threading.Thread(target=self.monitor_uninject, daemon=True).start()
                time.sleep(2)
        threading.Thread(target=monitor, daemon=True).start()

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = DLLInjectorGUI(root)
        root.mainloop()
    except Exception:
        logging.error("Uncaught exception:\n%s", traceback.format_exc())