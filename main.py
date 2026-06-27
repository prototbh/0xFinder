import sys
import customtkinter as ctk
import ctypes
from ctypes import wintypes, windll, create_string_buffer, c_size_t, Structure
from ctypes.wintypes import DWORD
from dataclasses import dataclass
import tkinter as tk
import os
import time
import requests
from typing import List, Optional
import threading
import struct
from tkinter import filedialog, messagebox
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def run_as_admin():
    script = sys.argv[0]
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, script, None, 1)

if not is_admin():
    run_as_admin()
    sys.exit()

PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READONLY = 0x02
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_WRITECOPY = 0x80
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_PRIVATE = 0x20000
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
PROCESS_ALL_ACCESS = 0x1F0FFF

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
OpenProcess.restype = ctypes.c_void_p
VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
VirtualAllocEx.restype = ctypes.c_void_p
WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
WriteProcessMemory.restype = ctypes.c_int
GetProcAddress = kernel32.GetProcAddress
GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
GetProcAddress.restype = ctypes.c_void_p
GetModuleHandle = kernel32.GetModuleHandleA
GetModuleHandle.argtypes = [ctypes.c_char_p]
GetModuleHandle.restype = ctypes.c_void_p
CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
CreateRemoteThread.restype = ctypes.c_void_p
WaitForSingleObject = kernel32.WaitForSingleObject
WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
WaitForSingleObject.restype = ctypes.c_ulong
CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [ctypes.c_void_p]
CloseHandle.restype = ctypes.c_int
ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = ctypes.c_int
VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
VirtualQueryEx.restype = ctypes.c_size_t

STRUCT_FORMATS = {
    'i': struct.Struct('<i'),
    'I': struct.Struct('<I'),
    'h': struct.Struct('<h'),
    'H': struct.Struct('<H'),
    'f': struct.Struct('<f'),
    'd': struct.Struct('<d'),
    'q': struct.Struct('<q'),
    'Q': struct.Struct('<Q'),
}

@dataclass
class Window:
    hwnd: int
    title: str
    process_id: int

class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("BaseAddress", c_size_t),
        ("AllocationBase", c_size_t),
        ("AllocationProtect", DWORD),
        ("RegionSize", c_size_t),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
    ]

class MemoryFinder:
    def __init__(self):
        self.buffer_size = 1024 * 1024 * 64
        self.value_type = "i"
        self.value_size = 4
        self.found_addresses = []
        self.thread_count = os.cpu_count() or 8
        self.progress_callback = None
        self.cancel_scan = False
        self._cached_struct = STRUCT_FORMATS.get('i')
        
    def set_value_type(self, vtype: str):
        self.value_type = vtype
        self._cached_struct = STRUCT_FORMATS.get(vtype)
        if self._cached_struct:
            self.value_size = self._cached_struct.size

    def get_all_windows(self) -> List[Window]:
        windows = []
        def enum_windows_callback(hwnd, _):
            if windll.user32.IsWindowVisible(hwnd):
                length = windll.user32.GetWindowTextLengthW(hwnd)
                if length > 0:
                    title = create_string_buffer(length + 1)
                    windll.user32.GetWindowTextA(hwnd, title, length + 1)
                    process_id = DWORD()
                    windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(process_id))
                    windows.append(Window(hwnd, title.value.decode(), process_id.value))
            return True
        WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        windll.user32.EnumWindows(WNDENUMPROC(enum_windows_callback), 0)
        return windows

    def _fast_find_all(self, buffer_data: bytes, pattern: bytes, base_addr: int) -> List[int]:
        addresses = []
        if HAS_NUMPY and len(pattern) <= 8:
            arr = np.frombuffer(buffer_data, dtype=np.uint8)
            pattern_arr = np.frombuffer(pattern, dtype=np.uint8)
            pattern_len = len(pattern)
            if len(arr) >= pattern_len:
                for i in range(pattern_len):
                    if i == 0:
                        matches = arr[i:len(arr) - pattern_len + 1 + i] == pattern_arr[i]
                    else:
                        matches &= arr[i:len(arr) - pattern_len + 1 + i] == pattern_arr[i]
                indices = np.where(matches)[0]
                addresses = [base_addr + int(idx) for idx in indices]
        else:
            offset = 0
            pattern_len = len(pattern)
            while True:
                offset = buffer_data.find(pattern, offset)
                if offset == -1:
                    break
                addresses.append(base_addr + offset)
                offset += max(1, pattern_len if pattern_len > 8 else self.value_size)
        return addresses

    def _scan_region_fast(self, handle, start_addr: int, size: int, desired_bytes: bytes) -> List[int]:
        addresses = []
        try:
            buffer = (ctypes.c_char * size)()
            bytes_read = c_size_t(0)
            if ReadProcessMemory(handle, ctypes.c_void_p(start_addr), buffer, size, ctypes.byref(bytes_read)):
                if bytes_read.value > 0:
                    buffer_data = bytes(buffer)[:bytes_read.value]
                    addresses = self._fast_find_all(buffer_data, desired_bytes, start_addr)
        except Exception:
            pass
        return addresses

    def _scan_chunk(self, handle, regions: List[tuple], desired_bytes: bytes) -> List[int]:
        addresses = []
        for start_addr, size in regions:
            if self.cancel_scan:
                break
            addresses.extend(self._scan_region_fast(handle, start_addr, size, desired_bytes))
        return addresses

    def _get_scannable_regions(self, handle) -> List[tuple]:
        regions = []
        address = 0
        mbi = MEMORY_BASIC_INFORMATION()
        mbi_size = ctypes.sizeof(mbi)
        readable_protections = (
            PAGE_READWRITE | PAGE_EXECUTE_READWRITE | 
            PAGE_READONLY | PAGE_EXECUTE_READ | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY
        )
        max_address = 0x7FFFFFFFFFFF if ctypes.sizeof(ctypes.c_void_p) == 8 else 0x7FFFFFFF
        
        while address < max_address:
            result = VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), mbi_size)
            if result == 0:
                break
            if (mbi.State & MEM_COMMIT and 
                mbi.Protect & readable_protections and
                not (mbi.Protect & 0x100) and
                mbi.RegionSize > 0):
                chunk_start = mbi.BaseAddress
                remaining = mbi.RegionSize
                while remaining > 0:
                    chunk_size = min(self.buffer_size, remaining)
                    regions.append((chunk_start, chunk_size))
                    chunk_start += chunk_size
                    remaining -= chunk_size
            address = mbi.BaseAddress + mbi.RegionSize
            if address <= mbi.BaseAddress:
                break
        return regions

    def memory_search(self, process_id: int, desired_value, search_addresses=None, progress_callback=None) -> List[int]:
        self.cancel_scan = False
        self.progress_callback = progress_callback
        
        handle = OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
            False, process_id & 0xFFFFFFFF
        )
        if not handle:
            return []

        try:
            if search_addresses:
                return self._search_specific_addresses_fast(handle, search_addresses, desired_value)
            
            regions = self._get_scannable_regions(handle)
            total_regions = len(regions)
            
            if isinstance(desired_value, str):
                desired_bytes = desired_value.encode("utf-8")
            elif self._cached_struct:
                desired_bytes = self._cached_struct.pack(desired_value)
            else:
                desired_bytes = struct.pack(f'<{self.value_type}', desired_value)

            chunk_size = max(1, total_regions // self.thread_count)
            region_chunks = [regions[i:i + chunk_size] for i in range(0, total_regions, chunk_size)]
            
            all_addresses = []
            completed = 0
            
            with ThreadPoolExecutor(max_workers=self.thread_count) as executor:
                futures = {executor.submit(self._scan_chunk, handle, chunk, desired_bytes): i 
                          for i, chunk in enumerate(region_chunks)}
                
                for future in as_completed(futures):
                    if self.cancel_scan:
                        break
                    result = future.result()
                    all_addresses.extend(result)
                    completed += 1
                    if progress_callback:
                        progress_callback(completed, len(region_chunks))
            
            return sorted(all_addresses)
        finally:
            CloseHandle(handle)

    def _search_specific_addresses_fast(self, handle, addresses: List[int], desired_value) -> List[int]:
        results = []
        
        if isinstance(desired_value, str):
            desired_bytes = desired_value.encode("utf-8")
            buffer_size = len(desired_bytes)
            for addr in addresses:
                if self.cancel_scan:
                    break
                buffer = (ctypes.c_char * buffer_size)()
                bytes_read = c_size_t(0)
                if ReadProcessMemory(handle, ctypes.c_void_p(addr), buffer, buffer_size, ctypes.byref(bytes_read)):
                    if bytes(buffer)[:bytes_read.value] == desired_bytes:
                        results.append(addr)
        else:
            buffer_size = self.value_size
            packed_value = self._cached_struct.pack(desired_value) if self._cached_struct else struct.pack(f'<{self.value_type}', desired_value)
            
            batch_size = 1000
            for i in range(0, len(addresses), batch_size):
                if self.cancel_scan:
                    break
                batch = addresses[i:i + batch_size]
                for addr in batch:
                    buffer = (ctypes.c_char * buffer_size)()
                    bytes_read = c_size_t(0)
                    if ReadProcessMemory(handle, ctypes.c_void_p(addr), buffer, buffer_size, ctypes.byref(bytes_read)):
                        if bytes(buffer)[:buffer_size] == packed_value:
                            results.append(addr)
        return results

    def write_address_value(self, process_id: int, address: int, value) -> str:
        handle = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, False, process_id & 0xFFFFFFFF)
        if not handle:
            return f"Failed to open process {process_id}"
        try:
            if isinstance(value, str):
                buffer = value.encode("utf-8").ljust(256, b"\x00")
            elif self._cached_struct:
                buffer = self._cached_struct.pack(value)
            else:
                buffer = struct.pack(f'<{self.value_type}', value)
            bytes_written = c_size_t()
            if WriteProcessMemory(handle, ctypes.c_void_p(address), buffer, len(buffer), ctypes.byref(bytes_written)):
                return "Success"
            return f"Failed to write to address 0x{address:X}"
        except Exception as e:
            return f"Error writing to memory: {e}"
        finally:
            CloseHandle(handle)

    def read_address_value(self, process_id: int, address: int):
        handle = OpenProcess(PROCESS_VM_READ, False, process_id & 0xFFFFFFFF)
        if not handle:
            return None
        try:
            buffer = (ctypes.c_char * self.value_size)()
            bytes_read = c_size_t(0)
            if ReadProcessMemory(handle, ctypes.c_void_p(address), buffer, self.value_size, ctypes.byref(bytes_read)):
                if self._cached_struct:
                    return self._cached_struct.unpack(bytes(buffer))[0]
                return struct.unpack(f'<{self.value_type}', bytes(buffer))[0]
            return None
        except Exception:
            return None
        finally:
            CloseHandle(handle)

def download_file(url, local_filename):
    try:
        if not os.path.exists(local_filename):
            response = requests.get(url, stream=True, timeout=30)
            response.raise_for_status()
            with open(local_filename, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
    except Exception as e:
        print(f"Error downloading file: {e}")

class App(ctk.CTk):
    def __init__(self, memory_finder):
        super().__init__()
        self.memory_finder = memory_finder
        self.freeze_active = False
        self.freeze_thread = None
        self.freeze_stop_event = threading.Event()
        self.windows = []
        self.found_addresses = []
        self.scan_thread = None
        self.scan_start_time = 0

        self.setup_window()
        self.create_widgets()
        self.populate_windows()

        self.drag_start_x = 0
        self.drag_start_y = 0

    def setup_window(self):
        self.title("0xFinder")
        self.geometry("900x350")
        ctk.set_appearance_mode("dark")

        self.bg_color = "#121212"
        self.outline_color = "#E0E0E0"
        self.text_color = "#E0E0E0"
        self.button_hover = "#2a2a2a"
        self.freeze_active_color = "#e63946"
        self.freeze_hover_color = "#c1121f"
        self.accent_color = "#00d4aa"

        self.overrideredirect(True)

        self.title_bar = ctk.CTkFrame(self, fg_color=self.bg_color, height=30)
        self.title_bar.pack(fill="x", side="top")
        self.title_bar.grid_columnconfigure(0, weight=1)

        self.close_button = ctk.CTkButton(
            self.title_bar, text="X", command=self.quit,
            fg_color="transparent", hover_color=self.freeze_active_color,
            text_color=self.text_color, width=30, height=30,
            corner_radius=0, border_width=1, border_color=self.outline_color,
        )
        self.close_button.grid(row=0, column=1, sticky="e", padx=0)

        self.title_label = ctk.CTkLabel(
            self.title_bar, text="0xFinder ⚡", font=("Arial", 14, "bold"),
            text_color=self.text_color,
        )
        self.title_label.grid(row=0, column=0, sticky="nsew", padx=(0, 0))

        self.title_bar.bind("<Button-1>", self.start_drag)
        self.title_bar.bind("<B1-Motion>", self.on_drag)
        self.title_label.bind("<Button-1>", self.start_drag)
        self.title_label.bind("<B1-Motion>", self.on_drag)

        self.main_frame = ctk.CTkFrame(self, fg_color=self.bg_color)
        self.main_frame.pack(fill="both", expand=True, padx=0, pady=0)

        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(1, weight=1)
        self.main_frame.grid_rowconfigure(0, weight=0)
        self.main_frame.grid_rowconfigure(1, weight=1)
        self.main_frame.grid_rowconfigure(2, weight=0)

        self.attributes("-topmost", True)
        self.lift()

    def start_drag(self, event):
        self.drag_start_x = event.x_root - self.winfo_x()
        self.drag_start_y = event.y_root - self.winfo_y()

    def on_drag(self, event):
        x = event.x_root - self.drag_start_x
        y = event.y_root - self.drag_start_y
        self.geometry(f"+{x}+{y}")

    def create_widgets(self):
        self.create_search_frame()
        self.create_results_frame()
        self.create_modification_frame()

    def refresh_windows(self):
        self.windows = self.memory_finder.get_all_windows()
        self.window_list.configure(values=[f"{win.title} - PID: {win.process_id}" for win in self.windows])
        self.log_message("Window list refreshed")

    def inject_dll(self):
        selected_window = self.get_selected_window()
        if not selected_window:
            return
        dll_path = filedialog.askopenfilename(title="Select DLL to Inject", filetypes=[("DLL Files", "*.dll")])
        if not dll_path:
            return
        try:
            dll_path = os.path.abspath(dll_path)
            if not os.path.exists(dll_path):
                messagebox.showerror("Error", f"DLL file not found: {dll_path}")
                return
            h_process = OpenProcess(PROCESS_ALL_ACCESS, False, selected_window.process_id)
            if not h_process:
                messagebox.showerror("Error", f"Failed to open process. Error code: {ctypes.get_last_error()}")
                return
            remote_memory = VirtualAllocEx(h_process, None, len(dll_path) + 1, 0x1000, 0x40)
            if not remote_memory:
                messagebox.showerror("Error", f"Failed to allocate memory. Error code: {ctypes.get_last_error()}")
                CloseHandle(h_process)
                return
            written = ctypes.c_size_t(0)
            if not WriteProcessMemory(h_process, remote_memory, dll_path.encode("utf-8"), len(dll_path) + 1, ctypes.byref(written)):
                messagebox.showerror("Error", f"Failed to write memory. Error code: {ctypes.get_last_error()}")
                CloseHandle(h_process)
                return
            load_library = GetProcAddress(GetModuleHandle(b"kernel32.dll"), b"LoadLibraryA")
            if not load_library:
                messagebox.showerror("Error", "Failed to get address of LoadLibraryA.")
                CloseHandle(h_process)
                return
            h_thread = CreateRemoteThread(h_process, None, 0, load_library, remote_memory, 0, None)
            if not h_thread:
                messagebox.showerror("Error", f"Failed to create remote thread. Error code: {ctypes.get_last_error()}")
                CloseHandle(h_process)
                return
            WaitForSingleObject(h_thread, 0xFFFFFFFF)
            CloseHandle(h_thread)
            CloseHandle(h_process)
            messagebox.showinfo("Success", "DLL injected successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def run_lua_in_game(self):
        try:
            selected_window = self.get_selected_window()
            if not selected_window:
                return
            url = "https://github.com/prototbh/TEMP/raw/refs/heads/main/lua%20ex.dll"
            local_path = os.path.join(os.getcwd(), "lua_ex.dll")
            if os.path.exists(local_path):
                self.log_message("Lua DLL already exists, skipping download...")
            else:
                self.log_message("Downloading Lua DLL...")
                download_file(url, local_path)
                if not os.path.exists(local_path):
                    self.log_message("Download failed")
                    return
            h_process = OpenProcess(PROCESS_ALL_ACCESS, False, selected_window.process_id)
            if not h_process:
                self.log_message("Failed to open process")
                return
            remote_memory = VirtualAllocEx(h_process, None, len(local_path) + 1, 0x1000, 0x40)
            if not remote_memory:
                self.log_message("Memory allocation failed")
                CloseHandle(h_process)
                return
            written = ctypes.c_size_t(0)
            if not WriteProcessMemory(h_process, remote_memory, local_path.encode("utf-8"), len(local_path) + 1, ctypes.byref(written)):
                self.log_message("Memory write failed")
                CloseHandle(h_process)
                return
            load_library = GetProcAddress(GetModuleHandle(b"kernel32.dll"), b"LoadLibraryA")
            if not load_library:
                self.log_message("GetProcAddress failed")
                CloseHandle(h_process)
                return
            h_thread = CreateRemoteThread(h_process, None, 0, load_library, remote_memory, 0, None)
            if not h_thread:
                self.log_message("CreateRemoteThread failed")
                CloseHandle(h_process)
                return
            WaitForSingleObject(h_thread, 0xFFFFFFFF)
            CloseHandle(h_thread)
            CloseHandle(h_process)
            self.log_message("Lua DLL injected successfully!")
        except Exception as e:
            self.log_message(f"Lua inject error: {e}")

    def create_search_frame(self):
        search_frame = ctk.CTkFrame(self.main_frame, fg_color=self.bg_color)
        search_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 5))
        search_frame.grid_columnconfigure(0, weight=1)
        search_frame.grid_columnconfigure(1, weight=1)

        self.window_list = ctk.CTkComboBox(
            search_frame, width=280, fg_color=self.bg_color,
            button_color=self.bg_color, button_hover_color=self.button_hover,
            text_color=self.text_color, border_color="#E0E0E0", border_width=1,
            dropdown_fg_color=self.bg_color, dropdown_text_color=self.text_color,
            dropdown_hover_color=self.button_hover,
        )
        self.window_list.set("Select a Window")
        self.window_list.grid(row=0, column=0, padx=(0, 5), pady=5, sticky="ew")

        self.search_value_entry = ctk.CTkEntry(
            search_frame, width=280, placeholder_text="Value to Search",
            fg_color=self.bg_color, text_color=self.text_color,
            border_color="#E0E0E0", border_width=1, placeholder_text_color="#a0a0a0",
        )
        self.search_value_entry.grid(row=0, column=1, padx=(5, 0), pady=5, sticky="ew")

        self.value_type_list = ctk.CTkComboBox(
            search_frame, width=280, fg_color=self.bg_color,
            button_color=self.bg_color, button_hover_color=self.button_hover,
            text_color=self.text_color, border_color="#E0E0E0", border_width=1,
            dropdown_fg_color=self.bg_color, dropdown_text_color=self.text_color,
            dropdown_hover_color=self.button_hover,
        )
        self.value_type_list.set("Select Value Type")
        self.value_type_list.configure(values=["4-byte Integer", "4-byte Float", "8-byte Double", "2-byte Integer", "String"])
        self.value_type_list.grid(row=1, column=0, padx=(0, 5), pady=5, sticky="ew")

        self.refresh_button = ctk.CTkButton(
            search_frame, text="Refresh Windows", command=self.refresh_windows,
            fg_color=self.bg_color, hover_color=self.button_hover,
            text_color=self.text_color, width=120, border_width=1, border_color=self.outline_color,
        )
        self.refresh_button.grid(row=1, column=1, padx=(5, 0), pady=5, sticky="ew")

    def create_results_frame(self):
        results_frame = ctk.CTkFrame(self.main_frame, fg_color=self.bg_color)
        results_frame.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=5)
        results_frame.grid_columnconfigure(0, weight=1)

        button_frame = ctk.CTkFrame(results_frame, fg_color=self.bg_color)
        button_frame.grid(row=0, column=0, sticky="ew", pady=(0, 5))

        self.search_button = ctk.CTkButton(
            button_frame, text="⚡ First Scan", command=self.search_memory,
            fg_color=self.bg_color, hover_color=self.button_hover,
            text_color=self.text_color, width=120, border_width=1, border_color=self.outline_color,
        )
        self.search_button.pack(side="left", padx=5)

        self.next_scan_button = ctk.CTkButton(
            button_frame, text="🔍 Next Scan", command=self.next_scan,
            fg_color=self.bg_color, hover_color=self.button_hover,
            text_color=self.text_color, width=120, border_width=1, border_color=self.outline_color,
        )
        self.next_scan_button.pack(side="left", padx=5)

        self.cancel_button = ctk.CTkButton(
            button_frame, text="✖ Cancel", command=self.cancel_scan,
            fg_color=self.bg_color, hover_color=self.freeze_active_color,
            text_color=self.text_color, width=80, border_width=1, border_color=self.outline_color,
        )
        self.cancel_button.pack(side="left", padx=5)

        self.progress_label = ctk.CTkLabel(button_frame, text="", text_color=self.accent_color, font=("Arial", 11))
        self.progress_label.pack(side="left", padx=10)

        self.address_list = ctk.CTkTextbox(
            results_frame, width=580, height=100, fg_color=self.bg_color,
            text_color=self.text_color, border_color=self.outline_color,
            scrollbar_button_color=self.bg_color, scrollbar_button_hover_color=self.button_hover,
        )
        self.address_list.grid(row=1, column=0, sticky="nsew", pady=(0, 5))

    def create_modification_frame(self):
        bottom_frame = ctk.CTkFrame(self.main_frame, fg_color=self.bg_color)
        bottom_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(5, 0))
        bottom_frame.grid_columnconfigure(0, weight=1)

        self.modify_frame = ctk.CTkFrame(bottom_frame, fg_color=self.bg_color)
        self.modify_frame.grid(row=0, column=0, padx=5, sticky="w")

        self.modify_address_entry = ctk.CTkEntry(
            self.modify_frame, placeholder_text="Address (hex)",
            fg_color=self.bg_color, text_color=self.text_color,
            border_color="#E0E0E0", border_width=1, placeholder_text_color="#a0a0a0", width=180,
        )
        self.modify_address_entry.pack(side="left", padx=5)

        self.modify_value_entry = ctk.CTkEntry(
            self.modify_frame, placeholder_text="New Value",
            fg_color=self.bg_color, text_color=self.text_color,
            border_color="#E0E0E0", border_width=1, placeholder_text_color="#a0a0a0", width=180,
        )
        self.modify_value_entry.pack(side="left", padx=5)

        self.modify_button = ctk.CTkButton(
            self.modify_frame, text="Modify", command=self.modify_value,
            fg_color=self.bg_color, hover_color=self.button_hover,
            text_color=self.text_color, width=85, border_width=1, border_color=self.outline_color,
        )
        self.modify_button.pack(side="left", padx=5)

        self.freeze_button = ctk.CTkButton(
            self.modify_frame, text="Freeze", command=self.toggle_freeze,
            fg_color=self.bg_color, hover_color=self.freeze_hover_color,
            text_color=self.text_color, width=85, border_width=1, border_color=self.outline_color,
        )
        self.freeze_button.pack(side="left", padx=5)

        self.inject_button = ctk.CTkButton(
            bottom_frame, text="Inject DLL", command=self.inject_dll,
            fg_color=self.bg_color, hover_color=self.button_hover,
            text_color=self.text_color, width=85, border_width=1, border_color=self.outline_color,
        )
        self.inject_button.grid(row=0, column=2, padx=5, sticky="e")

        self.custom_button = ctk.CTkButton(
            bottom_frame, text="Custom", command=self.toggle_modify,
            fg_color=self.bg_color, hover_color=self.button_hover,
            text_color=self.text_color, width=85, border_width=1, border_color=self.outline_color,
        )
        self.custom_button.grid(row=0, column=3, padx=5, sticky="e")

        self.lua_button = ctk.CTkButton(
            bottom_frame, text="Lua", command=self.run_lua_in_game,
            fg_color=self.bg_color, hover_color=self.button_hover,
            text_color=self.text_color, width=85, border_width=1, border_color=self.outline_color,
        )
        self.lua_button.grid(row=0, column=1, padx=5, sticky="e")

    def toggle_modify(self):
        if self.modify_frame.winfo_ismapped():
            self.modify_frame.grid_remove()
            self.custom_button.configure(text="Custom")
        else:
            self.modify_frame.grid()
            self.custom_button.configure(text="Hide Custom")

    def populate_windows(self):
        self.windows = self.memory_finder.get_all_windows()
        self.window_list.configure(values=[f"{win.title} - PID: {win.process_id}" for win in self.windows])

    def get_selected_window(self):
        selected_value = self.window_list.get()
        if not selected_value or selected_value == "Select a Window":
            self.log_message("Please select a window")
            return None
        selected_index = next(
            (i for i, win in enumerate(self.windows) if f"{win.title} - PID: {win.process_id}" == selected_value),
            None,
        )
        if selected_index is None:
            self.log_message("Invalid selection")
            return None
        return self.windows[selected_index]

    def log_message(self, message: str):
        self.address_list.configure(state="normal")
        self.address_list.insert("1.0", f"{message}\n")
        self.address_list.configure(state="disabled")

    def update_progress(self, current: int, total: int):
        elapsed = time.time() - self.scan_start_time
        percent = (current / total) * 100 if total > 0 else 0
        self.progress_label.configure(text=f"Scanning: {percent:.0f}% ({elapsed:.1f}s)")
        self.update_idletasks()

    def cancel_scan(self):
        self.memory_finder.cancel_scan = True
        self.progress_label.configure(text="Cancelled")

    def _do_scan(self, process_id: int, value, is_next_scan: bool):
        def progress_cb(current, total):
            self.after(0, lambda: self.update_progress(current, total))
        
        if is_next_scan:
            addresses = self.memory_finder.memory_search(
                process_id=process_id, desired_value=value,
                search_addresses=self.found_addresses, progress_callback=progress_cb
            )
        else:
            addresses = self.memory_finder.memory_search(
                process_id=process_id, desired_value=value, progress_callback=progress_cb
            )
        
        self.after(0, lambda: self._scan_complete(addresses))

    def _scan_complete(self, addresses: List[int]):
        elapsed = time.time() - self.scan_start_time
        self.found_addresses = addresses
        self.search_button.configure(state="normal")
        self.next_scan_button.configure(state="normal")
        self.progress_label.configure(text=f"Done in {elapsed:.2f}s")
        self.update_address_list()

    def search_memory(self):
        try:
            selected_window = self.get_selected_window()
            if not selected_window:
                return
            selected_value_type = self.value_type_list.get()
            if selected_value_type == "String":
                value = self.search_value_entry.get()
                self.memory_finder.set_value_type("s")
                self.memory_finder.value_size = len(value.encode("utf-8"))
            else:
                value = int(self.search_value_entry.get())
                if selected_value_type == "4-byte Float":
                    self.memory_finder.set_value_type("f")
                elif selected_value_type == "8-byte Double":
                    self.memory_finder.set_value_type("d")
                elif selected_value_type == "2-byte Integer":
                    self.memory_finder.set_value_type("h")
                else:
                    self.memory_finder.set_value_type("i")

            self.address_list.configure(state="normal")
            self.address_list.delete("1.0", "end")
            self.address_list.insert("1.0", "Scanning memory...\n")
            self.address_list.configure(state="disabled")
            
            self.search_button.configure(state="disabled")
            self.next_scan_button.configure(state="disabled")
            self.scan_start_time = time.time()
            self.progress_label.configure(text="Starting scan...")
            
            self.scan_thread = threading.Thread(
                target=self._do_scan,
                args=(selected_window.process_id, value, False),
                daemon=True
            )
            self.scan_thread.start()

        except ValueError:
            self.log_message("Error: Invalid value entered")
        except Exception as e:
            self.log_message(f"Error: {e}")

    def next_scan(self):
        try:
            selected_window = self.get_selected_window()
            if not selected_window:
                return
            if not self.found_addresses:
                self.log_message("No previous scan results. Do a First Scan first.")
                return
                
            selected_value_type = self.value_type_list.get()
            if selected_value_type == "String":
                value = self.search_value_entry.get()
            else:
                value = int(self.search_value_entry.get())

            self.address_list.configure(state="normal")
            self.address_list.delete("1.0", "end")
            self.address_list.insert("1.0", f"Narrowing down {len(self.found_addresses)} addresses...\n")
            self.address_list.configure(state="disabled")
            
            self.search_button.configure(state="disabled")
            self.next_scan_button.configure(state="disabled")
            self.scan_start_time = time.time()
            self.progress_label.configure(text="Filtering...")
            
            self.scan_thread = threading.Thread(
                target=self._do_scan,
                args=(selected_window.process_id, value, True),
                daemon=True
            )
            self.scan_thread.start()

        except ValueError:
            self.log_message("Error: Invalid value entered")
        except Exception as e:
            self.log_message(f"Error: {e}")

    def update_address_list(self):
        self.address_list.configure(state="normal")
        self.address_list.delete("1.0", "end")
        count = len(self.found_addresses)
        self.address_list.insert("1.0", f"Found {count} address{'es' if count != 1 else ''}:\n\n")
        display_limit = 500
        if count > display_limit:
            self.address_list.insert("end", f"(Showing first {display_limit} of {count})\n")
        addresses_to_show = self.found_addresses[:display_limit]
        self.address_list.insert("end", "\n".join([f"0x{addr:X}" for addr in addresses_to_show]))
        self.address_list.configure(state="disabled")

    def modify_value(self):
        try:
            selected_window = self.get_selected_window()
            if not selected_window:
                return
            address = int(self.modify_address_entry.get(), 16)
            selected_value_type = self.value_type_list.get()
            if selected_value_type == "String":
                value = self.modify_value_entry.get()
            else:
                value = int(self.modify_value_entry.get())
            result = self.memory_finder.write_address_value(selected_window.process_id, address, value)
            self.log_message(result)
        except Exception as e:
            self.log_message(f"Error: {e}")

    def toggle_freeze(self):
        if self.freeze_active:
            self.stop_freeze()
        else:
            self.start_freeze()

    def start_freeze(self):
        selected_window = self.get_selected_window()
        if not selected_window:
            return
        try:
            address = int(self.modify_address_entry.get(), 16)
            selected_value_type = self.value_type_list.get()
            if selected_value_type == "String":
                value = self.modify_value_entry.get()
            else:
                value = int(self.modify_value_entry.get())
        except Exception as e:
            self.log_message(f"Error: {e}")
            return

        self.freeze_active = True
        self.freeze_stop_event.clear()
        self.freeze_button.configure(text="Frozen", fg_color=self.freeze_active_color, hover_color=self.freeze_hover_color)
        self.freeze_thread = threading.Thread(
            target=self.freeze_loop,
            args=(selected_window.process_id, address, value),
            daemon=True,
        )
        self.freeze_thread.start()
        self.log_message(f"Freezing 0x{address:X} to {value}")

    def stop_freeze(self):
        self.freeze_active = False
        self.freeze_stop_event.set()
        if self.freeze_thread and self.freeze_thread.is_alive():
            self.freeze_thread.join(timeout=0.1)
        self.freeze_button.configure(text="Freeze", fg_color=self.bg_color, hover_color=self.button_hover)
        self.log_message("Freeze stopped")

    def freeze_loop(self, process_id, address, value):
        while not self.freeze_stop_event.is_set():
            try:
                result = self.memory_finder.write_address_value(process_id, address, value)
                if "Failed" in result:
                    self.after(0, lambda r=result: self.log_message(f"Freeze error: {r}"))
                    break
                time.sleep(0.005)
            except Exception as e:
                self.after(0, lambda err=e: self.log_message(f"Freeze error: {err}"))
                break
        self.freeze_active = False
        self.after(0, lambda: self.freeze_button.configure(text="Freeze", fg_color=self.bg_color, hover_color=self.button_hover))

if __name__ == "__main__":
    memory_finder = MemoryFinder()
    app = App(memory_finder)
    app.mainloop()
