import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import joblib
import numpy as np
import os
import hashlib
import time
import requests
import pefile
import threading
import configparser  # <-- Import the new library

# --- Configuration ---
CONFIG_FILE = 'config.ini'
RELEVANT_EXTENSIONS = {'.exe', '.dll', '.scr', '.com', '.msi', '.jar', '.vbs', '.bat', '.ps1', '.docm', '.xlsm'}
DEFAULT_API_WAIT_TIME = 4

# Feature order must remain constant
FEATURE_ORDER = [
    'proc_pid', 'file', 'urls', 'type', 'name', 'ext_urls', 'path',
    'program', 'info', 'positives', 'families', 'description',
    'sign_name', 'sign_stacktrace', 'arguments', 'api', 'category',
    'imported_dll_count', 'dll', 'pe_res_name', 'filetype',
    'pe_sec_name', 'entropy', 'hosts', 'requests', 'mitm', 'domains',
    'dns_servers', 'tcp', 'udp', 'dead_hosts', 'proc', 'beh_command_line',
    'process_path', 'tree_command_line', 'children', 'tree_process_name',
    'command_line', 'regkey_read', 'directory_enumerated', 'regkey_opened',
    'file_created', 'wmi_query', 'dll_loaded', 'regkey_written',
    'file_read', 'apistats', 'errors', 'action', 'log'
]

# (The FeatureExtractor class remains the same)
class FeatureExtractor:
    def __init__(self, api_key, status_callback):
        self.api_key = api_key
        self.status_callback = status_callback
        self.headers = {'x-apikey': self.api_key}
        self.base_url = 'https://www.virustotal.com/api/v3'
    def _update_status(self, message):
        if self.status_callback: self.status_callback.__self__.root.after(0, self.status_callback, message)
    def _get_static_features(self, file_path):
        static_features = {}
        try:
            pe = pefile.PE(file_path, fast_load=True)
            static_features['imported_dll_count'] = len(pe.DIRECTORY_ENTRY_IMPORT)
            static_features['dll'] = static_features['imported_dll_count']
            entropies = [s.get_entropy() for s in pe.sections if s.get_entropy() > 0]
            static_features['entropy'] = sum(entropies) / len(entropies) if entropies else 0
            static_features['pe_sec_name'] = len(pe.sections)
            static_features['pe_res_name'] = len(pe.DIRECTORY_ENTRY_RESOURCE.entries) if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else 0
            pe.close()
        except Exception:
            static_features.update({'imported_dll_count': 0, 'dll': 0, 'entropy': 0, 'pe_sec_name': 0, 'pe_res_name': 0})
        return static_features
    def _parse_vt_report(self, report):
        dynamic_features = {}
        attrs = report.get('data', {}).get('attributes', {}); stats = attrs.get('last_analysis_stats', {})
        dynamic_features['positives'] = stats.get('malicious', 0) + stats.get('suspicious', 0)
        behavior = attrs.get('behaviours', {}); dynamic_features['regkey_opened'] = len(behavior.get('Registry Keys Opened', [])); dynamic_features['regkey_read'] = len(behavior.get('Registry Keys Read', [])); dynamic_features['regkey_written'] = len(behavior.get('Registry Keys Set', [])); dynamic_features['file_created'] = len(behavior.get('Files Written', [])); dynamic_features['file_read'] = len(behavior.get('Files Opened', [])); dynamic_features['dll_loaded'] = len(behavior.get('Modules Loaded', [])); dynamic_features['wmi_query'] = len(behavior.get('WMI Queries', [])); dynamic_features['directory_enumerated'] = len(behavior.get('Directories Enumerated', [])); proc_created = len(behavior.get('Processes Created', [])); dynamic_features['proc'] = proc_created; dynamic_features['children'] = proc_created; dynamic_features['domains'] = len(behavior.get('Domains Contacted', [])); dynamic_features['hosts'] = len(behavior.get('IP Traffic', [])); dynamic_features['dns_servers'] = len(behavior.get('DNS Lookups', [])); dynamic_features['tcp'] = len(behavior.get('TCP Connections', [])); dynamic_features['udp'] = len(behavior.get('UDP Connections', [])); dynamic_features['command_line'] = len(behavior.get('Commands Executed', [])); dynamic_features['sign_name'] = len(attrs.get('crowdsourced_ids', [])); dynamic_features['families'] = len(attrs.get('popular_threat_classification', {}).get('suggested_threat_label', [])); api_calls = len(behavior.get('API Calls', [])); dynamic_features['api'] = api_calls; dynamic_features['apistats'] = api_calls
        return dynamic_features
    def analyze_file(self, file_path, pause_event):
        self._update_status(f"Analyzing: {os.path.basename(file_path)}"); all_features = self._get_static_features(file_path); sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""): sha256_hash.update(byte_block)
            file_hash = sha256_hash.hexdigest()
        except IOError as e: return None, f"IOError: {e}"
        report_url = f"{self.base_url}/files/{file_hash}"
        try:
            pause_event.wait(); response = requests.get(report_url, headers=self.headers)
            if response.status_code == 404:
                self._update_status("No report, uploading..."); pause_event.wait()
                with open(file_path, 'rb') as f:
                    files = {'file': (os.path.basename(file_path), f)}; upload_response = requests.post(f"{self.base_url}/files", headers=self.headers, files=files); upload_response.raise_for_status()
                analysis_id = upload_response.json()['data']['id']; analysis_url = f"{self.base_url}/analyses/{analysis_id}"
                while True:
                    pause_event.wait(); self._update_status("Polling for analysis..."); time.sleep(20); analysis_report = requests.get(analysis_url, headers=self.headers)
                    if analysis_report.json().get('data', {}).get('attributes', {}).get('status') == 'completed': break
                report_response = requests.get(report_url, headers=self.headers)
            elif response.status_code == 200: report_response = response
            else: raise requests.exceptions.RequestException(f"API Error {response.status_code}: {response.text}")
            dynamic_features = self._parse_vt_report(report_response.json()); all_features.update(dynamic_features)
        except requests.exceptions.RequestException as e: return None, f"API Error: {e}"
        feature_vector = [all_features.get(feature_name, 0) for feature_name in FEATURE_ORDER]
        return feature_vector, "Success"

class RansomwareScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Ransomware Scanner")
        self.root.geometry("800x700")

        # --- Load Configuration ---
        self.vt_api_key = self.load_config()
        if not self.vt_api_key:
            self.root.withdraw()  # Hide the main window if config is missing
            messagebox.showerror("Configuration Error", f"'{CONFIG_FILE}' not found or is invalid.\nA template has been created. Please add your API key and restart.")
            self.root.after(100, self.root.destroy)
            return

        # --- Class Variables ---
        self.model, self.scaler = None, None
        self.model_path = tk.StringVar(); self.scaler_path = tk.StringVar()
        self.status_text = tk.StringVar(value="Status: Idle")
        self.files_to_scan = []
        self.api_wait_time_var = tk.StringVar(value=str(DEFAULT_API_WAIT_TIME))
        self.pause_event = threading.Event(); self.pause_event.set()
        self.scan_all_files_var = tk.BooleanVar(value=False)

        # --- GUI Layout ---
        main_frame = ttk.Frame(self.root, padding="15"); main_frame.pack(fill=tk.BOTH, expand=True)
        config_frame = ttk.Labelframe(main_frame, text="1. Configuration", padding="10"); config_frame.pack(fill=tk.X, padx=5, pady=5)
        self._create_config_widgets(config_frame)
        target_frame = ttk.Labelframe(main_frame, text="2. Select Targets", padding="10"); target_frame.pack(fill=tk.X, padx=5, pady=5)
        self._create_target_widgets(target_frame)
        control_frame = ttk.Frame(main_frame); control_frame.pack(pady=15)
        self.scan_button = ttk.Button(control_frame, text="Start Scan", command=self.start_scan_thread, width=15); self.scan_button.pack(side=tk.LEFT, padx=5, ipady=5)
        self.pause_button = ttk.Button(control_frame, text="Pause", command=self.toggle_pause, state=tk.DISABLED, width=15); self.pause_button.pack(side=tk.LEFT, padx=5, ipady=5)
        results_frame = ttk.Labelframe(main_frame, text="3. Results", padding="10"); results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self._create_results_table(results_frame)
        self.status_label = ttk.Label(main_frame, textvariable=self.status_text, anchor=tk.W); self.status_label.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=(5,0))

    def load_config(self):
        """Loads API key from config.ini. Creates file if it doesn't exist."""
        config = configparser.ConfigParser()
        if not os.path.exists(CONFIG_FILE):
            config['VirusTotal'] = {'api_key': 'YOUR_API_KEY_HERE'}
            with open(CONFIG_FILE, 'w') as configfile:
                config.write(configfile)
            return None
        
        try:
            config.read(CONFIG_FILE)
            api_key = config.get('VirusTotal', 'api_key')
            if api_key == 'YOUR_API_KEY_HERE' or not api_key:
                return None
            return api_key
        except (configparser.NoSectionError, configparser.NoOptionError):
            return None

    def _create_config_widgets(self, parent):
        """GUI setup for configuration, now simplified."""
        # API key entry is removed from the GUI.
        self._create_file_browser(parent, "ML Model:", self.model_path, self.browse_model)
        self._create_file_browser(parent, "Scaler (Optional):", self.scaler_path, self.browse_scaler)
        
        # Add the wait time entry here
        wait_frame = ttk.Frame(parent)
        wait_frame.pack(fill=tk.X, pady=2, padx=5)
        ttk.Label(wait_frame, text="API Wait (s):", width=18).pack(side=tk.LEFT)
        ttk.Entry(wait_frame, textvariable=self.api_wait_time_var, width=5).pack(side=tk.LEFT)
    
    def start_scan_thread(self):
        """Validation now checks the loaded API key."""
        if not self.files_to_scan: messagebox.showwarning("No Targets", "Please select files or a directory."); return
        if not self.model: messagebox.showwarning("Configuration Missing", "Please load a model."); return
        # The key is checked on startup, so we can assume it's valid here.
        
        self.scan_button.config(state=tk.DISABLED); self.pause_button.config(state=tk.NORMAL, text="Pause")
        self.pause_event.set()
        threading.Thread(target=self.run_batch_scan, daemon=True).start()

    def run_batch_scan(self):
        """Instantiates FeatureExtractor with the loaded API key."""
        self.root.after(0, lambda: [self.results_tree.delete(i) for i in self.results_tree.get_children()])
        try:
            try:
                wait_time = float(self.api_wait_time_var.get());
                if wait_time < 0: wait_time = 0
            except ValueError:
                self.root.after(0, messagebox.showwarning, "Invalid Wait Time", f"Using default: {DEFAULT_API_WAIT_TIME}s.")
                wait_time = DEFAULT_API_WAIT_TIME; self.root.after(0, self.api_wait_time_var.set, str(DEFAULT_API_WAIT_TIME))
            
            # Use the API key loaded from the config file
            extractor = FeatureExtractor(self.vt_api_key, self.update_status_from_thread)
            total_files = len(self.files_to_scan)
            for i, file_path in enumerate(self.files_to_scan):
                self.pause_event.wait()
                self.update_status_from_thread(f"Processing {i+1}/{total_files}: {os.path.basename(file_path)}")
                item_id = self.add_placeholder_row_safe(file_path)
                feature_vector, status = extractor.analyze_file(file_path, self.pause_event)
                if feature_vector is None:
                    self.update_result_row_safe(item_id, "N/A", status, "error")
                else:
                    features_np = np.array(feature_vector).reshape(1, -1)
                    features_scaled = self.scaler.transform(features_np) if self.scaler else features_np
                    prediction = self.model.predict(features_scaled)[0]
                    result_text, tag = ("RANSOMWARE", "ransomware") if prediction == 1 else ("Normal", "normal")
                    self.update_result_row_safe(item_id, result_text, "Scan Complete", tag)
                if i < total_files - 1:
                    self.pause_event.wait(); self.update_status_from_thread(f"Waiting {wait_time:.1f}s..."); time.sleep(wait_time)
        finally:
            self.root.after(0, self.finalize_scan)

    # --- No other significant changes to the methods below ---
    def browse_directory(self):
        dir_path = filedialog.askdirectory(title="Select Directory to Scan");
        if not dir_path: return
        scan_all = self.scan_all_files_var.get()
        if not scan_all: self.update_status_from_thread(f"Searching for files with extensions: {', '.join(RELEVANT_EXTENSIONS)}")
        else: self.update_status_from_thread("Searching for all files in directory...")
        found_files = [os.path.join(root, file) for root, _, files in os.walk(dir_path) for file in files if scan_all or os.path.splitext(file)[1].lower() in RELEVANT_EXTENSIONS]
        if not found_files: messagebox.showinfo("Info", "No relevant files were found."); return
        self.files_to_scan.extend(found_files); self.files_to_scan = sorted(list(set(self.files_to_scan)))
        self.update_file_list_label(); self.update_status_from_thread(f"Added {len(found_files)} files to the scan queue.")
    def toggle_pause(self):
        is_paused = not self.pause_event.is_set()
        if is_paused: self.pause_event.set(); self.pause_button.config(text="Pause"); self.update_status_from_thread("Resuming scan...")
        else: self.pause_event.clear(); self.pause_button.config(text="Resume"); self.update_status_from_thread("Scan paused by user.")
    def finalize_scan(self):
        self.update_status_from_thread("Batch scan complete.")
        self.scan_button.config(state=tk.NORMAL); self.pause_button.config(state=tk.DISABLED, text="Pause")
    def add_placeholder_row_safe(self, file_path):
        item_id_container = []
        def add_row(): item_id_container.append(self.results_tree.insert('', 'end', values=(os.path.basename(file_path), "Scanning...", "In progress...")))
        self.root.after(0, add_row)
        while not item_id_container: time.sleep(0.01)
        return item_id_container[0]
    def update_result_row_safe(self, item_id, result, status, tag):
        def update_row():
            try: self.results_tree.item(item_id, values=(self.results_tree.item(item_id, 'values')[0], result, status), tags=(tag,))
            except tk.TclError: pass
        self.root.after(0, update_row)
    def update_status_from_thread(self, message): self.root.after(0, self.status_text.set, f"Status: {message}")
    def _create_file_browser(self, parent, label_text, text_var, command):
        frame = ttk.Frame(parent); frame.pack(fill=tk.X, pady=2, padx=5)
        ttk.Label(frame, text=label_text, width=18).pack(side=tk.LEFT)
        ttk.Entry(frame, textvariable=text_var, state='readonly').pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(frame, text="Browse...", command=command).pack(side=tk.LEFT)
    def _create_target_widgets(self, parent):
        btn_frame = ttk.Frame(parent); btn_frame.pack(fill=tk.X)
        ttk.Button(btn_frame, text="Select Files...", command=self.browse_files).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_frame, text="Select Directory...", command=self.browse_directory).pack(side=tk.LEFT)
        ttk.Checkbutton(btn_frame, text="Scan All File Types", variable=self.scan_all_files_var).pack(side=tk.LEFT, padx=20)
        ttk.Button(btn_frame, text="Clear List", command=self.clear_file_list).pack(side=tk.RIGHT)
        self.file_list_label = ttk.Label(parent, text="0 files selected."); self.file_list_label.pack(anchor=tk.W, pady=(5,0))
    def _create_results_table(self, parent):
        cols = ('file_name', 'result', 'status'); self.results_tree = ttk.Treeview(parent, columns=cols, show='headings', height=10)
        self.results_tree.heading('file_name', text='File Name'); self.results_tree.heading('result', text='Prediction'); self.results_tree.heading('status', text='Scan Status')
        self.results_tree.column('file_name', width=300, anchor=tk.W); self.results_tree.column('result', width=150, anchor=tk.CENTER); self.results_tree.column('status', width=200, anchor=tk.W)
        self.results_tree.tag_configure('ransomware', background='#ffdddd'); self.results_tree.tag_configure('normal', background='#ddffdd'); self.results_tree.tag_configure('error', background='#fffbdd')
        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.results_tree.yview); self.results_tree.configure(yscroll=scrollbar.set)
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True); scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    def browse_model(self):
        path = filedialog.askopenfilename(filetypes=(("Model Files", "*.pkl *.joblib"), ("All Files", "*.*")));
        if path: self._load_asset(path, 'model', self.model_path)
    def browse_scaler(self):
        path = filedialog.askopenfilename(filetypes=(("Model Files", "*.pkl *.joblib"), ("All Files", "*.*")));
        if path: self._load_asset(path, 'scaler', self.scaler_path)
    def _load_asset(self, path, asset_type, path_var):
        try:
            asset = joblib.load(path)
            if asset_type == 'model': self.model = asset
            else: self.scaler = asset
            path_var.set(path); messagebox.showinfo("Success", f"{asset_type.capitalize()} loaded.")
        except Exception as e: messagebox.showerror("Error", f"Failed to load {asset_type}: {e}")
    def browse_files(self):
        paths = filedialog.askopenfilenames(title="Select Files to Scan");
        if paths: self.files_to_scan.extend(paths); self.files_to_scan = sorted(list(set(self.files_to_scan))); self.update_file_list_label()
    def clear_file_list(self):
        self.files_to_scan = []; self.update_file_list_label()
        for i in self.results_tree.get_children(): self.results_tree.delete(i)
        self.status_text.set("Status: File list cleared.")
    def update_file_list_label(self):
        self.file_list_label.config(text=f"{len(self.files_to_scan)} files selected.")

if __name__ == "__main__":
    root = tk.Tk()
    app = RansomwareScannerApp(root)
    # Only run the main loop if the configuration was loaded successfully
    if app.vt_api_key:
        root.mainloop()
