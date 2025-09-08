# --- START OF FILE backend.py ---

import os
import uuid
import threading
import time
import datetime
from flask import Flask, request, jsonify, render_template
import joblib
import numpy as np
import pefile
import math
from collections import deque
import psutil
from concurrent.futures import ThreadPoolExecutor
import pandas as pd
import hashlib
import logging
import shutil
import json
import subprocess
import sys
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.events import EVENT_JOB_EXECUTED, EVENT_JOB_ERROR
from flask_socketio import SocketIO

# ==============================================================================
# --- SHARED CONFIGURATION & SETUP ---
# ==============================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', filename='rdps_log.log', filemode='a')
app = Flask(__name__)
socketio = SocketIO(app, async_mode='threading')

# --- MODEL AND SCALER FILENAMES (HARDCODED) ---
OFFLINE_MODEL_NAME = "rf(Dynamic).pkl"
ONLINE_MODEL_NAME = "XGBoost.pkl"
ONLINE_SCALER_NAME = "XGBoost_Scaler.pkl"

OFFLINE_MODEL_PATH = os.path.join(BASE_DIR, OFFLINE_MODEL_NAME)
ONLINE_MODEL_PATH = os.path.join(BASE_DIR, ONLINE_MODEL_NAME)
ONLINE_SCALER_PATH = os.path.join(BASE_DIR, ONLINE_SCALER_NAME)

# --- OFFLINE (STATIC) ANALYSIS SETUP ---
app.config['UPLOAD_FOLDER'] = 'uploads'; os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
QUARANTINE_FOLDER = os.path.join(BASE_DIR, 'quarantine'); os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
QUARANTINE_MANIFEST = os.path.join(QUARANTINE_FOLDER, 'quarantine_log.json')
MAX_FILE_SIZE_MB = 100
offline_tasks = {}
manifest_lock = threading.Lock()
FEATURE_ORDER = [ 'proc_pid', 'file', 'urls', 'type', 'name', 'ext_urls', 'path', 'program', 'info', 'positives', 'families', 'description', 'sign_name', 'sign_stacktrace', 'arguments', 'api', 'category', 'imported_dll_count', 'dll', 'pe_res_name', 'filetype', 'pe_sec_name', 'entropy', 'hosts', 'requests', 'mitm', 'domains', 'dns_servers', 'tcp', 'udp', 'dead_hosts', 'proc', 'beh_command_line', 'process_path', 'tree_command_line', 'children', 'tree_process_name', 'command_line', 'regkey_read', 'directory_enumerated', 'regkey_opened', 'file_created', 'wmi_query', 'dll_loaded', 'regkey_written', 'file_read', 'apistats', 'errors', 'action', 'log' ]
RELEVANT_EXTENSIONS = {'.exe', '.dll', '.scr', '.com', '.msi', '.jar', '.vbs', '.bat', '.ps1', '.docm', '.xlsm'}

# --- PAUSE/RESUME CONTROL FOR OFFLINE SCANS ---
offline_scan_pause_event = threading.Event()
offline_scan_pause_event.set() 
is_offline_scan_paused = False

# --- SCHEDULED SCAN CONFIG ---
QUICK_SCAN_INTERVAL_HOURS = 24
FULL_SCAN_INTERVAL_DAYS = 15

# --- ONLINE (DYNAMIC) ANALYSIS SETUP ---
online_analysis_state = { 'status': 'Stopped', 'normal_flows': 0, 'ransomware_flows': 0, 'last_log_line': 'Monitoring has not started.', 'blocked_connections': {}, 'stop_signal': False, 'thread': None, 'lock': threading.Lock() }
ONLINE_MODEL_FEATURES = [ "Src Port", "Dst Port", "Protocol", "Init Bwd Win Byts", "Pkt Len Max", "Pkt Size Avg", "Pkt Len Mean", "Subflow Bwd Byts", "TotLen Bwd Pkts", "Bwd Pkt Len Max", "Bwd Seg Size Avg", "Bwd Pkt Len Mean", "Pkt Len Var", "Pkt Len Std", "Bwd Pkt Len Min", "Pkt Len Min", "Bwd Header Len", "Bwd IAT Min", "Subflow Fwd Byts", "TotLen Fwd Pkts", "Flow IAT Min", "Fwd Pkt Len Mean", "Fwd Seg Size Avg", "ACK Flag Cnt", "Fwd Pkt Len Max", "Fwd Pkt Len Min" ]

# --- SYSTEM RESOURCE MONITORING ---
cpu_data = deque(maxlen=30); mem_data = deque(maxlen=30)
def monitor_resources():
    while True: cpu_data.append(psutil.cpu_percent(interval=1)); mem_data.append(psutil.virtual_memory().percent)

# ==============================================================================
# --- SCHEDULED OFFLINE SCANS ---
# ==============================================================================
scheduler = BackgroundScheduler(daemon=True)
scheduled_tasks_info = {
    'quick': {'id': 'quick_scan', 'status': 'Idle', 'last_run': None, 'next_run': None, 'current_task_id': None},
    'full': {'id': 'full_scan', 'status': 'Idle', 'last_run': None, 'next_run': None, 'current_task_id': None}
}

def get_scan_paths(scan_type):
    paths = []
    exclusions = set()
    
    if scan_type == 'quick':
        target_folders = ['Documents', 'Downloads']
        
        if sys.platform == "win32":
            users_dir = os.path.join(os.environ.get('SystemDrive', 'C:'), 'Users')
            ignored_users = {'All Users', 'Default', 'Default User', 'Public', 'desktop.ini'}
            if os.path.isdir(users_dir):
                for user_name in os.listdir(users_dir):
                    if user_name not in ignored_users:
                        user_home = os.path.join(users_dir, user_name)
                        if os.path.isdir(user_home):
                            for folder in target_folders:
                                path_to_scan = os.path.join(user_home, folder)
                                if os.path.isdir(path_to_scan):
                                    paths.append(path_to_scan)
        else:
            base_users_dirs = ['/home', '/Users']
            for base_dir in base_users_dirs:
                if os.path.isdir(base_dir):
                    for user_name in os.listdir(base_dir):
                        user_home = os.path.join(base_dir, user_name)
                        if os.path.isdir(user_home):
                            for folder in target_folders:
                                path_to_scan = os.path.join(user_home, folder)
                                if os.path.isdir(path_to_scan):
                                    paths.append(path_to_scan)
        logging.info(f"Quick scan configured for paths: {paths}")
    
    elif scan_type == 'full':
        if sys.platform == "win32":
            system_drive = os.environ.get('SystemDrive', 'C:') + os.sep
            paths.append(system_drive)
            exclusions.update([os.path.join(system_drive, d) for d in ["Windows", "Program Files", "Program Files (x86)", "ProgramData", "$Recycle.Bin"]])
        else:
            paths.append('/')
            exclusions.update(['/proc', '/sys', '/dev', '/run', '/tmp', '/var/lib', '/usr/lib', '/snap'])
        logging.info(f"Full scan configured for path: {paths} with exclusions.")

    return paths, exclusions

def trigger_scheduled_scan(scan_type):
    task_info = scheduled_tasks_info[scan_type]; logging.info(f"Triggering scheduled {scan_type} scan.")
    with app.app_context():
        if not os.path.exists(OFFLINE_MODEL_PATH):
            logging.error(f"Cannot run scheduled {scan_type} scan: Model not found at {OFFLINE_MODEL_PATH}"); task_info['status'] = f"Error: Model not found"; return
        task_id = str(uuid.uuid4()); task_info.update({'status': 'Running', 'current_task_id': task_id})
        scan_paths, exclusions = get_scan_paths(scan_type)
        all_files_to_scan = []
        for path in scan_paths:
            for root, dirs, files in os.walk(path, topdown=True):
                dirs[:] = [d for d in dirs if os.path.join(root, d) not in exclusions]
                for file in files:
                    if os.path.splitext(file)[1].lower() in RELEVANT_EXTENSIONS: all_files_to_scan.append(os.path.join(root, file))
        offline_tasks[task_id] = {'status': 'PENDING', 'progress': 'Queued...', 'results': [], 'files_processed': 0, 'total_files': 0, 'skipped_files': 0}
        scan_thread = threading.Thread(target=run_local_scan_logic, args=(task_id, None, OFFLINE_MODEL_PATH, None, True, 0.5, all_files_to_scan))
        scan_thread.daemon = True; scan_thread.start()
        job = scheduler.get_job(task_info['id'])
        if job: task_info['next_run'] = job.next_run_time.isoformat() if job.next_run_time else None

def scheduled_scan_listener(event):
    job_id = event.job_id; scan_type = 'quick' if job_id == 'quick_scan' else 'full'; task_info = scheduled_tasks_info[scan_type]
    if event.exception: logging.error(f'Scheduled job {job_id} failed: {event.exception}'); task_info['status'] = 'Error'
    else: logging.info(f'Scheduled job {job_id} finished successfully.'); task_info['status'] = 'Idle'; task_info['last_run'] = datetime.datetime.now().isoformat()
    job = scheduler.get_job(job_id)
    if job: task_info['next_run'] = job.next_run_time.isoformat() if job.next_run_time else None

# ==============================================================================
# --- OFFLINE ANALYSIS CORE LOGIC & OTHER FUNCTIONS ---
# ==============================================================================
def load_manifest():
    with manifest_lock:
        if not os.path.exists(QUARANTINE_MANIFEST): return {}
        try:
            with open(QUARANTINE_MANIFEST, 'r') as f: return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError): return {}
def save_manifest(data):
    with manifest_lock:
        with open(QUARANTINE_MANIFEST, 'w') as f: json.dump(data, f, indent=4)
def quarantine_file(original_path, file_hash):
    if not os.path.exists(original_path): logging.warning(f"File {original_path} no longer exists. Cannot quarantine."); return None, "File not found"
    item_id = str(uuid.uuid4()); quarantined_filename = f"{item_id}.quarantined"; destination_path = os.path.join(QUARANTINE_FOLDER, quarantined_filename)
    try:
        shutil.move(original_path, destination_path); manifest = load_manifest()
        quarantine_item = { "id": item_id, "original_path": original_path, "filename": os.path.basename(original_path), "quarantined_at": time.strftime("%Y-%m-%d %H:%M:%S"), "hash": file_hash, "quarantined_path": destination_path }
        manifest[item_id] = quarantine_item; save_manifest(manifest)
        socketio.emit('quarantine_update', quarantine_item); logging.info(f"Quarantined {original_path} as {item_id}")
        return item_id, "Quarantined successfully"
    except Exception as e: logging.error(f"Failed to quarantine {original_path}: {e}"); return None, f"Quarantine failed: {e}"
class StaticFeatureExtractor:
    def __init__(self): self.filetype_mapping = { '.exe': 1, '.dll': 2, '.scr': 1, '.com': 1, '.msi': 20, '.pdf': 3, '.doc': 4, '.docx': 5, '.docm': 5, '.xls': 6, '.xlsx': 7, '.xlsm': 7, '.ppt': 8, '.pptx': 9, '.txt': 10, '.jpg': 11, '.png': 12, '.zip': 13, '.rar': 14, '.js': 15, '.vbs': 16, '.ps1': 17, '.bat': 18, '.cmd': 19, '.jar': 21 }
    def _string_to_numeric(self, s):
        if not s or not isinstance(s, str): return 0
        return int(hashlib.sha256(s.encode('utf-8', 'ignore')).hexdigest()[:8], 16)
    def analyze_file(self, file_path):
        features = {col: 0.0 for col in FEATURE_ORDER}; file_hash = "N/A"
        try:
            if not os.path.exists(file_path): raise FileNotFoundError
            basename = os.path.basename(file_path); dirname = os.path.dirname(file_path); file_ext = os.path.splitext(basename)[1].lower()
            features['name'] = float(self._string_to_numeric(basename)); features['path'] = float(self._string_to_numeric(dirname)); features['filetype'] = float(self.filetype_mapping.get(file_ext, 0))
            with open(file_path, 'rb') as f:
                data = f.read(); file_hash = hashlib.sha256(data).hexdigest()
                features['file'] = float(int(file_hash[:8], 16))
                if len(data) > 0:
                    counts = np.bincount(np.frombuffer(data, dtype=np.uint8)); probs = counts[counts > 0] / len(data)
                    features['entropy'] = float(-np.sum(probs * np.log2(probs)))
            if file_ext in {'.exe', '.dll', '.scr', '.com'}:
                try:
                    pe = pefile.PE(data=data)
                    features['imported_dll_count'] = float(len(pe.DIRECTORY_ENTRY_IMPORT)) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0.0
                    if hasattr(pe, 'sections'): features['pe_sec_name'] = self._string_to_numeric(pe.sections[0].Name.decode().strip('\x00'))
                    api_count = 0
                    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                        for entry in pe.DIRECTORY_ENTRY_IMPORT: api_count += len(entry.imports)
                    features['apistats'] = float(api_count); features['api'] = float(api_count)
                except pefile.PEFormatError: pass
                except Exception as pe_err: logging.error(f"Error during PE analysis for {basename}: {pe_err}")
        except FileNotFoundError: return None, f"File not found during analysis: {os.path.basename(file_path)}", file_hash
        except Exception as e: logging.error(f"Feature extraction failed for {file_path}: {e}"); return None, f"Feature extraction failed", file_hash
        return [features[col] for col in FEATURE_ORDER], "Analysis complete", file_hash
def process_single_file(file_path, extractor, model, scaler, task_id, threshold):
    offline_scan_pause_event.wait(); task = offline_tasks.get(task_id);
    if not task: return
    basename = os.path.basename(file_path); file_result = {'filename': basename, 'prediction': 'Error', 'status': 'Unknown Error', 'hash': 'N/A'}
    try:
        if not os.path.exists(file_path): raise FileNotFoundError
        if os.path.getsize(file_path) > (MAX_FILE_SIZE_MB * 1024 * 1024):
            task['skipped_files'] += 1; file_result.update({'prediction': 'Skipped', 'status': f'File > {MAX_FILE_SIZE_MB}MB'}); task['results'].append(file_result); return
        feature_vector, status_msg, file_hash = extractor.analyze_file(file_path)
        file_result.update({'status': status_msg, 'hash': file_hash})
        if feature_vector:
            features_df = pd.DataFrame([feature_vector], columns=FEATURE_ORDER); features_scaled = scaler.transform(features_df) if scaler else features_df
            if hasattr(model, 'predict_proba'): final_score = model.predict_proba(features_scaled)[0][1]
            elif hasattr(model, 'decision_function'): final_score = 1 / (1 + math.exp(-model.decision_function(features_scaled)[0]))
            else: final_score = float(model.predict(features_scaled)[0])
            prediction = 1 if final_score >= threshold else 0
            if prediction == 1: file_result['prediction'] = 'Ransomware'; _, quarantine_status = quarantine_file(file_path, file_hash); file_result['status'] = quarantine_status
            else: file_result['prediction'] = 'Normal'
            file_result['score'] = float(final_score)
    except FileNotFoundError: file_result['status'] = f"File disappeared during scan."; task['skipped_files'] += 1
    except Exception as e: logging.error(f"Error processing {basename}: {e}"); file_result['status'] = f"Processing Error: {e}"; task['skipped_files'] += 1
    finally:
        task['results'].append(file_result)
        if file_result['prediction'] != 'Skipped': task['files_processed'] += 1
def run_local_scan_logic(task_id, directory_path, model_path, scaler_path, filter_extensions, threshold, file_list=None):
    try:
        model = joblib.load(model_path); scaler = joblib.load(scaler_path) if scaler_path and os.path.exists(scaler_path) else None
    except Exception as e: offline_tasks[task_id] = {'status': 'ERROR', 'message': f'Failed to load model/scaler: {e}'}; logging.error(e); return
    extractor = StaticFeatureExtractor(); files_to_scan = file_list if file_list is not None else []
    if directory_path:
        try:
            for root, _, files in os.walk(directory_path):
                for file in files:
                    try:
                        file_path = os.path.join(root, file)
                        if os.path.isfile(file_path):
                            if filter_extensions:
                                if os.path.splitext(file)[1].lower() in RELEVANT_EXTENSIONS: files_to_scan.append(file_path)
                            else: files_to_scan.append(file_path)
                    except Exception as walk_err: logging.warning(f"Could not process path in os.walk: {walk_err}")
        except Exception as e: offline_tasks[task_id] = {'status': 'ERROR', 'message': f'Error accessing directory: {e}'}; logging.error(e); return
    offline_tasks[task_id]['total_files'] = len(files_to_scan)
    if offline_tasks[task_id]['total_files'] == 0:
        offline_tasks[task_id]['status'] = 'COMPLETE'; offline_tasks[task_id]['progress'] = 'Scan complete. No relevant files found.'; return
    max_workers = min(32, os.cpu_count() + 4)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(lambda file: process_single_file(file, extractor, model, scaler, task_id, threshold), files_to_scan)
    offline_tasks[task_id]['status'] = 'COMPLETE'; offline_tasks[task_id]['progress'] = 'Scan complete.'
def block_connection(src_ip, dst_ip, dst_port, protocol_num):
    rule_id = f"RDPS-BLOCK-{uuid.uuid4().hex[:8]}"; proto_name = "TCP" if protocol_num == 6 else "UDP" if protocol_num == 17 else "ANY"
    with online_analysis_state['lock']:
        if any(c['src_ip'] == src_ip and c['dst_ip'] == dst_ip and c.get('dst_port') == dst_port for c in online_analysis_state['blocked_connections'].values()):
            logging.info(f"Connection {src_ip} -> {dst_ip}:{dst_port} is already logged/blocked. Skipping.")
            return
    logging.warning(f"Attempting to block connection: {src_ip} -> {dst_ip}:{dst_port} ({proto_name})")
    try:
        if sys.platform == "win32": command = f'netsh advfirewall firewall add rule name="{rule_id}" dir=out action=block protocol={proto_name} remoteip={dst_ip} remoteport={dst_port}'
        elif sys.platform == "linux": command = f'iptables -A OUTPUT -p {proto_name.lower()} -s {src_ip} -d {dst_ip} --dport {dst_port} -j DROP'
        else: logging.error(f"Unsupported OS for firewall blocking: {sys.platform}"); return
        subprocess.run(command, check=True, shell=True, capture_output=True, text=True)
        with online_analysis_state['lock']: online_analysis_state['blocked_connections'][rule_id] = { 'src_ip': src_ip, 'dst_ip': dst_ip, 'dst_port': dst_port, 'protocol': proto_name, 'blocked_at': time.strftime("%Y-%m-%d %H:%M:%S") }
        logging.info(f"Successfully created firewall rule: {rule_id}")
    except (subprocess.CalledProcessError, FileNotFoundError) as e: logging.error(f"FIREWALL ERROR: Failed to create rule {rule_id}. COMMAND: '{e.cmd}'. ERROR: {e.stderr}. Ensure you are running with Administrator/root privileges.")
    except Exception as e: logging.error(f"An unexpected error occurred while blocking connection: {e}")
def unblock_connection(rule_id):
    logging.warning(f"Attempting to remove firewall rule: {rule_id}")
    try:
        if sys.platform == "win32": command = f'netsh advfirewall firewall delete rule name="{rule_id}"'
        elif sys.platform == "linux":
            with online_analysis_state['lock']: info = online_analysis_state['blocked_connections'].get(rule_id)
            if not info: return
            command = f"iptables -D OUTPUT -p {info['protocol'].lower()} -s {info['src_ip']} -d {info['dst_ip']} --dport {info['dst_port']} -j DROP"
        else: logging.error(f"Unsupported OS for firewall unblocking: {sys.platform}"); return
        subprocess.run(command, check=True, shell=True, capture_output=True, text=True)
        with online_analysis_state['lock']:
            if rule_id in online_analysis_state['blocked_connections']: del online_analysis_state['blocked_connections'][rule_id]
        logging.info(f"Successfully removed firewall rule: {rule_id}")
    except (subprocess.CalledProcessError, FileNotFoundError) as e: logging.error(f"FIREWALL ERROR: Failed to delete rule {rule_id}. COMMAND: '{e.cmd}'. ERROR: {e.stderr}. Privileges may be required.")
    except Exception as e: logging.error(f"An unexpected error occurred while unblocking connection: {e}")
def run_online_detection_logic(config):
    model, scaler = config['model'], config['scaler']
    live_csv_path = config['live_csv_path']
    prevention_on = config['prevention_on']
    last_processed_line = 0
    logging.info("Online detection thread started.")
    while not online_analysis_state['stop_signal']:
        try:
            if not os.path.exists(live_csv_path):
                logging.info(f"ONLINE: Waiting for data file: {live_csv_path}")
                with online_analysis_state['lock']:
                    online_analysis_state['last_log_line'] = f"Waiting for CICFlowMeter data file..."
                time.sleep(5)
                continue

            with open(live_csv_path, 'r') as f:
                full_df = pd.read_csv(f, on_bad_lines='skip', low_memory=False)

            if len(full_df) > last_processed_line:
                logging.info(f"ONLINE: Found {len(full_df) - last_processed_line} new lines of data.")
                new_data = full_df.iloc[last_processed_line:].copy()
                new_data.columns = new_data.columns.str.strip()

                # FIX: Add detailed logging for column mismatch errors
                if not all(col in new_data.columns for col in ONLINE_MODEL_FEATURES):
                    missing_cols = [col for col in ONLINE_MODEL_FEATURES if col not in new_data.columns]
                    logging.error(f"ONLINE: CSV file is missing required columns: {missing_cols}.")
                    logging.error(f"ONLINE: Available columns in CSV: {list(new_data.columns)}")
                    with online_analysis_state['lock']:
                        online_analysis_state['last_log_line'] = "Error: CSV columns mismatch."
                    time.sleep(10)  # Wait before retrying
                    continue

                df_model_data = new_data[ONLINE_MODEL_FEATURES].apply(pd.to_numeric, errors='coerce').fillna(0)
                scaled_features = scaler.transform(df_model_data)
                predictions = model.predict(scaled_features)

                for i, prediction in enumerate(predictions):
                    flow_info = new_data.iloc[i]
                    src_ip = flow_info.get('Src IP', 'N/A')
                    dst_ip = flow_info.get('Dst IP', 'N/A')
                    dst_port = int(flow_info.get('Dst Port', 0))
                    src_port = int(flow_info.get('Src Port', 0))
                    protocol_num = int(flow_info.get('Protocol', 0))

                    log_line = f"Flow: {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                    with online_analysis_state['lock']:
                        online_analysis_state['last_log_line'] = log_line

                    if prediction == 1:
                        # FIX: Add logging before the duplicate check for better diagnostics
                        logging.warning(f"ONLINE: RAW RANSOMWARE DETECTION - {log_line}")
                        with online_analysis_state['lock']:
                            online_analysis_state['ransomware_flows'] += 1
                        
                        if prevention_on:
                            block_connection(src_ip, dst_ip, dst_port, protocol_num)
                        else:
                            with online_analysis_state['lock']:
                                if not any(c.get('src_ip') == src_ip and c.get('dst_ip') == dst_ip and c.get('dst_port') == dst_port for c in online_analysis_state['blocked_connections'].values()):
                                    flow_id = f"DETECTED-{uuid.uuid4().hex[:8]}"
                                    proto_name = "TCP" if protocol_num == 6 else "UDP" if protocol_num == 17 else "ANY"
                                    online_analysis_state['blocked_connections'][flow_id] = {
                                        'src_ip': src_ip, 'dst_ip': dst_ip, 'dst_port': dst_port, 'protocol': proto_name,
                                        'blocked_at': time.strftime("%Y-%m-%d %H:%M:%S")
                                    }
                    else:
                        with online_analysis_state['lock']:
                            online_analysis_state['normal_flows'] += 1
                last_processed_line = len(full_df)

        except pd.errors.EmptyDataError:
            with online_analysis_state['lock']:
                online_analysis_state['last_log_line'] = "Data file is empty, waiting for flows..."
        except Exception as e:
            logging.error(f"Error in online detection loop: {e}", exc_info=True)
            with online_analysis_state['lock']:
                online_analysis_state['status'] = 'Error'
                online_analysis_state['last_log_line'] = f"An error occurred: {e}"
            break
        time.sleep(3)

    logging.info("Online detection thread finished.")
    with online_analysis_state['lock']:
        online_analysis_state['status'] = 'Stopped'

@app.route('/')
def index(): return render_template('dashboard.html')
@app.route('/favicon.ico')
def favicon(): return '', 204
@app.route('/system-stats')
def get_system_stats(): return jsonify({'cpu': list(cpu_data), 'memory': list(mem_data)})
@app.route('/offline/scan-directory', methods=['POST'])
def start_directory_scan():
    if 'directory_path' not in request.form: return jsonify({'error': 'directory_path not provided'}), 400
    if not os.path.exists(OFFLINE_MODEL_PATH): return jsonify({'error': f'Model file "{OFFLINE_MODEL_NAME}" not found on server.'}), 500
    directory_path = request.form['directory_path']; filter_extensions = request.form.get('filter_extensions') == 'true'
    try: threshold = float(request.form.get('threshold', 0.5))
    except ValueError: return jsonify({'error': 'Invalid threshold value.'}), 400
    if not os.path.isdir(directory_path): return jsonify({'error': f'Invalid directory path on server: {directory_path}'}), 400
    task_id = str(uuid.uuid4())
    offline_tasks[task_id] = {'status': 'PENDING', 'progress': 'Queued...', 'results': [], 'files_processed': 0, 'total_files': 0, 'skipped_files': 0}
    scan_thread = threading.Thread(target=run_local_scan_logic, args=(task_id, directory_path, OFFLINE_MODEL_PATH, None, filter_extensions, threshold))
    scan_thread.daemon = True; scan_thread.start()
    return jsonify({'task_id': task_id})
@app.route('/offline/schedule/status', methods=['GET'])
def get_schedule_status():
    for scan_type in ['quick', 'full']:
        info = scheduled_tasks_info[scan_type]; task_id = info.get('current_task_id')
        if task_id and task_id in offline_tasks:
            task_status = offline_tasks[task_id]['status']
            if task_status in ['COMPLETE', 'ERROR']: info['status'] = 'Idle'; info['current_task_id'] = None
            else: info['status'] = "Running"
    return jsonify(scheduled_tasks_info)
@app.route('/offline/status/<task_id>')
def get_offline_status(task_id):
    task = offline_tasks.get(task_id)
    if not task: return jsonify({'error': 'Task not found'}), 404
    task['is_paused'] = is_offline_scan_paused
    return jsonify(task)
@app.route('/offline/toggle-pause', methods=['POST'])
def toggle_offline_pause():
    global is_offline_scan_paused
    if offline_scan_pause_event.is_set():
        offline_scan_pause_event.clear(); is_offline_scan_paused = True; logging.info("Offline scan paused.")
    else:
        offline_scan_pause_event.set(); is_offline_scan_paused = False; logging.info("Offline scan resumed.")
    return jsonify({'success': True, 'is_paused': is_offline_scan_paused})
@app.route('/offline/quarantine/list', methods=['GET'])
def list_quarantined_files(): return jsonify(load_manifest())
@app.route('/offline/quarantine/restore/<item_id>', methods=['POST'])
def restore_quarantined_file(item_id):
    manifest = load_manifest(); item = manifest.get(item_id)
    if not item: return jsonify({'error': 'Item not found in manifest'}), 404
    try:
        original_dir = os.path.dirname(item['original_path']); os.makedirs(original_dir, exist_ok=True)
        shutil.move(item['quarantined_path'], item['original_path'])
        del manifest[item_id]; save_manifest(manifest); socketio.emit('quarantine_list_changed')
        logging.info(f"Restored {item_id} to {item['original_path']}")
        return jsonify({'success': f"File '{item['filename']}' restored successfully."})
    except Exception as e: logging.error(f"Failed to restore {item_id}: {e}"); return jsonify({'error': f"Failed to restore file: {e}"}), 500
@app.route('/offline/quarantine/delete/<item_id>', methods=['POST'])
def delete_quarantined_file(item_id):
    manifest = load_manifest(); item = manifest.get(item_id)
    if not item: return jsonify({'error': 'Item not found in manifest'}), 404
    try:
        if os.path.exists(item['quarantined_path']): os.remove(item['quarantined_path'])
        del manifest[item_id]; save_manifest(manifest); socketio.emit('quarantine_list_changed')
        logging.info(f"Deleted {item_id} ({item['filename']}) permanently.")
        return jsonify({'success': f"File '{item['filename']}' deleted permanently."})
    except Exception as e: logging.error(f"Failed to delete {item_id}: {e}"); return jsonify({'error': f"Failed to delete file: {e}"}), 500
@app.route('/offline/quarantine/restore-all', methods=['POST'])
def restore_all_quarantined_files():
    manifest = load_manifest();
    if not manifest: return jsonify({'success': 'Quarantine is already empty.'})
    success_count, fail_count = 0, 0; new_manifest = {}
    for item_id, item in list(manifest.items()):
        try:
            original_dir = os.path.dirname(item['original_path']); os.makedirs(original_dir, exist_ok=True)
            shutil.move(item['quarantined_path'], item['original_path']); success_count += 1
        except Exception as e: logging.error(f"Failed to auto-restore {item_id}: {e}"); new_manifest[item_id] = item; fail_count += 1
    save_manifest(new_manifest); socketio.emit('quarantine_list_changed')
    return jsonify({'success': f'Attempted to restore all files. Success: {success_count}, Failures: {fail_count}.'})
@app.route('/offline/quarantine/delete-all', methods=['POST'])
def delete_all_quarantined_files():
    manifest = load_manifest()
    if not manifest: return jsonify({'success': 'Quarantine is already empty.'})
    success_count, fail_count = 0, 0; new_manifest = {}
    for item_id, item in list(manifest.items()):
        try:
            if os.path.exists(item['quarantined_path']): os.remove(item['quarantined_path']); success_count += 1
        except Exception as e: logging.error(f"Failed to auto-delete {item_id}: {e}"); new_manifest[item_id] = item; fail_count += 1
    save_manifest(new_manifest); socketio.emit('quarantine_list_changed')
    return jsonify({'success': f'Attempted to delete all files. Success: {success_count}, Failures: {fail_count}.'})
@app.route('/online/start', methods=['POST'])
def start_online_scan():
    with online_analysis_state['lock']:
        if online_analysis_state['status'] == 'Running': return jsonify({'error': 'Online analysis is already running.'}), 400
        online_analysis_state.update({
            'status': 'Starting',
            'stop_signal': False,
            'normal_flows': 0,
            'ransomware_flows': 0,
            'last_log_line': 'Initializing...',
            'blocked_connections': {}
        })
    try:
        cicflowmeter_dir = request.form.get('cicflowmeter_dir'); prevention_on = request.form.get('prevention_on') == 'true'
        if not cicflowmeter_dir: raise ValueError("CICFlowMeter directory is required.")
        if not os.path.exists(ONLINE_MODEL_PATH): raise FileNotFoundError(f"Model file '{ONLINE_MODEL_NAME}' not found on server.")
        if not os.path.exists(ONLINE_SCALER_PATH): raise FileNotFoundError(f"Scaler file '{ONLINE_SCALER_NAME}' not found on server.")
        today_date_str = time.strftime('%Y-%m-%d'); live_csv_path = os.path.join(cicflowmeter_dir, f"{today_date_str}_Flow.csv")
        model = joblib.load(ONLINE_MODEL_PATH); scaler = joblib.load(ONLINE_SCALER_PATH)
        config = { 'model': model, 'scaler': scaler, 'live_csv_path': live_csv_path, 'prevention_on': prevention_on }
        thread = threading.Thread(target=run_online_detection_logic, args=(config,)); thread.daemon = True
        with online_analysis_state['lock']: online_analysis_state['thread'] = thread; online_analysis_state['status'] = 'Running'
        thread.start()
        return jsonify({'success': 'Online analysis started.'})
    except Exception as e:
        logging.error(f"Failed to start online analysis: {e}")
        with online_analysis_state['lock']:
            online_analysis_state['status'] = 'Error'; online_analysis_state['last_log_line'] = f"Failed to start: {e}"
        return jsonify({'error': f'Failed to start online analysis: {e}'}), 500
@app.route('/online/stop', methods=['POST'])
def stop_online_scan():
    with online_analysis_state['lock']:
        if online_analysis_state['status'] != 'Running': return jsonify({'error': 'Online analysis is not running.'}), 400
        online_analysis_state['stop_signal'] = True; online_analysis_state['last_log_line'] = "Stop signal received. Shutting down..."
    return jsonify({'success': 'Stop signal sent to online analysis thread.'})
@app.route('/online/status', methods=['GET'])
def get_online_status():
    with online_analysis_state['lock']:
        status_to_send = {
            'status': online_analysis_state['status'],
            'normal_flows': online_analysis_state['normal_flows'],
            'ransomware_flows': online_analysis_state['ransomware_flows'],
            'last_log_line': online_analysis_state['last_log_line'],
            'blocked_connections': online_analysis_state['blocked_connections'],
        }
    return jsonify(status_to_send)
@app.route('/online/unblock/<rule_id>', methods=['POST'])
def unblock_online_connection(rule_id):
    unblock_connection(rule_id)
    return jsonify({'success': f"Attempted to unblock rule {rule_id}."})

if __name__ == '__main__':
    monitor_thread = threading.Thread(target=monitor_resources); monitor_thread.daemon = True; monitor_thread.start()
    if os.path.exists(OFFLINE_MODEL_PATH):
        scheduler.add_job(trigger_scheduled_scan, 'interval', hours=QUICK_SCAN_INTERVAL_HOURS, id='quick_scan', args=['quick'], misfire_grace_time=3600)
        scheduler.add_job(trigger_scheduled_scan, 'interval', days=FULL_SCAN_INTERVAL_DAYS, id='full_scan', args=['full'], misfire_grace_time=3600*24)
        scheduler.add_listener(scheduled_scan_listener, EVENT_JOB_EXECUTED | EVENT_JOB_ERROR)
        scheduler.start(); logging.info("Scheduled scans initialized.")
        for job in scheduler.get_jobs():
            scan_type = 'quick' if job.id == 'quick_scan' else 'full'
            scheduled_tasks_info[scan_type]['next_run'] = job.next_run_time.isoformat() if job.next_run_time else None
    else:
        logging.warning(f"Default offline model '{OFFLINE_MODEL_NAME}' not found. Scheduled scans will be disabled.")
    socketio.run(app, debug=True, host='0.0.0.0')
