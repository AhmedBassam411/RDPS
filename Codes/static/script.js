// --- START OF FILE script.js ---

document.addEventListener('DOMContentLoaded', () => {
    // General Setup
    document.querySelector('.tab-link')?.click();
    startResourceMonitoring();
    initializeSocketIO(); // <-- NEW

    // Offline Analysis Setup
    initializeOfflineScanner();
    initializeQuarantineControls();
    loadQuarantineList();
    initializeScheduledScans();
    initializePauseButton();

    // Online Analysis Setup
    initializeOnlineScanner();
    initializeOnlineCharts();
    pollOnlineStatus();
});

// --- NEW: WEBSOCKET SETUP ---
function initializeSocketIO() {
    const socket = io();

    socket.on('connect', () => {
        console.log('Successfully connected to real-time server.');
    });

    socket.on('disconnect', () => {
        console.log('Disconnected from real-time server.');
    });

    // Listen for single new item from a scan
    socket.on('quarantine_update', (newItem) => {
        console.log('Received real-time quarantine update:', newItem);
        addQuarantineItemToTable(newItem);
    });

    // Listen for event that requires a full list refresh (e.g., after delete/restore)
    socket.on('quarantine_list_changed', () => {
        console.log('Received signal to refresh quarantine list.');
        loadQuarantineList();
    });
}


// --- GENERAL UI & SHARED FUNCTIONS ---
// (The rest of the script is unchanged from the previous step)
function openTab(evt, tabName) {
    let i, tabcontent, tablinks;
    tabcontent = document.getElementsByClassName("tab-content"); for (i = 0; i < tabcontent.length; i++) { tabcontent[i].classList.remove("active"); }
    tablinks = document.getElementsByClassName("tab-link"); for (i = 0; i < tablinks.length; i++) { tablinks[i].classList.remove("active"); }
    document.getElementById(tabName).classList.add("active"); evt.currentTarget.className += " active";
}

let mainResourceChart, onlineResourceChart;
function startResourceMonitoring() {
    const mainCtx = document.getElementById('resource-chart')?.getContext('2d');
    const onlineCtx = document.getElementById('online-resource-chart')?.getContext('2d');
    const createChart = (ctx) => {
        if (!ctx) return null;
        const cpuGradient = ctx.createLinearGradient(0, 0, 0, 300); cpuGradient.addColorStop(0, 'rgba(59, 130, 246, 0.5)'); cpuGradient.addColorStop(1, 'rgba(59, 130, 246, 0)');
        const memGradient = ctx.createLinearGradient(0, 0, 0, 300); memGradient.addColorStop(0, 'rgba(163, 113, 247, 0.5)'); memGradient.addColorStop(1, 'rgba(163, 113, 247, 0)');
        return new Chart(ctx, { type: 'line', data: { labels: Array(30).fill(''), datasets: [ { label: 'CPU Usage (%)', data: [], borderColor: '#3b82f6', backgroundColor: cpuGradient, fill: true, tension: 0.4, pointRadius: 0 }, { label: 'Memory Usage (%)', data: [], borderColor: '#a371f7', backgroundColor: memGradient, fill: true, tension: 0.4, pointRadius: 0 } ] }, options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, max: 100 }, x: { display: false } }, plugins: { legend: { position: 'bottom', labels: { color: '#8b949e' } } }, animation: { duration: 0 }, interaction: { intersect: false, mode: 'index' } } });
    };
    mainResourceChart = createChart(mainCtx); onlineResourceChart = createChart(onlineCtx);
    setInterval(async () => {
        try {
            const response = await fetch('/system-stats'); if (!response.ok) return;
            const stats = await response.json(); const dataLength = Math.max((stats.cpu || []).length, (stats.memory || []).length); const labels = Array(dataLength).fill('');
            [mainResourceChart, onlineResourceChart].forEach(chart => {
                if (chart) { chart.data.datasets[0].data = stats.cpu; chart.data.datasets[1].data = stats.memory; chart.data.labels = labels; chart.update('none'); }
            });
        } catch (error) { console.error("Failed to fetch system stats:", error); }
    }, 2000);
}


// ==============================================================================
// --- OFFLINE ANALYSIS SECTION ---
// ==============================================================================

let activeOfflinePollingInterval = null; let activeOfflineTaskId = null; let displayedResultsCount = 0;
let countdownInterval;
function initializeScheduledScans() {
    pollScheduledScansStatus();
    setInterval(pollScheduledScansStatus, 5000);
}

let nextRunTimes = { quick: null, full: null };
async function pollScheduledScansStatus() {
    try {
        const response = await fetch('/offline/schedule/status'); if (!response.ok) throw new Error('Could not fetch schedule status');
        const data = await response.json(); updateScanBox('quick', data.quick); updateScanBox('full', data.full);
        const runningScheduledTask = data.quick.current_task_id || data.full.current_task_id;
        if (runningScheduledTask && runningScheduledTask !== activeOfflineTaskId) {
            console.log("New scheduled scan detected, switching progress view to task:", runningScheduledTask); resetOfflineProgressUI(); pollOfflineStatus(runningScheduledTask);
        }
        if (!countdownInterval) { countdownInterval = setInterval(updateCountdowns, 1000); }
    } catch (error) {
        console.error(error); document.getElementById('quick-scan-status').textContent = 'Connection Error'; document.getElementById('full-scan-status').textContent = 'Connection Error';
    }
}
function updateScanBox(type, info) {
    const statusEl = document.getElementById(`${type}-scan-status`);
    statusEl.textContent = info.status;
    nextRunTimes[type] = info.next_run ? new Date(info.next_run) : null;
}
function updateCountdowns() { updateCountdown('quick', nextRunTimes.quick); updateCountdown('full', nextRunTimes.full); }
function formatTime(ms) { if (ms < 0) return 'Now!'; const totalSeconds = Math.floor(ms / 1000); const days = Math.floor(totalSeconds / 86400); const hours = Math.floor((totalSeconds % 86400) / 3600); const minutes = Math.floor((totalSeconds % 3600) / 60); const seconds = totalSeconds % 60; let parts = []; if (days > 0) parts.push(`${days}d`); parts.push(`${String(hours).padStart(2, '0')}h`); parts.push(`${String(minutes).padStart(2, '0')}m`); parts.push(`${String(seconds).padStart(2, '0')}s`); return parts.join(' '); }
function updateCountdown(type, nextRunDate) { const timerEl = document.getElementById(`${type}-scan-timer`); if (nextRunDate) { const remaining = nextRunDate.getTime() - Date.now(); timerEl.textContent = formatTime(remaining); } else { timerEl.textContent = 'Not scheduled'; } }
function resetOfflineProgressUI() {
    document.getElementById('offline-scan-status').textContent = 'Awaiting Task'; document.getElementById('offline-scan-progress').textContent = 'Idle'; document.getElementById('offline-scan-progress-bar').style.width = '0%';
    ['scanned-counter', 'detected-counter', 'skipped-counter'].forEach(id => document.getElementById(id).innerText = '0');
    document.querySelector("#offline-alerts ul").innerHTML = ""; displayedResultsCount = 0;
}
function pollOfflineStatus(taskId) {
    if (activeOfflinePollingInterval) { clearInterval(activeOfflinePollingInterval); }
    activeOfflineTaskId = taskId; const scanButton = document.getElementById('offline-scan-button'); const pauseButton = document.getElementById('offline-pause-button'); pauseButton.disabled = false;
    activeOfflinePollingInterval = setInterval(async () => {
        try {
            const statusResponse = await fetch(`/offline/status/${taskId}`); if (!statusResponse.ok) throw new Error("Server connection issue for task status");
            const task = await statusResponse.json(); pauseButton.textContent = task.is_paused ? 'Resume' : 'Pause'; let progressText = task.progress || 'Initializing...';
            if (task.is_paused) { progressText = 'Paused' } else if (task.total_files > 0) {
                const totalProgress = task.files_processed + task.skipped_files; progressText = `Processing ${totalProgress} / ${task.total_files}`;
                const percentage = (totalProgress / task.total_files) * 100; document.getElementById('offline-scan-progress-bar').style.width = `${percentage}%`;
            }
            document.getElementById('offline-scan-progress').textContent = progressText;
            if (task.results && task.results.length > displayedResultsCount) {
                const newResults = task.results.slice(displayedResultsCount); newResults.forEach(fileResult => { if (fileResult.prediction === 'Ransomware') addThreatAlert(fileResult.filename, fileResult.score, fileResult.status); }); displayedResultsCount = task.results.length;
            }
            document.getElementById('scanned-counter').innerText = task.files_processed; document.getElementById('detected-counter').innerText = document.querySelector("#offline-alerts ul").children.length; document.getElementById('skipped-counter').innerText = task.skipped_files;
            if (task.status === 'COMPLETE' || task.status === 'ERROR') {
                clearInterval(activeOfflinePollingInterval); activeOfflineTaskId = null; pauseButton.disabled = true; pauseButton.textContent = 'Pause';
                scanButton.disabled = false; scanButton.textContent = 'Initiate Custom Scan'; document.getElementById('offline-scan-progress-bar').style.width = task.status === 'COMPLETE' ? '100%' : '0%';
                if (task.status === 'COMPLETE') { document.getElementById('offline-scan-status').textContent = 'Scan Finished!'; document.getElementById('offline-scan-progress').textContent = 'All files processed.'; } else { document.getElementById('offline-scan-status').textContent = `Error: ${task.message}`; }
                loadQuarantineList();
            }
        } catch (error) {
            clearInterval(activeOfflinePollingInterval); activeOfflineTaskId = null; document.getElementById('offline-scan-status').textContent = 'Connection to server lost.';
            scanButton.disabled = false; scanButton.textContent = 'Initiate Custom Scan'; pauseButton.disabled = true; pauseButton.textContent = 'Pause';
        }
    }, 1000);
}
function initializeOfflineScanner() {
    const scanForm = document.getElementById('offline-scan-form'); if (!scanForm) return;
    const scanButton = document.getElementById('offline-scan-button'); const thresholdSlider = document.getElementById('threshold-slider'); const thresholdValue = document.getElementById('threshold-value');
    thresholdSlider.addEventListener('input', (e) => thresholdValue.textContent = e.target.value);
    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault(); scanButton.disabled = true; scanButton.textContent = 'Initializing...'; resetOfflineProgressUI();
        const formData = new FormData(scanForm);
        try {
            const startResponse = await fetch('/offline/scan-directory', { method: 'POST', body: formData });
            const responseData = await startResponse.json(); if (!startResponse.ok) throw new Error(responseData.error || `Server error`);
            document.getElementById('offline-scan-status').textContent = 'Custom Scan in Progress'; pollOfflineStatus(responseData.task_id);
        } catch (error) { document.getElementById('offline-scan-status').textContent = `Error: ${error.message}`; scanButton.disabled = false; scanButton.textContent = 'Initiate Custom Scan'; }
    });
}
function initializePauseButton() {
    const pauseButton = document.getElementById('offline-pause-button');
    pauseButton?.addEventListener('click', async () => {
        try {
            const response = await fetch('/offline/toggle-pause', { method: 'POST' });
            const data = await response.json(); if (data.success) { pauseButton.textContent = data.is_paused ? 'Resume' : 'Pause'; }
        } catch (error) { console.error("Failed to toggle pause:", error); alert("Error communicating with server to toggle pause."); }
    });
}
function addThreatAlert(fileName, score, status) {
    const alertsList = document.querySelector("#offline-alerts ul"); if (alertsList) {
        const li = document.createElement("li"); const statusText = status.startsWith("Quarantined") ? " (Quarantined)" : "";
        li.innerHTML = `<strong>${fileName}</strong> <span>(Confidence: ${(score * 100).toFixed(1)}%)${statusText}</span>`; alertsList.prepend(li);
    }
}
function addQuarantineItemToTable(item) {
    const tableBody = document.getElementById('quarantine-table-body');
    if (!tableBody) return;

    // Remove placeholder if it exists
    const placeholder = tableBody.querySelector('.placeholder-text');
    if (placeholder) {
        tableBody.innerHTML = '';
    }

    // Enable bulk action buttons
    document.getElementById('quarantine-restore-all').disabled = false;
    document.getElementById('quarantine-delete-all').disabled = false;

    // Add new row
    const row = document.createElement('tr');
    row.id = `q-item-${item.id}`; // Add an ID for potential future use (like highlighting)
    row.innerHTML = `<td>${item.filename}</td><td>${item.original_path}</td><td>${item.quarantined_at}</td><td class="action-buttons"><button class="btn-restore" data-id="${item.id}">Restore</button><button class="btn-delete" data-id="${item.id}">Delete</button></td>`;
    tableBody.prepend(row); // Prepend to see the newest items first
}
async function loadQuarantineList() {
    const tableBody = document.getElementById('quarantine-table-body'); if (!tableBody) return;
    try {
        const response = await fetch('/offline/quarantine/list'); const manifest = await response.json(); tableBody.innerHTML = '';
        const hasItems = Object.keys(manifest).length > 0;
        document.getElementById('quarantine-restore-all').disabled = !hasItems; document.getElementById('quarantine-delete-all').disabled = !hasItems;
        if (!hasItems) { tableBody.innerHTML = `<tr><td colspan="4" class="placeholder-text">No files are currently in quarantine.</td></tr>`; return; }
        for (const [id, item] of Object.entries(manifest)) {
             addQuarantineItemToTable({ ...item, id: id });
        }
    } catch (error) {
        console.error('Failed to load quarantine list:', error);
        tableBody.innerHTML = `<tr><td colspan="4" class="placeholder-text danger-text">Error loading quarantine list.</td></tr>`;
    }
}
function initializeQuarantineControls() {
    document.getElementById('quarantine-table-body')?.addEventListener('click', (e) => {
        const target = e.target; const id = target.dataset.id;
        if (target.classList.contains('btn-restore')) {
            if (!confirm(`Are you sure you want to restore this file? It might be dangerous.`)) return;
            fetch(`/offline/quarantine/restore/${id}`, { method: 'POST' }).then(res => res.json()).then(data => { alert(data.success || data.error); }).catch(err => alert(`Error: ${err}`));
        } else if (target.classList.contains('btn-delete')) {
            if (!confirm('Are you sure you want to permanently delete this file? This action cannot be undone.')) return;
            fetch(`/offline/quarantine/delete/${id}`, { method: 'POST' }).then(res => res.json()).then(data => { alert(data.success || data.error); }).catch(err => alert(`Error: ${err}`));
        }
    });
    document.getElementById('quarantine-restore-all')?.addEventListener('click', () => {
        if (!confirm('Are you sure you want to restore ALL files from quarantine? This could be dangerous.')) return;
        fetch('/offline/quarantine/restore-all', { method: 'POST' }).then(res => res.json()).then(data => { alert(data.success || data.error); }).catch(err => alert(`Error: ${err}`));
    });
    document.getElementById('quarantine-delete-all')?.addEventListener('click', () => {
        if (!confirm('Are you sure you want to permanently delete ALL files in quarantine? This action cannot be undone.')) return;
        fetch('/offline/quarantine/delete-all', { method: 'POST' }).then(res => res.json()).then(data => { alert(data.success || data.error); }).catch(err => alert(`Error: ${err}`));
    });
}

// ==============================================================================
// --- ONLINE ANALYSIS SECTION ---
// ==============================================================================
let onlineFlowChart;
function initializeOnlineCharts() {
    const ctx = document.getElementById('online-flow-chart')?.getContext('2d'); if (!ctx) return;
    onlineFlowChart = new Chart(ctx, { type: 'pie', data: { labels: ['Normal Flows', 'Ransomware Flows'], datasets: [{ data: [0, 0], backgroundColor: ['#2ea043', '#f85149'], borderColor: 'var(--card-bg-color)', borderWidth: 2 }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { color: '#8b949e' } } } } });
}
let onlinePollingInterval;
function pollOnlineStatus() {
    onlinePollingInterval = setInterval(async () => {
        try {
            const response = await fetch('/online/status'); if (!response.ok) return;
            const state = await response.json();
            document.getElementById('online-system-status').textContent = state.status; document.getElementById('online-last-event').textContent = state.last_log_line; document.getElementById('normal-flows-counter').innerText = state.normal_flows; document.getElementById('ransomware-flows-counter').innerText = state.ransomware_flows;
            if (onlineFlowChart) { onlineFlowChart.data.datasets[0].data = [state.normal_flows, state.ransomware_flows]; onlineFlowChart.update(); }
            const tableBody = document.getElementById('blocked-connections-table-body'); tableBody.innerHTML = '';
            const threatEvents = Object.entries(state.blocked_connections);
            if (threatEvents.length === 0) {
                tableBody.innerHTML = `<tr><td colspan="6" class="placeholder-text">No threat events logged yet.</td></tr>`;
            } else {
                for (const [id, item] of threatEvents) {
                    const row = document.createElement('tr');
                    const isBlocked = id.startsWith('RDPS-BLOCK-');
                    const statusText = isBlocked ? 'Blocked' : 'Detected Only';
                    const statusClass = isBlocked ? 'danger-text' : 'warning-text';
                    const actionsHtml = isBlocked
                        ? `<td class="action-buttons"><button class="btn-unblock" data-id="${id}">Unblock</button></td>`
                        : '<td>-</td>';

                    row.innerHTML = `
                        <td>${item.src_ip}</td>
                        <td>${item.dst_ip}:${item.dst_port}</td>
                        <td>${item.protocol}</td>
                        <td><span class="${statusClass}">${statusText}</span></td>
                        <td>${item.blocked_at}</td>
                        ${actionsHtml}
                    `;
                    tableBody.appendChild(row);
                }
            }
            const scanButton = document.getElementById('online-scan-button');
            if (state.status === 'Running') { scanButton.textContent = 'Stop Monitoring'; scanButton.classList.add('stop-button'); scanButton.disabled = false; } else { scanButton.textContent = 'Start Monitoring'; scanButton.classList.remove('stop-button'); scanButton.disabled = false; }
        } catch (error) { console.error("Failed to poll online status:", error); document.getElementById('online-system-status').textContent = 'Connection Error'; }
    }, 2000);
}
function initializeOnlineScanner() {
    const scanForm = document.getElementById('online-scan-form');
    const scanButton = document.getElementById('online-scan-button');
    if (!scanForm || !scanButton) return;
    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault(); scanButton.disabled = true;
        if (scanButton.classList.contains('stop-button')) {
            scanButton.textContent = 'Stopping...';
            try { const response = await fetch('/online/stop', { method: 'POST' }); const result = await response.json(); if (!response.ok) throw new Error(result.error); } catch (error) { alert(`Error stopping monitoring: ${error.message}`); scanButton.disabled = false; }
        } else {
            scanButton.textContent = 'Starting...';
            const formData = new FormData(scanForm);
            try { const response = await fetch('/online/start', { method: 'POST', body: formData }); const result = await response.json(); if (!response.ok) throw new Error(result.error); } catch (error) { alert(`Error starting monitoring: ${error.message}`); document.getElementById('online-system-status').textContent = 'Error'; document.getElementById('online-last-event').textContent = error.message; scanButton.disabled = false; }
        }
    });
    document.getElementById('blocked-connections-table-body')?.addEventListener('click', (e) => {
        const target = e.target; if (target.classList.contains('btn-unblock')) {
            const ruleId = target.dataset.id; if (!confirm(`Are you sure you want to unblock this connection?`)) return;
            fetch(`/online/unblock/${ruleId}`, { method: 'POST' }).then(res => res.json()).then(data => { if (data.error) alert(data.error); }).catch(err => alert(`Error: ${err}`));
        }
    });
}