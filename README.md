# RDPS
This project is a multi-faceted Ransomware Detection and Prevention System designed to provide a robust defense against ransomware threats. It integrates both online (network-based) and offline (host-based) detection modules into a unified, user-friendly web dashboard. The system leverages machine learning models to identify malicious patterns in real-time network flows and static file characteristics, offering automated threat quarantine and an optional active prevention protocol to block malicious connections via the system firewall.

## 🚨 Disclaimer
This tool is intended for **educational and research purposes only**. Running software with administrator/root privileges and automatically modifying firewall rules carries inherent risks. The authors are not responsible for any damage or misuse. **Use at your own risk.**

## System Architecture
The RDPS operates in two primary modes:

1.  **Offline (Host-Based) Detection**: This mode focuses on static file analysis. The backend uses a machine learning model (`rf(Dynamic).pkl`) to scan file characteristics (e.g., entropy, PE headers, API imports) to identify potential threats without executing them.
2.  **Online (Network-Based) Detection**: This mode focuses on dynamic traffic analysis. It requires the **CICFlowMeter** tool to be running separately. The backend ingests the flow data from CSV files and uses another model (`XGBoost.pkl`) to detect network patterns indicative of ransomware activity, such as C2 communication or data exfiltration preparation.
------------------------------------------------
## Prerequisites

1.  **Python 3.8+**
2.  **CICFlowMeter**: The online analysis component is entirely dependent on this tool. You must have it installed and running.
    -   Ensure it is configured to generate **daily CSV files**.
3.  **Pre-trained Models**: You must acquire the three model/scaler files (`rf(Dynamic).pkl`, `XGBoost.pkl`, `XGBoost_Scaler.pkl`) and place them in the root of the project directory. *These models are not included in this repository.*
   
------------------------------------------------
## How to Run

### Main Web Dashboard (Recommended)

This is the primary interface for the RDPS.

1.  **Run the Backend Server**:
    For the firewall "Prevention Protocol" to function, you must run this command with administrative privileges.
    
    **On Windows (Admin PowerShell/CMD):**
    ```powershell
    python backend.py
    ```
    **On Linux/macOS (root):**
    ```bash
    sudo python backend.py
    ```

2.  **Access the Dashboard**:
    Open a web browser and navigate to `http://1227.0.0.1:5000`.

3.  **Configure Online Analysis**:
    -   Navigate to the "Online Network Analysis" tab.
    -   Enter the **full, absolute path** to your CICFlowMeter's `daily` output directory (e.g., `D:\CICflowmeter\bin\data\daily`).
    -   Check the "Enable Prevention Protocol" box if you are running with admin rights and want to actively block threats.
    -   Click "Start Monitoring".
