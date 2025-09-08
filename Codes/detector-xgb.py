import pandas as pd
import joblib
import time
import os
import datetime
import logging  ### New import for logging

# ==============================================================================
#                             --- CONFIGURATION ---
# ==============================================================================

# --- File Paths ---
MODEL_PATH = 'XGBoost.pkl'
SCALER_PATH = 'XGBoost_Scaler.pkl'

# --- Automatic Path for CICFlowMeter Output ---
# IMPORTANT: Make sure this path to the CICFlowmeter folder is correct for your PC.
CICFLOWMETER_OUTPUT_DIR = r"D:\CICflowmeter\bin\data\daily" 
today_date_str = datetime.date.today().strftime('%Y-%m-%d')
LIVE_CSV_FILENAME = f"{today_date_str}_Flow.csv" 
LIVE_CSV_PATH = os.path.join(CICFLOWMETER_OUTPUT_DIR, LIVE_CSV_FILENAME)

# --- Feature List for the Model ---
MODEL_FEATURES = [
    "Src Port", "Dst Port", "Protocol", "Init Bwd Win Byts", "Pkt Len Max", 
    "Pkt Size Avg", "Pkt Len Mean", "Subflow Bwd Byts", "TotLen Bwd Pkts", 
    "Bwd Pkt Len Max", "Bwd Seg Size Avg", "Bwd Pkt Len Mean", "Pkt Len Var", 
    "Pkt Len Std", "Bwd Pkt Len Min", "Pkt Len Min", "Bwd Header Len", 
    "Bwd IAT Min", "Subflow Fwd Byts", "TotLen Fwd Pkts", "Flow IAT Min", 
    "Fwd Pkt Len Mean", "Fwd Seg Size Avg", "ACK Flag Cnt", "Fwd Pkt Len Max", 
    "Fwd Pkt Len Min"
]

### --- Setup the Logger ---
# This will create a file named 'detection_log.txt' in the same folder as the script.
# It will log all events, with timestamps.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='detection_log.txt',
    filemode='a'  # 'a' means append to the file if it exists
)

# ==============================================================================
#                            --- SCRIPT START ---
# ==============================================================================

print("--- Ransomware Detection System Initializing ---")

# --- Load Model and Scaler ---
try:
    print("Loading model and scaler...")
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    print("Model and scaler loaded successfully.")
    logging.info("System started. Model and scaler loaded.")
except FileNotFoundError as e:
    print(f"FATAL ERROR: Could not find model/scaler file: {e}")
    logging.error(f"FATAL ERROR: Could not find model/scaler file: {e}")
    exit()

# --- Initialize State Variables ---
last_processed_line = 0
### --- Initialize Counters ---
normal_count = 0
ransomware_count = 0

print(f"\nMonitoring live traffic from: {LIVE_CSV_PATH}")
print("Press Ctrl+C to stop.")

# --- Real-Time Detection Loop ---
while True:
    try:
        # Check if the live CSV file has been created yet
        if not os.path.exists(LIVE_CSV_PATH):
            print(f"Waiting for CICFlowMeter to create the data file... ({LIVE_CSV_FILENAME})", end='\r')
            time.sleep(5)
            continue

        # Read the entire CSV file
        full_df = pd.read_csv(LIVE_CSV_PATH, on_bad_lines='skip', low_memory=False)

        # Check if there are new lines to process
        if len(full_df) > last_processed_line:
            new_data = full_df.iloc[last_processed_line:]

            # Check if all required columns are present in the dataframe
            if not all(col in new_data.columns for col in MODEL_FEATURES):
                time.sleep(2)
                continue
            
            # Prepare data for prediction
            df_model_data = new_data[MODEL_FEATURES].apply(pd.to_numeric, errors='coerce').fillna(0)
            scaled_features = scaler.transform(df_model_data)

            # Get predictions
            predictions = model.predict(scaled_features)

            ### --- Process each new flow and its prediction ---
            for i in range(len(new_data)):
                prediction = predictions[i]
                flow_info = new_data.iloc[i]

                # Create a concise string for logging
                log_line = (
                    f"Flow: {flow_info.get('Src IP', 'N/A')}:{flow_info.get('Src Port', 'N/A')} -> "
                    f"{flow_info.get('Dst IP', 'N/A')}:{flow_info.get('Dst Port', 'N/A')} "
                    f"Proto: {flow_info.get('Protocol', 'N/A')}"
                )

                if prediction == 1:
                    # RANSOMWARE DETECTED
                    ransomware_count += 1
                    
                    # Print a detailed alert to the console
                    alert_message = (
                        f"\n\n==================== RANSOMWARE ALERT! ====================\n"
                        f"  Timestamp:     {flow_info.get('Timestamp', 'N/A')}\n"
                        f"  Source:        {flow_info.get('Src IP', 'N/A')}:{flow_info.get('Src Port', 'N/A')}\n"
                        f"  Destination:   {flow_info.get('Dst IP', 'N/A')}:{flow_info.get('Dst Port', 'N/A')}\n"
                        f"  Protocol:      {flow_info.get('Protocol', 'N/A')}\n"
                        f"===========================================================\n"
                    )
                    print(alert_message)
                    
                    # Log the event as a WARNING
                    logging.warning(f"RANSOMWARE DETECTED - {log_line}")

                else:
                    # NORMAL TRAFFIC
                    normal_count += 1
                    # Log the normal event as INFO
                    logging.info(f"Normal traffic detected - {log_line}")

            # Update the number of lines we have processed
            last_processed_line = len(full_df)

        ### --- Print the updating status line ---
        status_line = f"Status: Normal Flows: {normal_count} | Ransomware Flows: {ransomware_count}"
        # The `end='\r'` moves the cursor to the start of the line so it gets overwritten
        print(status_line, end='\r')

    except pd.errors.EmptyDataError:
        # This happens if the file is created but is still empty. It's normal.
        print("Data file is currently empty, waiting for flows...", end='\r')
    except Exception as e:
        # Catch other potential errors
        print(f"\nAn error occurred: {e}")
        logging.error(f"An error occurred in the main loop: {e}")
    
    # Wait for a few seconds before checking the file again
    time.sleep(5)