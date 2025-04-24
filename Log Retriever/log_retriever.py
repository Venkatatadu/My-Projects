import os
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("retriever.log"),
        logging.StreamHandler()
    ]
)

def retrieve_logs(file_path):
    """
    Retrieve and display logs from a specified file.
    
    Args:
        file_path (str): Path to the log file.
    """
    if not os.path.exists(file_path):
        logging.error(f"Log file not found: {file_path}")
        return
    
    try:
        with open(file_path, 'r') as file:
            logging.info(f"Reading logs from {file_path}...")
            logs = file.readlines()
            for line in logs:
                print(line.strip())
    except Exception as e:
        logging.error(f"Failed to retrieve logs: {e}")

def main():
    # Ask for the log file path
    log_file = input("Enter the path to the log file: ").strip()
    retrieve_logs(log_file)

if __name__ == "__main__":
    main()
