import errno
import logging
import os
import time
import shutil
import threading

from datetime import datetime

import logging
from logging.handlers import RotatingFileHandler
from contextlib import contextmanager

# ------------------------------------- Application logging -------------------------------------

log = logging.getLogger('app_logger')

def configure_app_logger(log_path=None, level=logging.INFO, maxFileSizeMb=5):
    if log_path:
        if not os.path.isfile(log_path):
            os.makedirs(log_path, exist_ok=True)
            log_path = os.path.join(log_path, 'netwatcher.log')
        handler = RotatingFileHandler(log_path, maxBytes=maxFileSizeMb*1024*1024, backupCount=5)
        handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
        handler.setLevel(level)
    else:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
        log.addHandler(handler)

    log.addHandler(handler)
    log.setLevel(level)

# @contextmanager 
# def log_exception(): 
#     try: 
#         yield 
#     except Exception as e: 
#         log.exception("Exception occurred") 
#         raise

# ------------------------------------- Events logging -------------------------------------

# TODO: try to use LogRotatingFileHandler instead of custom implementation

def try_log(file_path, message, max_retries=3):
    for _ in range(max_retries):
        try:
            with open(file_path, "a") as f:
                f.write(message + "\n")
            return True
        except OSError as e:
            if e.errno == errno.EACCES:
                continue  # Retry immediately
            else:
                raise  # Raise the exception if it's not a file-in-use error
    else:
        logging.error(f"Failed to log to file {file_path}!")
        return False

def rotate_logs(log_file_path, max_log_files=5, max_file_size=10*1024*1024):
    """
    Rotate log files when they exceed a specified size.

    :param log_file_path: Path to the current log file
    :param max_log_files: Maximum number of archived logs to keep
    :param max_file_size: Maximum size (in bytes) of the log file before rotating
    """
    log_dir, log_file = os.path.split(log_file_path)

    # Ensure the log directory exists
    os.makedirs(log_dir, exist_ok=True)

    # Check if the current log file exists and its size
    if os.path.exists(log_file_path) and os.path.getsize(log_file_path) > max_file_size:
        # Generate a timestamp for the archived log file
        timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
        rotated_log_file = os.path.join(log_dir,f"{log_file}_{timestamp}")

        try:
            shutil.copy2(log_file_path, rotated_log_file)
            os.remove(log_file_path)
        except OSError as e:
            if e.errno != errno.EACCES:
                raise
            else:
                logging.error(f"Failed to rotate log file {log_file_path}!")

        # Clean up old log files, keeping only the most recent `max_log_files` files
        log_files = sorted([f for f in os.listdir(log_dir) if f.startswith(log_file) and f != log_file])
        if len(log_files) > max_log_files:
            for old_log in log_files[:-max_log_files]:
                os.remove(os.path.join(log_dir, old_log))

def start_log_rotation(log_file_path, interval=60, max_log_files=5, max_file_size=10*1024*1024):
    """
    Start a thread to rotate logs periodically.

    :param log_file_path: Path to the current log file
    :param interval: Time interval (in seconds) between log rotations
    :param max_log_files: Maximum number of archived logs to keep
    :param max_file_size: Maximum size (in bytes) of the log file before rotating
    """
    def rotate_logs_periodically(log_file_path, interval, max_log_files, max_file_size):
        while True:
            rotate_logs(log_file_path, max_log_files, max_file_size)
            time.sleep(interval)

    # TODO: move to global scope and make sure we are not leaking threads
    log_rotation_thread = threading.Thread(target=rotate_logs_periodically, args=(log_file_path, interval, max_log_files, max_file_size))
    log_rotation_thread.daemon = True
    log_rotation_thread.start()

    return log_rotation_thread
