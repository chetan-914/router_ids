"""
Example: Run the intrusion detection system in continuous monitoring mode.
"""

import json
import logging
import sys
import time
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from router_ids.core import CoreManager
from router_ids.utils.logger import setup_logger

# Setup logger for the example script
logger = setup_logger(__name__)

def handle_detection_results(results: dict) -> None:
    """
    This is a callback function that processes detection results.
    You can customize this to send alerts, log to a SIEM, etc.
    """
    print("\n" + "=" * 60)
    print("INTRUSION DETECTION CYCLE COMPLETE")
    print("=" * 60)
    print(f"Timestamp: {results.get('timestamp')}")
    print(f"Pcap File: {results.get('pcap_file')}")
    print("-" * 60)
    
    detections = results.get("detections", {})
    has_detection = False
    
    if not detections:
        print("No detections performed.")
    else:
        for detector_name, detection in detections.items():
            if detection.get('detected', False):
                has_detection = True
                print(f"!!! ALERT: Potential {detector_name.upper()} Attack Detected !!!")
            
            print(f"\n  Detector: {detector_name.upper()}")
            print(f"    Detected: {detection.get('detected', False)}")
            print(f"    Score: {detection.get('score', 0.0):.4f}")
            print(f"    Label: {detection.get('label', 'unknown')}")
            if 'reason' in detection:
                print(f"    Reason: {detection['reason']}")

    if has_detection:
        # Here you could trigger other actions (e.g., send an email)
        logger.warning("One or more potential attacks were detected in this cycle.")
    
    errors = results.get("errors", [])
    if errors:
        print("\nErrors During Analysis:")
        for error in errors:
            print(f"  - {error}")
    
    print("=" * 60 + "\n")


def main() -> None:
    """Main entry point to start and manage the monitor."""
    logger.info("Router IDS - Initializing Continuous Monitor")
    logger.info("NOTE: This script may require root privileges (sudo) to capture network traffic.")
    
    # --- USER IMPLEMENTATION ---
    # 1. Initialize the CoreManager with monitoring parameters.
    #    Change "wlan0" to your network interface (e.g., "eth0").
    manager = CoreManager(
        interface="wlan0",      # Network interface to monitor
        capture_duration=30,    # Capture traffic for 30 seconds
        monitor_interval=60     # Wait 60 seconds between captures
    )
    
    try:
        # 2. Start monitoring and pass the callback function.
        #    The library will now run in the background.
        manager.start_monitoring(callback=handle_detection_results)
        
        # 3. Keep the main script alive while the monitor runs.
        print("Monitoring has started. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Shutdown signal received.")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
    finally:
        # 4. Gracefully stop the monitor on exit.
        logger.info("Stopping monitor...")
        manager.stop_monitoring()
        logger.info("Monitor has been stopped. Exiting.")


if __name__ == "__main__":
    main()