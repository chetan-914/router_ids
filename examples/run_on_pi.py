"""
Example: Run intrusion detection on a Raspberry Pi router.

This script demonstrates:
1. Capturing network traffic with tcpdump
2. Running the detection pipeline
3. Handling results and cleanup

On a Raspberry Pi, you may need to:
- Grant tcpdump CAP_NET_RAW capability: sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
- Or run this script with sudo: sudo python examples/run_on_pi.py
"""

import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from router_ids.core import CoreManager
from router_ids.utils.logger import setup_logger

logger = setup_logger(__name__)


def capture_traffic(
    output_file: str, duration: int = 30, interface: str = "eth0"
) -> bool:
    """
    Capture network traffic using tcpdump.

    Args:
        output_file: Path to write pcap file
        duration: Capture duration in seconds
        interface: Network interface to capture on

    Returns:
        True if capture succeeded, False otherwise
    """
    try:
        cmd = [
            "tcpdump",
            "-i",
            interface,
            "-G",
            str(duration),
            "-w",
            output_file,
        ]
        
        logger.info(f"Starting tcpdump: {' '.join(cmd)}")
        result = subprocess.run(cmd, timeout=duration + 5)
        
        if result.returncode == 0:
            logger.info(f"Captured traffic to {output_file}")
            return True
        else:
            logger.error(f"tcpdump failed with return code {result.returncode}")
            return False

    except subprocess.TimeoutExpired:
        logger.error("tcpdump capture timed out")
        return False
    except FileNotFoundError:
        logger.error("tcpdump not found. Install with: sudo apt-get install tcpdump")
        return False
    except Exception as e:
        logger.error(f"Error capturing traffic: {e}")
        return False


def run_detection(pcap_file: str) -> dict:
    """
    Run intrusion detection on pcap file.

    Args:
        pcap_file: Path to pcap file

    Returns:
        Detection results dictionary
    """
    try:
        manager = CoreManager()
        results = manager.run_once(pcap_file)
        return results
    except Exception as e:
        logger.error(f"Error running detection: {e}")
        return {
            "error": str(e),
            "detections": {},
        }


def print_results(results: dict) -> None:
    """Pretty print detection results."""
    print("\n" + "=" * 60)
    print("INTRUSION DETECTION RESULTS")
    print("=" * 60)
    print(f"Timestamp: {results.get('timestamp')}")
    print(f"Pcap File: {results.get('pcap_file')}")
    print("-" * 60)
    
    detections = results.get("detections", {})
    
    if not detections:
        print("No detections performed")
    else:
        for detector_name, detection in detections.items():
            print(f"\n{detector_name.upper()}:")
            print(f"  Detected: {detection.get('detected', False)}")
            print(f"  Score: {detection.get('score', 0.0):.4f}")
            print(f"  Label: {detection.get('label', 'unknown')}")
            if 'reason' in detection:
                print(f"  Reason: {detection['reason']}")
    
    errors = results.get("errors", [])
    if errors:
        print("\nErrors:")
        for error in errors:
            print(f"  - {error}")
    
    print("=" * 60 + "\n")


def main() -> None:
    """Main entry point."""
    logger.info("Router IDS - Example on Raspberry Pi")
    
    # Configuration
    capture_duration = 30  # seconds
    network_interface = "eth0"  # Change to your interface (e.g., wlan0)
    pcap_file = "/tmp/router_ids_capture.pcap"
    
    try:
        # Step 1: Generate dummy models (if not present)
        models_dir = Path(__file__).parent.parent / "src" / "router_ids" / "models"
        model_files = [
            models_dir / "ddos_model.joblib",
            models_dir / "mitm_model.joblib",
            models_dir / "c2c_model.joblib",
        ]
        
        if not all(f.exists() for f in model_files):
            logger.info("Generating dummy models...")
            import subprocess
            subprocess.run(
                [
                    sys.executable,
                    str(models_dir / "make_dummy_models.py"),
                ],
                check=True,
            )
            logger.info("Models generated")
        
        # Step 2: Capture traffic
        logger.info(f"Capturing {capture_duration}s of traffic on {network_interface}...")
        if not capture_traffic(pcap_file, duration=capture_duration, interface=network_interface):
            logger.error("Traffic capture failed")
            return
        
        # Wait a moment for tcpdump to finalize
        time.sleep(1)
        
        # Step 3: Verify pcap file exists
        if not os.path.exists(pcap_file):
            logger.error(f"Pcap file not created: {pcap_file}")
            return
        
        logger.info(f"Pcap file size: {os.path.getsize(pcap_file)} bytes")
        
        # Step 4: Run detection
        logger.info("Running intrusion detection...")
        results = run_detection(pcap_file)
        
        # Step 5: Print results
        print_results(results)
        
        # Step 6: Save results to JSON
        results_file = "/tmp/router_ids_results.json"
        with open(results_file, "w") as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to {results_file}")
        
    except Exception as e:
        logger.error(f"Exception in main: {e}", exc_info=True)
    
    finally:
        # Cleanup
        if os.path.exists(pcap_file):
            os.remove(pcap_file)
            logger.info(f"Cleaned up {pcap_file}")


if __name__ == "__main__":
    main()
