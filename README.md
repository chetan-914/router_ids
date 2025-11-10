
# Router IDS - IoT Intrusion Detection System for Raspberry Pi

A lightweight, extendable intrusion detection library designed to run on a Raspberry Pi used as an IoT router. Detects three attack types from tcpdump pcap captures: **DDoS**, **MITM**, and **C2C** (command-and-control).

## Features

- **Lightweight**: Synchronous, minimal dependencies. Runs on Raspberry Pi.
- **Modular**: Feature extraction, rule-based pre-checks, and pluggable detection models.
- **Efficient**: Single-pass packet parsing and feature extraction per capture interval.
- **Extendable**: Add new detectors by implementing the `FeatureExtractor` interface and registering with `CoreManager`.
- **Safe**: Includes security notes for production deployment.

## Requirements

- Python 3.11+
- Raspberry Pi OS (or any Linux distribution)
- `tcpdump` installed and configured with appropriate permissions
- Dependencies: scapy, pyyaml, scikit-learn, joblib

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/chetan-914/router-ids.git
   cd router-ids
   ```


---

### How to Use `router-ids` as a Library

To integrate the `router-ids` intrusion detection system into your own Python application, follow these steps. The core of the library is the `CoreManager` class, which orchestrates the entire detection process.

#### Step 1: System Prerequisites

Before using the library, the host system (e.g., Raspberry Pi, Kali Linux) must have `tcpdump` installed and configured.

1.  **Install tcpdump**:
    ```bash
    sudo apt-get update
    sudo apt-get install tcpdump
    ```

2.  **Set tcpdump Permissions**: To allow your Python script to capture network traffic, you must either run your script with `sudo` or grant special capabilities to the `tcpdump` executable.

    *   **Option A (Recommended for production/services)**: Grant capabilities to `tcpdump` so it can be run by non-root users.
        ```bash
        # Install the utility if it's missing
        sudo apt-get install libcap2-bin

        # Grant permissions
        sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)
        ```
    *   **Option B (Simple for testing)**: Run your main Python script using `sudo`.
        ```bash
        sudo python your_application.py
        ```

#### Step 2: Install the Library

Place the `router-ids` project folder in your workspace. You can install it into your Python environment using `pip`.

```bash
# Navigate to the root of the router-ids project directory
cd path/to/router-ids

# Install the library
pip install .
```
This makes `router-ids` importable in any of your Python scripts, just like any other package.

#### Step 3: Generate the ML Models

The library requires pre-trained machine learning models to function. A script is provided to generate placeholder models. You only need to do this once.

```bash
python -m router_ids.models.make_dummy_models
```
This command will create the necessary `.joblib` files inside the library's `src/router_ids/models/model_joblib/` directory. The library is pre-configured to find them there.

#### Step 4: Use the Library in Your Code

Now you can import and use `CoreManager` in your application. The basic workflow is:
1.  Capture network traffic to a `.pcap` file.
2.  Instantiate `CoreManager`.
3.  Call the `manager.run_once()` method with the path to the `.pcap` file.
4.  Process the results.

Here is a complete, practical example script:

`my_detector_app.py`
```python
import json
import os
import subprocess
import time
from router_ids.core import CoreManager

def capture_traffic_to_file(pcap_file: str, duration: int = 30, interface: str = "wlan0"):
    """
    Captures network traffic using tcpdump and saves it to a file.
    Returns True on success, False on failure.
    """
    print(f"Starting {duration}-second traffic capture on interface '{interface}'...")
    cmd = ["tcpdump", "-i", interface, "-G", str(duration), "-w", pcap_file]
    
    try:
        # Using subprocess.run to wait for tcpdump to complete
        result = subprocess.run(cmd, timeout=duration + 5, check=True, capture_output=True, text=True)
        print(f"Successfully captured traffic to '{pcap_file}'")
        return True
    except FileNotFoundError:
        print("ERROR: tcpdump not found. Please install it.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"ERROR: tcpdump failed. Return code: {e.returncode}")
        print(f"Stderr: {e.stderr}")
        print("HINT: Do you have the right permissions? Try running with 'sudo' or using 'setcap'.")
        return False
    except subprocess.TimeoutExpired:
        print("ERROR: tcpdump capture timed out.")
        return False

def main():
    """Main application logic."""
    pcap_output_file = "/tmp/live_capture.pcap"
    capture_interface = "wlan0"  # Change this to your network interface
    
    # 1. Capture live traffic
    if not capture_traffic_to_file(pcap_output_file, duration=30, interface=capture_interface):
        return  # Exit if capture fails

    # 2. Initialize the IDS CoreManager
    # It will automatically find the default rules and models within the library
    print("\nInitializing Router IDS CoreManager...")
    manager = CoreManager()

    # 3. Run detection on the captured file
    print(f"Analyzing '{pcap_output_file}' for threats...")
    results = manager.run_once(pcap_output_file)

    # 4. Print the results in a readable format
    print("\n--- INTRUSION DETECTION REPORT ---")
    print(json.dumps(results, indent=2))
    print("--------------------------------\n")
    
    # Example: Check for a specific alert
    if results.get("detections", {}).get("ddos", {}).get("detected"):
        print("ALERT: A potential DDoS attack was detected!")

    # 5. Clean up the capture file
    if os.path.exists(pcap_output_file):
        os.remove(pcap_output_file)
        print(f"Cleaned up temporary file: '{pcap_output_file}'")

if __name__ == "__main__":
    main()
```

#### Step 5 (Advanced): Customizing Paths

If you want to manage your own configuration files and models outside of the library, you can pass their locations to the `CoreManager` during initialization.

```python
# Example of custom configuration
manager = CoreManager(
    rules_path="/etc/my_app_config/rules.yaml",
    thresholds_path="/etc/my_app_config/thresholds.yaml",
    models_dir="/opt/my_app_models/"
)

# The rest of the logic is the same
# results = manager.run_once(pcap_file)
# ...
```