#  Python Security Tools

A collection of specialized Python scripts focused on application security, network reconnaissance, symmetric cryptography, and system resource auditing. Designed to reinforce secure coding practices and modular security automation.

---

##  Scripts & Detailed Overview

### 1.  Network Port Scanner (`script1_network_ports.py`)
* **Description:** Performs local network analysis to identify open ports and active services.
* **Purpose:** Helps assess the local attack surface and verify running network services during preliminary security audits.
* **Key Modules:** `socket`, `sys`

### 2.  Fernet Symmetric Cryptography (`script2_fernet_crypto.py`)
* **Description:** Implements robust symmetric encryption and decryption using the Fernet specification.
* **Purpose:** Secures sensitive information such as configuration tokens, API keys, or local text data against unauthorized access.
* **Key Modules:** `cryptography.fernet`

### 3. Password Policy Validator (`script3_password_validator.py`)
* **Description:** Evaluates password strength against strict security criteria (minimum length, inclusion of uppercase and lowercase letters, numbers, and special symbols).
* **Purpose:** Enforces strong authentication standards and prevents the use of weak, dictionary-based passwords in user registration systems.
* **Key Modules:** `re`, `string`

### 4. System Memory Monitor (`script4_memory_monitor.py`)
* **Description:** A lightweight system auditing utility designed to track RAM consumption and resource performance.
* **Purpose:** Identifies anomalous resource spikes and monitors system health in the local environment.
* **Key Modules:** `os`, `sys`

---

## Prerequisites

Make sure you have **Python 3.x** installed on your system (Linux/Ubuntu, Windows, or macOS).

For cryptographic features, install the required dependency via pip:
```bash
pip install cryptography
