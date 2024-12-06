# **Log File Analyzer**

## **Overview**

The **Log File Analyzer** is a Python-based script designed to analyze HTTP log files efficiently. It parses the logs to generate insights such as the number of requests per IP address, the most accessed endpoints, and suspicious activity (e.g., failed login attempts). The results are displayed in the terminal and can be exported in either CSV or JSON formats.

---

## **Features**

- **Request Count by IP Address:** Determine how many requests were made by each IP.
- **Most Accessed Endpoint:** Identify the endpoint that received the most traffic.
- **Suspicious Activity Detection:** Detect IPs with excessive failed login attempts.
- **Multiple Log Formats:** Supports parsing logs in *common* and *combined* formats.
- **Customizable Thresholds:** Adjust the threshold for identifying suspicious activity.
- **Export Results:** Save analysis outputs as CSV or JSON files.
- **User-Friendly Output:** View results in a well-formatted table in the terminal.

---

## **Getting Started**

### **Prerequisites**
Ensure you have Python 3.6+ installed on your machine.

Install the required Python libraries:
```bash
pip install tabulate
```

---

### **Usage**

1. Clone or download this repository.
2. Navigate to the directory containing the script.
3. Run the script using the following command:
   ```bash
   python log_analyzer.py [log_file] [output_file] [--options]
   ```

### **Arguments**
- `log_file`: *(Optional)* Path to the log file. Defaults to `sample.log`.
- `output_file`: *(Optional)* Path to save the analysis results. Defaults to `log_analysis_results.csv`.

### **Options**
| Option                  | Description                                                                                   | Default                  |
|-------------------------|-----------------------------------------------------------------------------------------------|--------------------------|
| `--failed-login-threshold` | Threshold for failed login attempts to classify suspicious activity.                          | `10`                     |
| `--log-format`           | Specify the log format: `common` or `combined`.                                               | `common`                 |
| `--output-format`        | Specify the output format: `csv` or `json`.                                                   | `csv`                    |

---

### **Examples**

#### **Basic Usage**
Analyze `access.log` and save results to `output.csv`:
```bash
python log_analyzer.py access.log output.csv
```

#### **Using JSON Output**
Analyze `access.log` and save results to `output.json`:
```bash
python log_analyzer.py access.log output.json --output-format json
```

#### **Setting Custom Threshold**
Analyze `access.log` with a failed login threshold of `5`:
```bash
python log_analyzer.py access.log output.csv --failed-login-threshold 5
```

---

## **Output Details**

1. **Requests per IP:**
   Displays the number of requests received from each IP address.

2. **Most Accessed Endpoint:**
   The endpoint that was accessed most frequently, along with the count.

3. **Suspicious Activity:**
   Lists IPs with failed login attempts exceeding the specified threshold.

### **Sample Output in Terminal**
```plaintext
Requests per IP Address:
+---------------+---------------+
| IP Address    | Request Count |
+---------------+---------------+
| 192.168.0.1   | 120           |
| 192.168.0.2   | 95            |
+---------------+---------------+

Most Frequently Accessed Endpoint:
/home (Accessed 200 times)

Suspicious Activity Detected:
+---------------+------------------------+
| IP Address    | Failed Login Attempts |
+---------------+------------------------+
| 192.168.0.5   | 15                     |
| 192.168.0.6   | 12                     |
+---------------+------------------------+
```

### **Sample CSV Output**
```csv
Requests per IP
IP Address,Request Count
192.168.0.1,120
192.168.0.2,95

Most Accessed Endpoint
Endpoint,Access Count
/home,200

Suspicious Activity
IP Address,Failed Login Count
192.168.0.5,15
192.168.0.6,12
```

---

## **Error Handling**

- **File Not Found:** If the specified log file does not exist, an error message will be displayed, and the script will exit gracefully.
- **Invalid Log Format:** The script uses a default pattern if the specified format is unsupported.

---

## **Contributing**

Contributions are welcome! Feel free to submit issues or pull requests to improve the functionality or add new features.

---

## **License**

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## **Contact**

For any questions or suggestions, feel free to reach out to:
- **Email:** [sakshamchhawan18@gmail.com](mailto:sakshamchhawan18@gmail.com)
- **GitHub:** [sakshamchhawan18](https://github.com/sakshamchhawan18)

---

Happy Logging! 😊