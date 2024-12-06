import os
import re
import csv
import json
import logging
import argparse
from collections import defaultdict
from tabulate import tabulate


# Set up logging
logging.basicConfig(level=logging.INFO)


# Constants
DEFAULT_LOG_FILE = "sample.log"  # Default path for the log file
DEFAULT_CSV_OUTPUT = "log_analysis_results.csv"  # Default CSV output path
DEFAULT_FAILED_LOGIN_THRESHOLD = 10  # Default threshold for suspicious activity

# Log Patterns (Add support for multiple formats)
LOG_PATTERNS = {
    "common": r'(\d+\.\d+\.\d+\.\d+) .*? ".*? (/\S*) .*?" (\d{3})',
    "combined": r'(\d+\.\d+\.\d+\.\d+) .*? "(GET|POST|PUT|DELETE) (/\S*) .*?" (\d{3})',
}


def parse_log_file(file_path, log_format="common"):
    """Parse the log file and extract relevant data."""
    ip_requests = defaultdict(int)
    endpoint_requests = defaultdict(int)
    failed_logins = defaultdict(int)

    # Select the appropriate log pattern
    pattern = LOG_PATTERNS.get(log_format, LOG_PATTERNS["common"])
    log_pattern = re.compile(pattern)

    try:
        with open(file_path, "r") as file:
            for line in file:
                match = log_pattern.search(line)
                if match:
                    ip, endpoint, status_code = match.groups()
                    ip_requests[ip] += 1
                    endpoint_requests[endpoint] += 1
                    if status_code == "401":
                        failed_logins[ip] += 1
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        raise
    except Exception as e:
        logging.error(f"Error reading file: {e}")
        raise

    return ip_requests, endpoint_requests, failed_logins


def save_to_csv(ip_data, endpoint_data, suspicious_activity, output_file):
    """Save the analysis results to a CSV file."""
    with open(output_file, mode="w", newline="") as csvfile:
        writer = csv.writer(csvfile)

        # Write Requests per IP section
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_data.items():
            writer.writerow([ip, count])
        writer.writerow([])

        # Write Most Accessed Endpoint section
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([endpoint_data[0], endpoint_data[1]])
        writer.writerow([])

        # Write Suspicious Activity section
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])


def save_to_json(ip_data, endpoint_data, suspicious_activity, output_file):
    """Save the analysis results to a JSON file."""
    data = {
        "ip_requests": ip_data,
        "most_accessed_endpoint": endpoint_data,
        "suspicious_activity": suspicious_activity
    }
    with open(output_file, "w") as f:
        json.dump(data, f, indent=4)


def print_results(ip_requests, most_accessed_endpoint, suspicious_activity):
    """Print analysis results to the console in a formatted way."""
    print("Requests per IP Address:")
    print(tabulate(ip_requests.items(), headers=["IP Address", "Request Count"], tablefmt="grid"))
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    print("\nSuspicious Activity Detected:")
    print(tabulate(suspicious_activity.items(), headers=["IP Address", "Failed Login Attempts"], tablefmt="grid"))


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Analyze HTTP log files")
    parser.add_argument("log_file", help="Path to the log file", default=DEFAULT_LOG_FILE, nargs="?")
    parser.add_argument("output_file", help="Path to save the output file", default=DEFAULT_CSV_OUTPUT, nargs="?")
    parser.add_argument("--failed-login-threshold", type=int, default=DEFAULT_FAILED_LOGIN_THRESHOLD,
                        help="Threshold for failed login attempts to consider suspicious")
    parser.add_argument("--log-format", choices=LOG_PATTERNS.keys(), default="common", 
                        help="Log format (e.g., 'common', 'combined')")
    parser.add_argument("--output-format", choices=["csv", "json"], default="csv", 
                        help="Output format (e.g., 'csv', 'json')")
    return parser.parse_args()


def main():
    """Main function to perform log analysis."""
    args = parse_arguments()

    log_file = args.log_file
    output_file = args.output_file
    failed_login_threshold = args.failed_login_threshold
    log_format = args.log_format
    output_format = args.output_format

    logging.info(f"Looking for log file at: {os.path.abspath(log_file)}")

    # Parse the log file
    try:
        ip_requests, endpoint_requests, failed_logins = parse_log_file(log_file, log_format)
    except FileNotFoundError:
        return  # Exit if the log file doesn't exist
    except Exception as e:
        logging.error(f"Error during log parsing: {e}")
        return

    # Check if there are any endpoint requests before calling `max()`
    if endpoint_requests:
        most_accessed_endpoint = max(endpoint_requests.items(), key=lambda item: item[1])
    else:
        most_accessed_endpoint = ("None", 0)

    # Sort and identify key metrics
    ip_requests = dict(sorted(ip_requests.items(), key=lambda item: item[1], reverse=True))
    suspicious_activity = {ip: count for ip, count in failed_logins.items() if count > failed_login_threshold}

    # Print results to console
    print_results(ip_requests, most_accessed_endpoint, suspicious_activity)

    # Save results to the chosen output format
    if output_format == "csv":
        save_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity, output_file)
    elif output_format == "json":
        save_to_json(ip_requests, most_accessed_endpoint, suspicious_activity, output_file)

    logging.info(f"Results saved to: {os.path.abspath(output_file)}")


if __name__ == "__main__":
    main()
