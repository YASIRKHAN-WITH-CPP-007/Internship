import requests
import urllib.parse
import os
# Function to load payloads from a file
def load_payloads(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]

# Function to perform SQL Injection test
def sql_injection_test(url, param, payloads):
    for payload in payloads:
        vuln_url = f"{url}?{param}={urllib.parse.quote(payload)}"
        print(f"Testing URL: {vuln_url}")  # Debugging line
        response = requests.get(vuln_url)
        print(f"Response Status Code: {response.status_code}")  # Debugging line
        print(f"Response Text Sample: {response.text[:500]}")  # Debugging line
        if "SQL syntax" in response.text or "mysql_fetch" in response.text:
            print(f"[!] SQL Injection vulnerability detected with payload: {payload} at {vuln_url}")
            return
    print(f"[-] No SQL Injection vulnerability detected at {url}")

# Function to perform XSS test
def xss_test(url, param, payloads):
    for payload in payloads:
        vuln_url = f"{url}?{param}={urllib.parse.quote(payload)}"
        print(f"Testing URL: {vuln_url}")  # Debugging line
        response = requests.get(vuln_url)
        print(f"Response Status Code: {response.status_code}")  # Debugging line
        print(f"Response Text Sample: {response.text[:500]}")  # Debugging line
        if payload in response.text:
            print(f"[!] XSS vulnerability detected with payload: {payload} at {vuln_url}")
            return
    print(f"[-] No XSS vulnerability detected at {url}")

# Function to perform Directory Traversal test
def dir_traversal_test(url, param, payloads):
    for payload in payloads:
        vuln_url = f"{url}?{param}={urllib.parse.quote(payload)}"
        print(f"Testing URL: {vuln_url}")  # Debugging line
        response = requests.get(vuln_url)
        print(f"Response Status Code: {response.status_code}")  # Debugging line
        print(f"Response Text Sample: {response.text[:500]}")  # Debugging line
        if "root:" in response.text or "boot:" in response.text:
            print(f"[!] Directory Traversal vulnerability detected with payload: {payload} at {vuln_url}")
            return
    print(f"[-] No Directory Traversal vulnerability detected at {url}")

# Main function
if __name__ == "__main__":
    url = input("Enter the URL of the web application: ").strip()
    param = input("Enter the parameter to test (e.g., id, name): ").strip()

    # Load payloads
    sql_payloads = load_payloads("C:\\Users\\dell\\Desktop\\Internship\\Task4\\sql_payloads.txt")
    xss_payloads = load_payloads("C:\\Users\\dell\\Desktop\\Internship\\Task4\\xss_payloads.txt")
    traversal_payloads = load_payloads("C:\\Users\\dell\\Desktop\\Internship\\Task4\\traversal_payloads.txt")

    print("\nStarting vulnerability scan...\n")

    # Perform SQL Injection test
    sql_injection_test(url, param, sql_payloads)

    # Perform XSS test
    xss_test(url, param, xss_payloads)

    # Perform Directory Traversal test
    dir_traversal_test(url, param, traversal_payloads)

    print("\nScan completed.")


#https://juice-shop.herokuapp.com/#/search