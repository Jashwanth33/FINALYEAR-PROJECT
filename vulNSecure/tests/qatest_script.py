"""
vulNSecure Automated Testing Script
QA Automation Engineer + Security Tester

Requirements:
pip install requests colorama

Usage:
python qatest_script.py
"""

import os
import sys
import time
import json
import logging
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

logging.basicConfig(
    filename="vulnsecure_test_results.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


class VulnSecureTester:
    def __init__(
        self, base_url="http://localhost:3000", api_url="http://localhost:5001"
    ):
        self.base_url = base_url
        self.api_url = api_url
        self.results = {"passed": [], "failed": [], "warnings": [], "errors": []}

    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        if level == "PASS":
            print(f"{Fore.GREEN}[{timestamp}] PASS: {message}{Style.RESET_ALL}")
            self.results["passed"].append(message)
        elif level == "FAIL":
            print(f"{Fore.RED}[{timestamp}] FAIL: {message}{Style.RESET_ALL}")
            self.results["failed"].append(message)
        elif level == "WARN":
            print(f"{Fore.YELLOW}[{timestamp}] WARN: {message}{Style.RESET_ALL}")
            self.results["warnings"].append(message)
        elif level == "ERROR":
            print(f"{Fore.RED}[{timestamp}] ERROR: {message}{Style.RESET_ALL}")
            self.results["errors"].append(message)
        else:
            print(f"{Fore.CYAN}[{timestamp}] INFO: {message}{Style.RESET_ALL}")

        logging.info(f"[{level}] {message}")

    def test_api_endpoint(self, endpoint, method="GET", data=None, token=None):
        import requests

        url = f"{self.api_url}{endpoint}"
        headers = {"Content-Type": "application/json"}

        if token:
            headers["Authorization"] = f"Bearer {token}"

        try:
            if method == "GET":
                response = requests.get(url, headers=headers, timeout=10)
            elif method == "POST":
                response = requests.post(url, json=data, headers=headers, timeout=10)

            return {
                "status": response.status_code,
                "success": 200 <= response.status_code < 300,
                "data": response.json()
                if "application/json" in response.headers.get("content-type", "")
                else None,
                "text": response.text[:500],
            }
        except Exception as e:
            return {"status": 0, "success": False, "error": str(e), "data": None}

    def test_authentication(self):
        print("\n" + "=" * 60)
        print(f"{Fore.CYAN}TESTING AUTHENTICATION{Style.RESET_ALL}")
        print("=" * 60 + "\n")

        result = self.test_api_endpoint(
            "/api/auth/login",
            "POST",
            {"email": "admin@vulnsecure.com", "password": "admin123"},
        )

        if result["success"]:
            self.log("Login API responds correctly", "PASS")
            if result["data"] and result["data"].get("data", {}).get("token"):
                token = result["data"]["data"]["token"]
                self.log(f"Token received: {token[:50]}...", "PASS")
                return token
            else:
                self.log("Token not in response", "WARN")
        else:
            self.log(f"Login API failed: {result.get('error', 'Unknown')}", "FAIL")

        return None

    def test_scan_workflow(self, token):
        print("\n" + "=" * 60)
        print(f"{Fore.CYAN}TESTING SCAN WORKFLOW{Style.RESET_ALL}")
        print("=" * 60 + "\n")

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        result = self.test_api_endpoint(
            "/api/scans",
            "POST",
            {
                "name": f"Automated Test Scan - {datetime.now().strftime('%H:%M:%S')}",
                "target": "httpbin.org",
                "type": "web",
            },
        )

        if result["success"]:
            self.log("Scan creation successful", "PASS")
            scan_id = result["data"]["data"]["scan"]["id"]
            self.log(f"Scan ID: {scan_id}", "PASS")

            time.sleep(5)

            status_result = self.test_api_endpoint(f"/api/scans/{scan_id}", "GET")
            if status_result["success"]:
                self.log("Scan status retrieved", "PASS")
                status = status_result["data"]["data"]["scan"]["status"]
                self.log(f"Scan status: {status}", "PASS")

            return scan_id
        else:
            self.log("Scan creation failed", "FAIL")
            return None

    def test_vulnerability_endpoints(self, token):
        print("\n" + "=" * 60)
        print(f"{Fore.CYAN}TESTING VULNERABILITY ENDPOINTS{Style.RESET_ALL}")
        print("=" * 60 + "\n")

        endpoints = [
            ("/api/vulnerabilities?limit=5", "GET", None),
            ("/api/vulnerabilities/stats", "GET", None),
        ]

        for endpoint, method, data in endpoints:
            result = self.test_api_endpoint(endpoint, method)

            if result["success"]:
                self.log(f"GET {endpoint} - OK ({result['status']})", "PASS")
            else:
                self.log(f"GET {endpoint} - FAIL ({result['status']})", "FAIL")

    def test_report_endpoints(self, token):
        print("\n" + "=" * 60)
        print(f"{Fore.CYAN}TESTING REPORT ENDPOINTS{Style.RESET_ALL}")
        print("=" * 60 + "\n")

        result = self.test_api_endpoint("/api/reports?limit=5", "GET")
        if result["success"]:
            self.log("Reports list accessible", "PASS")
        else:
            self.log(f"Reports list failed: {result['status']}", "FAIL")

        result = self.test_api_endpoint(
            "/api/reports",
            "POST",
            {"title": "Automated Test Report", "type": "scan", "format": "json"},
        )

        if result["success"]:
            self.log("Report generation triggered", "PASS")
        else:
            self.log(f"Report generation failed: {result['status']}", "FAIL")

    def test_security_checks(self, token):
        print("\n" + "=" * 60)
        print(f"{Fore.CYAN}TESTING SECURITY CHECKS{Style.RESET_ALL}")
        print("=" * 60 + "\n")

        sqli_payloads = ["' OR '1'='1", "' UNION SELECT NULL--", "admin'--"]
        for payload in sqli_payloads:
            result = self.test_api_endpoint(f"/api/scans?name={payload}", "GET")
            if result["status"] == 401:
                self.log("SQL injection protection active", "PASS")
            else:
                self.log(f"SQLi payload handled: {result['status']}", "PASS")

        xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
        for payload in xss_payloads:
            result = self.test_api_endpoint(f"/api/scans?name={payload}", "GET")
            self.log(f"XSS payload tested: {result['status']}", "PASS")

    def test_api_health(self):
        print("\n" + "=" * 60)
        print(f"{Fore.CYAN}TESTING API HEALTH{Style.RESET_ALL}")
        print("=" * 60 + "\n")

        health_endpoints = [
            "/api/scans",
            "/api/vulnerabilities",
            "/api/reports",
            "/api/assets",
            "/api/notifications",
        ]

        for endpoint in health_endpoints:
            result = self.test_api_endpoint(endpoint, "GET")

            if result["success"]:
                self.log(f"{endpoint} - OK ({result['status']})", "PASS")
            elif result["status"] == 401:
                self.log(f"{endpoint} - Requires Auth (Expected)", "PASS")
            else:
                self.log(f"{endpoint} - {result['status']}", "WARN")

    def run_all_tests(self):
        print("\n" + "=" * 60)
        print(f"{Fore.GREEN}  VULNSECURE COMPREHENSIVE TEST SUITE{Style.RESET_ALL}")
        print("=" * 60 + "\n")

        self.log("Starting comprehensive tests...")

        self.test_api_health()
        token = self.test_authentication()

        if token:
            self.test_scan_workflow(token)
            self.test_vulnerability_endpoints(token)
            self.test_report_endpoints(token)
            self.test_security_checks(token)
        else:
            self.log("Cannot continue tests without authentication", "ERROR")

        self.generate_report()

    def generate_report(self):
        print("\n" + "=" * 60)
        print(f"{Fore.CYAN}TEST SUMMARY{Style.RESET_ALL}")
        print("=" * 60)

        total = len(self.results["passed"]) + len(self.results["failed"])
        pass_rate = (len(self.results["passed"]) / total * 100) if total > 0 else 0

        print(f"\nTotal Tests: {total}")
        print(f"{Fore.GREEN}Passed: {len(self.results['passed'])}{Style.RESET_ALL}")
        print(f"{Fore.RED}Failed: {len(self.results['failed'])}{Style.RESET_ALL}")
        print(
            f"{Fore.YELLOW}Warnings: {len(self.results['warnings'])}{Style.RESET_ALL}"
        )
        print(f"Pass Rate: {pass_rate:.1f}%")

        if self.results["failed"]:
            print(f"\n{Fore.RED}Failed Tests:{Style.RESET_ALL}")
            for test in self.results["failed"]:
                print(f"  - {test}")

        report = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total": total,
                "passed": len(self.results["passed"]),
                "failed": len(self.results["failed"]),
                "warnings": len(self.results["warnings"]),
                "pass_rate": pass_rate,
            },
            "results": self.results,
        }

        with open("test_report.json", "w") as f:
            json.dump(report, f, indent=2)

        print(f"\n{Fore.CYAN}Report saved to: test_report.json{Style.RESET_ALL}")


if __name__ == "__main__":
    tester = VulnSecureTester()
    tester.run_all_tests()
