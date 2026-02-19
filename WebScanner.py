import requests
from bs4 import BeautifulSoup
import urllib.parse
import colorama
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
from typing import List, Dict, Set


class WebSecurityScanner:
    def __init__(self, target_url: str, max_depth: int = 2):
        """
        Initialize the security scanner.
        """
        self.target_url = target_url.rstrip("/")
        self.max_depth = max_depth
        self.visited_urls: Set[str] = set()
        self.vulnerabilities: List[Dict] = []
        self.session = requests.Session()

        # Disable SSL warnings (for testing environments)
        requests.packages.urllib3.disable_warnings()

        colorama.init()

    # -----------------------------
    # Utility Methods
    # -----------------------------

    def normalize_url(self, url: str) -> str:
        parsed = urllib.parse.urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def report_vulnerability(self, vulnerability: Dict) -> None:
        self.vulnerabilities.append(vulnerability)

        print(f"{colorama.Fore.RED}[VULNERABILITY FOUND]{colorama.Style.RESET_ALL}")
        for key, value in vulnerability.items():
            print(f"{key}: {value}")
        print()

    # -----------------------------
    # Crawler
    # -----------------------------

    def crawl(self, url: str, depth: int = 0) -> None:
        if depth > self.max_depth:
            return

        normalized = self.normalize_url(url)
        if normalized in self.visited_urls:
            return

        try:
            print(f"Crawling: {url}")
            self.visited_urls.add(normalized)

            response = self.session.get(url, verify=False, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")

            for link in soup.find_all("a", href=True):
                next_url = urllib.parse.urljoin(url, link["href"])
                if next_url.startswith(self.target_url):
                    self.crawl(next_url, depth + 1)

        except Exception as e:
            print(f"Error crawling {url}: {e}")

    # -----------------------------
    # Vulnerability Checks
    # -----------------------------

    def check_sql_injection(self, url: str) -> None:
        sql_payloads = ["'", "' OR 1=1--", "' UNION SELECT NULL--"]

        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            return

        for payload in sql_payloads:
            for param in params:
                try:
                    test_params = params.copy()
                    test_params[param] = payload

                    test_query = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = parsed._replace(query=test_query).geturl()

                    response = self.session.get(test_url, verify=False, timeout=5)

                    if any(error in response.text.lower()
                           for error in ["sql", "mysql", "sqlite", "postgresql", "oracle"]):
                        self.report_vulnerability({
                            "type": "SQL Injection",
                            "url": url,
                            "parameter": param,
                            "payload": payload
                        })

                except Exception:
                    pass

    def check_xss(self, url: str) -> None:
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>"
        ]

        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            return

        for payload in xss_payloads:
            for param in params:
                try:
                    test_params = params.copy()
                    test_params[param] = payload

                    test_query = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = parsed._replace(query=test_query).geturl()

                    response = self.session.get(test_url, verify=False, timeout=5)

                    if payload in response.text:
                        self.report_vulnerability({
                            "type": "Cross-Site Scripting (XSS)",
                            "url": url,
                            "parameter": param,
                            "payload": payload
                        })

                except Exception:
                    pass

    def check_sensitive_info(self, url: str) -> None:
        sensitive_patterns = {
            "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "api_key": r"api[_-]?key[_-]?['\"`]([a-zA-Z0-9]{32,45})['\"`]"
        }

        try:
            response = self.session.get(url, verify=False, timeout=5)

            for info_type, pattern in sensitive_patterns.items():
                matches = re.findall(pattern, response.text)
                if matches:
                    self.report_vulnerability({
                        "type": "Sensitive Information Exposure",
                        "url": url,
                        "info_type": info_type
                    })

        except Exception:
            pass

    # -----------------------------
    # Main Scan
    # -----------------------------

    def scan(self) -> List[Dict]:
        print(f"\n{colorama.Fore.BLUE}Starting scan of {self.target_url}{colorama.Style.RESET_ALL}\n")

        # Crawl first
        self.crawl(self.target_url)

        print(f"\nDiscovered {len(self.visited_urls)} URLs\n")

        # Run checks concurrently
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []

            for url in self.visited_urls:
                futures.append(executor.submit(self.check_sql_injection, url))
                futures.append(executor.submit(self.check_xss, url))
                futures.append(executor.submit(self.check_sensitive_info, url))

            # Wait for all to complete
            for future in as_completed(futures):
                future.result()

        return self.vulnerabilities


# -----------------------------
# CLI Entry Point
# -----------------------------

if __name__ == "__main__":
    if len(sys.argv) != 2:
        #print("Usage: python scanner.py <target_url>")
        #sys.exit(1)

    target_url = sys.argv[1]

    scanner = WebSecurityScanner(target_url)
    results = scanner.scan()
    


    print(f"\n{colorama.Fore.GREEN}Scan Complete!{colorama.Style.RESET_ALL}")
    print(f"Total URLs scanned: {len(scanner.visited_urls)}")
    print(f"Vulnerabilities found: {len(results)}")


# In[ ]:




