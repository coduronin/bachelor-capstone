from utils.http_client import HttpClient
from payloads.in_band import get_payloads
from colorama import Fore, Style
import time
import json

class NoSQLInjector:
    def __init__(self, target_url, method='POST', extra_data=None, verbose=False, custom_headers=None):
        self.http_client = HttpClient(target_url, method, custom_headers=custom_headers)
        self.payloads = get_payloads()
        self.baseline_response = None
        self.baseline_time = 0
        self.extra_data = extra_data if extra_data else {}
        self.verbose = verbose

    def establish_baseline(self, parameter, valid_value):
        print("Establishing a baseline response...")
        data = self.extra_data.copy()
        data[parameter] = valid_value
        
        start_time = time.time()
        response = self.http_client.send_request(data)
        end_time = time.time()
        
        if response is not None:
            self.baseline_response = response
            self.baseline_time = end_time - start_time
            print(f"Baseline established. Status: {response.status_code}, Length: {len(response.text)}, Time: {self.baseline_time:.2f}s")
            if response.status_code == 200:
                print(f"{Fore.RED}[!] WARNING: Baseline is 200. Use an INVALID value with '-d' for proper detection.{Style.RESET_ALL}")
        else:
            print("Warning: Could not establish baseline.")

    def check_time_based_injection_multi(self, parameter, valid_value="benign_test_value"):
        data = self.extra_data.copy()
        data[parameter] = valid_value
        start_time = time.time()
        self.http_client.send_request(data)
        avg_baseline = time.time() - start_time
        
        print(f"[Time-Based] Baseline: {avg_baseline:.2f}s")
        print(f"[Time-Based] Testing {parameter} with time-based payloads...\n")
        
        threshold = avg_baseline + 2.0
        
        time_based_payloads = []
        for payload in self.payloads:
            is_time_based = False
            if isinstance(payload, dict) and '$where' in payload:
                where_code = str(payload.get('$where', '')).lower()
                if any(keyword in where_code for keyword in ['sleep', 'while', 'for(', 'gettime']):
                    is_time_based = True
            elif isinstance(payload, str):
                payload_lower = payload.lower()
                if any(keyword in payload_lower for keyword in ['sleep', 'while', 'for(']):
                    is_time_based = True
            if is_time_based:
                time_based_payloads.append(payload)
        
        if not time_based_payloads:
            print(f"{Fore.YELLOW}[!] No time-based payloads found{Style.RESET_ALL}")
            return None
        
        print(f"[Time-Based] Found {len(time_based_payloads)} time-based payloads\n")
        
        for idx, payload in enumerate(time_based_payloads, 1):
            data = self.extra_data.copy()
            payload_str = json.dumps(payload) if isinstance(payload, dict) else str(payload)
            data[parameter] = payload_str
            
            start = time.time()
            resp = self.http_client.send_request(data, timeout=threshold)
            elapsed = time.time() - start
            
            if self.verbose:
                if resp:
                    status_code = resp.status_code
                    if status_code == 0:
                        print(f"[VERBOSE] Payload: {payload} | Error: {resp.text} | Time: {elapsed:.2f}s")
                    else:
                        print(f"[VERBOSE] Payload: {payload} | Status: {status_code} | Time: {elapsed:.2f}s")
            
            if elapsed >= threshold or (resp.status_code == 0 and "timed out" in resp.text.lower()):
                if not self.verbose:
                    print(f"[Time-Based] #{idx}/{len(time_based_payloads)}... {Fore.GREEN}SUCCESS ({elapsed:.2f}s){Style.RESET_ALL}")
                
                from urllib.parse import urlencode, quote_plus
                payload_display = data.copy()
                payload_display[parameter] = quote_plus(payload_str)
                
                print(f"\n{Fore.GREEN}[+] Time-based NoSQL Injection DETECTED!{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+] Payload: {payload}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+] URL-encoded: {urlencode(payload_display, quote_via=quote_plus)}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+] Response: {elapsed:.2f}s (Baseline: {avg_baseline:.2f}s){Style.RESET_ALL}\n")
                
                where_code = str(payload.get('$where', '') if isinstance(payload, dict) else payload).lower()
                if 'sleep' in where_code:
                    pattern_name = '$where + sleep()'
                elif 'while' in where_code:
                    pattern_name = '$where + busy-wait'
                else:
                    pattern_name = 'time-based injection'
                
                return (pattern_name, payload)
            else:
                if not self.verbose:
                    print(f"[Time-Based] #{idx}/{len(time_based_payloads)}... {Fore.RED}FAILED ({elapsed:.2f}s){Style.RESET_ALL}")
        
        print(f"{Fore.YELLOW}[-] No time-based injection detected.{Style.RESET_ALL}")
        return None

    def check_injection(self, parameter, valid_value="benign_test_value"):
        self.establish_baseline(parameter, valid_value)
        if self.baseline_response is None:
            return False

        print(f"Testing parameter: {parameter}")
        for payload in self.payloads:
            data = self.extra_data.copy()
            payload_str = json.dumps(payload) if isinstance(payload, dict) else payload
            data[parameter] = payload_str
            
            start_time = time.time()
            response = self.http_client.send_request(data)
            request_time = time.time() - start_time
            
            if self.verbose:
                if response:
                    if response.status_code == 0:
                        print(f"[VERBOSE] {payload_str} | Error | {request_time:.2f}s")
                    else:
                        print(f"[VERBOSE] {payload_str} | {response.status_code} | {request_time:.2f}s")
            
            if response is not None:
                if "sleep" in str(payload) and request_time > 4 and request_time > (self.baseline_time + 3):
                    print(f"{Fore.GREEN}[+] Time-Based injection: {payload_str}{Style.RESET_ALL}")
                    return True

                if response.status_code != self.baseline_response.status_code:
                    if response.status_code in [200, 302] and self.baseline_response.status_code not in [200, 302]:
                        print(f"{Fore.GREEN}[+] Auth Bypass: {payload_str}{Style.RESET_ALL}")
                        return True
                    if response.status_code == 500:
                        print(f"{Fore.YELLOW}[?] Possible Error-Based: {payload_str}{Style.RESET_ALL}")

                try:
                    if response.json() and not self.baseline_response.json():
                        print(f"{Fore.GREEN}[+] JSON Structure change: {payload_str}{Style.RESET_ALL}")
                        return True
                except ValueError:
                    pass

        print(f"Parameter {parameter} does not seem vulnerable.")
        return False
