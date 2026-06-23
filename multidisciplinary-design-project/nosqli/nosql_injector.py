import argparse
from urllib.parse import parse_qs
from core.scanner import NoSQLInjector
from core.dumper import NoSQLDumper
from colorama import init, Fore, Style

def main():
    init(autoreset=True)
    parser = argparse.ArgumentParser(description='NoSQL Injection Tool')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-X', '--method', default='POST', help='HTTP method (GET or POST)')
    parser.add_argument('-p', '--param', required=True, help='Parameter to test')
    parser.add_argument('-d', '--data', help='Data string (e.g. "username=test&password=test")')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show all payloads tested')
    parser.add_argument('-C', '--custom-header', action='append', help='Custom header (e.g. -C "Cookie: session=abc")')
    parser.add_argument('--time-based', action='store_true', help='Time-based injection testing')

    args = parser.parse_args()

    extra_data = {}
    custom_headers = {}

    if args.data:
        parsed = parse_qs(args.data)
        extra_data = {k: v[0] for k, v in parsed.items()}

    if args.custom_header:
        for header in args.custom_header:
            if ':' in header:
                key, value = header.split(':', 1)
                custom_headers[key.strip()] = value.strip()

    try:
        injector = NoSQLInjector(args.url, args.method, extra_data=extra_data, verbose=args.verbose, custom_headers=custom_headers)
        valid_value = extra_data.get(args.param, "benign_test_value")
        
        if args.time_based:
            result = injector.check_time_based_injection_multi(args.param, valid_value)
            if result:
                pattern_name, _ = result
                choice = input(f"{Fore.CYAN}\n[?] Found {pattern_name}. Dump database? [y/N] {Style.RESET_ALL}").lower()
                if choice == 'y':
                    if 'sleep' in pattern_name.lower():
                        pattern_type = 'sleep'
                    elif 'busy-wait' in pattern_name.lower():
                        pattern_type = 'busy-wait'
                    else:
                        pattern_type = 'busy-wait'
                    
                    dumper = NoSQLDumper(args.url, extra_data, args.method, custom_headers, pattern_type, args.verbose)
                    dumper.dump_users(args.param)
        else:
            injector.check_injection(args.param, valid_value)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted. Exiting...{Style.RESET_ALL}")
        exit(0)

if __name__ == '__main__':
    main()
