#!/usr/bin/env python3
"""
Advanced DNS Lookup Tool
Author: zakia-23
Description: Comprehensive DNS lookup tool with multiple record types and analysis
"""

import subprocess
import re
import json
import socket
from datetime import datetime

class DNSAnalyzer:
    def __init__(self):
        self.dns_servers = {
            'google': '8.8.8.8',
            'cloudflare': '1.1.1.1',
            'opendns': '208.67.222.222',
            'quad9': '9.9.9.9',
            'local': 'localhost'
        }
        self.results = {}
    
    def nslookup_query(self, target, dns_server=None, record_type='A'):
        """Perform nslookup query and parse results"""
        try:
            cmd = ['nslookup']
            
            if record_type != 'A':
                cmd.extend(['-type=' + record_type])
            
            if dns_server:
                cmd.extend([target, dns_server])
            else:
                cmd.append(target)
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                return self.parse_nslookup_output(result.stdout, target, dns_server, record_type)
            else:
                return {"error": f"nslookup failed with return code {result.returncode}"}
                
        except subprocess.TimeoutExpired:
            return {"error": "DNS query timeout"}
        except FileNotFoundError:
            return {"error": "nslookup command not found"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}
    
    def parse_nslookup_output(self, output, target, dns_server, record_type):
        """Parse nslookup output for different record types"""
        lines = output.strip().split('\n')
        parsed_data = {
            'target': target,
            'dns_server': dns_server or 'default',
            'record_type': record_type,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'answers': [],
            'authoritative': False,
            'additional_info': {}
        }
        
        current_section = None
        
        for line in lines:
            line = line.strip()
            
            # Skip empty lines and headers
            if not line or line.startswith(';;'):
                continue
            
            # Detect sections
            if 'ANSWER SECTION' in line:
                current_section = 'answer'
                continue
            elif 'AUTHORITY SECTION' in line:
                current_section = 'authority'
                continue
            elif 'ADDITIONAL SECTION' in line:
                current_section = 'additional'
                continue
            
            # Parse server information
            if line.startswith('Server:'):
                parsed_data['server_used'] = line.split(':', 1)[1].strip()
                continue
            elif line.startswith('Address:'):
                parsed_data['server_address'] = line.split(':', 1)[1].strip()
                continue
            
            # Parse answers based on record type
            if current_section == 'answer' and line:
                answer_data = self.parse_answer_line(line, record_type)
                if answer_data:
                    parsed_data['answers'].append(answer_data)
            
            # Check if answer is authoritative
            if 'Authoritative answers can be found from' in line:
                parsed_data['authoritative'] = True
        
        return parsed_data
    
    def parse_answer_line(self, line, record_type):
        """Parse individual answer line based on record type"""
        # Remove multiple spaces
        line = ' '.join(line.split())
        
        if record_type == 'A':
            # Example: "google.com.     300    IN    A    142.251.32.206"
            pattern = r'([^\s]+)\s+\d+\s+IN\s+A\s+([\d.]+)'
            match = re.search(pattern, line)
            if match:
                return {
                    'type': 'A',
                    'name': match.group(1).rstrip('.'),
                    'address': match.group(2),
                    'ttl': '300'
                }
        
        elif record_type == 'AAAA':
            # IPv6 record
            pattern = r'([^\s]+)\s+\d+\s+IN\s+AAAA\s+([\w:]+)'
            match = re.search(pattern, line)
            if match:
                return {
                    'type': 'AAAA',
                    'name': match.group(1).rstrip('.'),
                    'address': match.group(2),
                    'ttl': '300'
                }
        
        elif record_type == 'MX':
            # Mail exchange record
            pattern = r'([^\s]+)\s+\d+\s+IN\s+MX\s+\d+\s+([^\s]+)'
            match = re.search(pattern, line)
            if match:
                return {
                    'type': 'MX',
                    'name': match.group(1).rstrip('.'),
                    'priority': '10',
                    'exchange': match.group(2).rstrip('.')
                }
        
        elif record_type == 'CNAME':
            # Canonical name record
            pattern = r'([^\s]+)\s+\d+\s+IN\s+CNAME\s+([^\s]+)'
            match = re.search(pattern, line)
            if match:
                return {
                    'type': 'CNAME',
                    'name': match.group(1).rstrip('.'),
                    'canonical': match.group(2).rstrip('.')
                }
        
        elif record_type == 'TXT':
            # Text record
            pattern = r'([^\s]+)\s+\d+\s+IN\s+TXT\s+"([^"]+)"'
            match = re.search(pattern, line)
            if match:
                return {
                    'type': 'TXT',
                    'name': match.group(1).rstrip('.'),
                    'text': match.group(2)
                }
        
        elif record_type == 'NS':
            # Name server record
            pattern = r'([^\s]+)\s+\d+\s+IN\s+NS\s+([^\s]+)'
            match = re.search(pattern, line)
            if match:
                return {
                    'type': 'NS',
                    'name': match.group(1).rstrip('.'),
                    'nameserver': match.group(2).rstrip('.')
                }
        
        elif record_type == 'PTR':
            # Reverse lookup record
            pattern = r'([^\s]+)\s+\d+\s+IN\s+PTR\s+([^\s]+)'
            match = re.search(pattern, line)
            if match:
                return {
                    'type': 'PTR',
                    'name': match.group(1),
                    'hostname': match.group(2).rstrip('.')
                }
        
        # Generic fallback pattern
        if not match:
            parts = line.split()
            if len(parts) >= 4:
                return {
                    'type': record_type,
                    'raw_data': line
                }
        
        return None
    
    def query_multiple_records(self, domain):
        """Query multiple DNS record types for a domain"""
        print(f"🔍 Comprehensive DNS Analysis for: {domain}")
        print("=" * 60)
        
        record_types = ['A', 'AAAA', 'MX', 'CNAME', 'TXT', 'NS']
        all_results = {}
        
        for record_type in record_types:
            print(f"\n📋 Querying {record_type} records...")
            result = self.nslookup_query(domain, record_type=record_type)
            
            if 'error' not in result:
                all_results[record_type] = result
                self.display_record_results(result, record_type)
            else:
                print(f"   ❌ No {record_type} records found or error: {result['error']}")
            
        return all_results
    
    def display_record_results(self, result, record_type):
        """Display results for a specific record type"""
        if not result.get('answers'):
            print(f"   ⚠️  No {record_type} records found")
            return
        
        for answer in result['answers']:
            if record_type == 'A':
                print(f"   ✅ {answer['name']} → {answer['address']} (IPv4)")
            elif record_type == 'AAAA':
                print(f"   ✅ {answer['name']} → {answer['address']} (IPv6)")
            elif record_type == 'MX':
                print(f"   ✅ Mail Server: {answer['exchange']} (Priority: {answer.get('priority', 'N/A')})")
            elif record_type == 'CNAME':
                print(f"   ✅ Alias: {answer['name']} → {answer['canonical']}")
            elif record_type == 'TXT':
                print(f"   ✅ TXT: {answer['text'][:50]}{'...' if len(answer['text']) > 50 else ''}")
            elif record_type == 'NS':
                print(f"   ✅ Name Server: {answer['nameserver']}")
    
    def compare_dns_servers(self, domain, record_type='A'):
        """Compare results from different DNS servers"""
        print(f"🌐 Comparing {record_type} records for '{domain}' across DNS servers")
        print("=" * 70)
        
        comparison_results = {}
        
        for server_name, server_ip in self.dns_servers.items():
            print(f"\n🔍 Querying {server_name} DNS ({server_ip})...")
            
            result = self.nslookup_query(domain, dns_server=server_ip, record_type=record_type)
            
            if 'error' not in result and result.get('answers'):
                comparison_results[server_name] = result
                answers = result['answers']
                
                if record_type in ['A', 'AAAA']:
                    addresses = [ans['address'] for ans in answers]
                    print(f"   ✅ {len(addresses)} {record_type} record(s) found:")
                    for addr in addresses:
                        print(f"      • {addr}")
                elif record_type == 'MX':
                    exchanges = [ans['exchange'] for ans in answers]
                    print(f"   ✅ {len(exchanges)} MX record(s) found:")
                    for exchange in exchanges:
                        print(f"      • {exchange}")
            else:
                print(f"   ❌ No results or error: {result.get('error', 'Unknown error')}")
        
        self.display_dns_comparison(comparison_results, domain, record_type)
    
    def display_dns_comparison(self, results, domain, record_type):
        """Display comparison of DNS server results"""
        if not results:
            print("\n❌ No successful DNS queries across all servers")
            return
        
        print("\n" + "=" * 70)
        print("📊 DNS SERVER COMPARISON SUMMARY")
        print("=" * 70)
        
        # Collect all unique answers
        all_answers = {}
        for server_name, result in results.items():
            if result.get('answers'):
                for answer in result['answers']:
                    key = answer.get('address') or answer.get('exchange') or answer.get('canonical') or answer.get('nameserver')
                    if key:
                        if key not in all_answers:
                            all_answers[key] = []
                        all_answers[key].append(server_name)
        
        print(f"\n📋 All unique {record_type} records found for '{domain}':")
        for i, (answer, servers) in enumerate(all_answers.items(), 1):
            server_list = ', '.join(servers)
            print(f"  {i}. {answer}")
            print(f"     📡 Found by: {server_list}")
        
        # Consistency analysis
        total_servers = len(self.dns_servers)
        consistent_answers = {}
        
        for answer, servers in all_answers.items():
            consistency = len(servers) / total_servers * 100
            consistent_answers[answer] = consistency
        
        print(f"\n🎯 Consistency Analysis:")
        for answer, consistency in consistent_answers.items():
            if consistency == 100:
                status = "🟢 PERFECT"
            elif consistency >= 70:
                status = "🟡 GOOD"
            elif consistency >= 40:
                status = "🟠 FAIR"
            else:
                status = "🔴 POOR"
            
            print(f"   • {answer}: {consistency:.0f}% consistent ({status})")
    
    def reverse_lookup(self, ip_address):
        """Perform reverse DNS lookup"""
        print(f"🔄 Reverse DNS lookup for: {ip_address}")
        print("=" * 50)
        
        try:
            # First try with nslookup
            result = self.nslookup_query(ip_address, record_type='PTR')
            
            if 'error' not in result and result.get('answers'):
                print("✅ Reverse lookup results:")
                for answer in result['answers']:
                    print(f"   • {ip_address} → {answer.get('hostname', 'N/A')}")
            else:
                # Fallback to socket library
                try:
                    hostname = socket.gethostbyaddr(ip_address)
                    print(f"✅ {ip_address} → {hostname[0]}")
                except socket.herror:
                    print(f"❌ No PTR record found for {ip_address}")
                except Exception as e:
                    print(f"❌ Reverse lookup failed: {e}")
                    
        except Exception as e:
            print(f"❌ Error: {e}")
    
    def dns_health_check(self, domain):
        """Perform comprehensive DNS health check"""
        print(f"🏥 DNS Health Check for: {domain}")
        print("=" * 50)
        
        checks = {
            'A Records': lambda: self.nslookup_query(domain, record_type='A'),
            'AAAA Records': lambda: self.nslookup_query(domain, record_type='AAAA'),
            'MX Records': lambda: self.nslookup_query(domain, record_type='MX'),
            'NS Records': lambda: self.nslookup_query(domain, record_type='NS'),
            'SOA Records': lambda: self.nslookup_query(domain, record_type='SOA'),
            'TXT Records': lambda: self.nslookup_query(domain, record_type='TXT')
        }
        
        health_status = {}
        
        for check_name, check_function in checks.items():
            print(f"\n🔍 Checking {check_name}...")
            result = check_function()
            
            if 'error' not in result and result.get('answers'):
                health_status[check_name] = '✅ HEALTHY'
                count = len(result['answers'])
                print(f"   ✅ Found {count} record(s)")
            else:
                health_status[check_name] = '❌ MISSING'
                print(f"   ❌ No records found")
        
        # Summary
        print("\n" + "=" * 50)
        print("📊 DNS HEALTH SUMMARY")
        print("=" * 50)
        
        healthy_checks = sum(1 for status in health_status.values() if status == '✅ HEALTHY')
        total_checks = len(health_status)
        health_percentage = (healthy_checks / total_checks) * 100
        
        for check, status in health_status.items():
            print(f"{status} {check}")
        
        print(f"\n🎯 Overall DNS Health: {health_percentage:.0f}%")
        
        if health_percentage == 100:
            print("🟢 EXCELLENT - All DNS records are properly configured")
        elif health_percentage >= 70:
            print("🟡 GOOD - Most DNS records are configured")
        elif health_percentage >= 50:
            print("🟠 FAIR - Some DNS records are missing")
        else:
            print("🔴 POOR - Major DNS configuration issues")

def main():
    analyzer = DNSAnalyzer()
    
    print("🌐 ADVANCED DNS LOOKUP TOOL")
    print("=" * 50)
    print("Comprehensive DNS analysis and troubleshooting")
    
    while True:
        print("\n🔧 DNS Analysis Options:")
        print("1. Quick DNS lookup (A records)")
        print("2. Comprehensive domain analysis")
        print("3. Compare DNS servers")
        print("4. Reverse DNS lookup")
        print("5. DNS health check")
        print("6. Custom record query")
        print("7. Exit")
        
        choice = input("\nSelect option (1-7): ").strip()
        
        if choice == '1':
            domain = input("Enter domain: ").strip()
            if domain:
                result = analyzer.nslookup_query(domain)
                if 'error' not in result:
                    print(f"\n✅ A records for {domain}:")
                    for answer in result.get('answers', []):
                        print(f"   • {answer['name']} → {answer['address']}")
                else:
                    print(f"❌ Error: {result['error']}")
            else:
                print("❌ Please enter a domain")
        
        elif choice == '2':
            domain = input("Enter domain: ").strip()
            if domain:
                analyzer.query_multiple_records(domain)
            else:
                print("❌ Please enter a domain")
        
        elif choice == '3':
            domain = input("Enter domain: ").strip()
            record_type = input("Record type [A]: ").strip() or 'A'
            if domain:
                analyzer.compare_dns_servers(domain, record_type)
            else:
                print("❌ Please enter a domain")
        
        elif choice == '4':
            ip = input("Enter IP address: ").strip()
            if ip:
                analyzer.reverse_lookup(ip)
            else:
                print("❌ Please enter an IP address")
        
        elif choice == '5':
            domain = input("Enter domain: ").strip()
            if domain:
                analyzer.dns_health_check(domain)
            else:
                print("❌ Please enter a domain")
        
        elif choice == '6':
            domain = input("Enter domain: ").strip()
            record_type = input("Record type (A, AAAA, MX, CNAME, TXT, NS, PTR): ").strip().upper()
            if domain and record_type:
                result = analyzer.nslookup_query(domain, record_type=record_type)
                if 'error' not in result:
                    print(f"\n✅ {record_type} records for {domain}:")
                    for answer in result.get('answers', []):
                        if record_type in ['A', 'AAAA']:
                            print(f"   • {answer['name']} → {answer['address']}")
                        elif record_type == 'MX':
                            print(f"   • {answer['exchange']} (Priority: {answer.get('priority', 'N/A')})")
                        elif record_type == 'CNAME':
                            print(f"   • {answer['name']} → {answer['canonical']}")
                        else:
                            print(f"   • {answer}")
                else:
                    print(f"❌ Error: {result['error']}")
            else:
                print("❌ Please enter both domain and record type")
        
        elif choice == '7':
            print("👋 Goodbye!")
            break
        
        else:
            print("❌ Invalid option")

if __name__ == "__main__":
    main()
