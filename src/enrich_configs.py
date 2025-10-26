import json
import base64
import socket
import requests
import sys
import os
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qs
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ConfigEnricher:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.location_cache: Dict[str, Tuple[str, str]] = {}

    def get_location_from_ip_api(self, ip: str) -> Tuple[str, str]:
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', headers=self.headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success' and data.get('countryCode'):
                    return data['countryCode'].lower(), data['country']
        except requests.exceptions.RequestException as e:
            logger.warning(f"ip-api.com failed: {e}")
        return '', ''

    def get_location_from_ipapi_co(self, ip: str) -> Tuple[str, str]:
        try:
            response = requests.get(f'https://ipapi.co/{ip}/json/', headers=self.headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('country_code') and data.get('country_name'):
                    return data['country_code'].lower(), data['country_name']
        except requests.exceptions.RequestException as e:
            logger.warning(f"ipapi.co failed: {e}")
        return '', ''

    def get_location_from_ipwhois(self, ip: str) -> Tuple[str, str]:
        try:
            response = requests.get(f'https://ipwhois.app/json/{ip}', headers=self.headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('country_code') and data.get('country'):
                    return data['country_code'].lower(), data['country']
        except requests.exceptions.RequestException as e:
            logger.warning(f"ipwhois.app failed: {e}")
        return '', ''

    def get_location(self, address: str) -> tuple:
        if address in self.location_cache:
            return self.location_cache[address]

        try:
            ip = socket.gethostbyname(address)
        except socket.gaierror:
            logger.warning(f"Could not resolve hostname: {address}")
            return "🏳️", "Unknown"

        apis = [
            self.get_location_from_ip_api,
            self.get_location_from_ipapi_co,
            self.get_location_from_ipwhois,
        ]
        
        for api_func in apis:
            country_code, country = api_func(ip)
            if country_code and country and len(country_code) == 2:
                flag = ''.join(chr(ord('🇦') + ord(c.upper()) - ord('A')) for c in country_code)
                self.location_cache[address] = (flag, country)
                return flag, country
        
        self.location_cache[address] = ("🏳️", "Unknown")
        return "🏳️", "Unknown"

    def decode_vmess(self, config: str) -> Optional[Dict]:
        try:
            encoded = config.replace('vmess://', '')
            decoded = base64.b64decode(encoded).decode('utf-8')
            return json.loads(decoded)
        except (json.JSONDecodeError, base64.Error, UnicodeDecodeError) as e:
            logger.warning(f"Failed to decode vmess: {e}")
            return None

    def parse_vless(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            if url.scheme.lower() != 'vless' or not url.hostname:
                return None
            netloc = url.netloc.split('@')[-1]
            address, port = netloc.split(':') if ':' in netloc else (netloc, '443')
            return {'address': address, 'port': int(port)}
        except (ValueError, TypeError, AttributeError) as e:
            logger.warning(f"Failed to parse vless: {e}")
            return None

    def parse_trojan(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            if url.scheme.lower() != 'trojan' or not url.hostname:
                return None
            port = url.port or 443
            return {'address': url.hostname, 'port': port}
        except (ValueError, TypeError, AttributeError) as e:
            logger.warning(f"Failed to parse trojan: {e}")
            return None

    def parse_hysteria2(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            if url.scheme.lower() not in ['hysteria2', 'hy2'] or not url.hostname or not url.port:
                return None
            return {'address': url.hostname, 'port': url.port}
        except (ValueError, TypeError, AttributeError) as e:
            logger.warning(f"Failed to parse hysteria2: {e}")
            return None

    def parse_shadowsocks(self, config: str) -> Optional[Dict]:
        try:
            parts = config.replace('ss://', '').split('@')
            if len(parts) != 2:
                return None
            server_parts = parts[1].split('#')[0]
            host, port = server_parts.split(':')
            return {'address': host, 'port': int(port)}
        except (ValueError, TypeError, AttributeError, base64.Error, UnicodeDecodeError) as e:
            logger.warning(f"Failed to parse shadowsocks: {e}")
            return None

    def extract_address(self, config: str) -> Optional[str]:
        try:
            config_lower = config.lower()
            
            if config_lower.startswith('vmess://'):
                data = self.decode_vmess(config)
                if data and 'add' in data:
                    return data['add']
            
            elif config_lower.startswith('vless://'):
                data = self.parse_vless(config)
                if data:
                    return data['address']
            
            elif config_lower.startswith('trojan://'):
                data = self.parse_trojan(config)
                if data:
                    return data['address']
            
            elif config_lower.startswith(('hysteria2://', 'hy2://')):
                data = self.parse_hysteria2(config)
                if data:
                    return data['address']
            
            elif config_lower.startswith('ss://'):
                data = self.parse_shadowsocks(config)
                if data:
                    return data['address']
            
            return None
        except Exception as e:
            logger.error(f"Failed to extract address: {e}")
            return None

    def process_configs(self, input_file: str, output_file: str):
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except FileNotFoundError:
            logger.error(f"{input_file} not found!")
            return
        except Exception as e:
            logger.error(f"Error reading {input_file}: {e}")
            return

        configs = []
        for line in lines:
            line = line.strip()
            if not line.startswith('//') and line:
                configs.append(line)

        unique_addresses = set()
        for config in configs:
            address = self.extract_address(config)
            if address:
                unique_addresses.add(address)

        logger.info(f"Found {len(unique_addresses)} unique server addresses")

        for address in unique_addresses:
            flag, country = self.get_location(address)
            logger.info(f"Resolved {address} -> {flag} {country}")

        try:
            os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.location_cache, f, indent=2, ensure_ascii=False)
            logger.info(f"Successfully saved location data to {output_file}")
        except IOError as e:
            logger.error(f"Failed to write output file: {e}")
        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}")


def main():
    if len(sys.argv) < 3:
        print("Usage: python enrich_configs.py <input.txt> <output.json>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]

    enricher = ConfigEnricher()
    enricher.process_configs(input_file, output_file)

if __name__ == '__main__':
    main()
