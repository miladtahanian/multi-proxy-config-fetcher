import json
import base64
import sys
import os
from typing import Dict, Optional
from urllib.parse import urlparse, parse_qs
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ConfigRenamer:
    def __init__(self, location_file: str):
        self.location_cache: Dict[str, tuple] = {}
        self.load_location_cache(location_file)

    def load_location_cache(self, location_file: str):
        try:
            with open(location_file, 'r', encoding='utf-8') as f:
                self.location_cache = json.load(f)
            logger.info(f"Loaded {len(self.location_cache)} location entries from cache")
        except FileNotFoundError:
            logger.error(f"{location_file} not found!")
        except Exception as e:
            logger.error(f"Error loading location cache: {e}")

    def get_location(self, address: str) -> tuple:
        if address in self.location_cache:
            return tuple(self.location_cache[address])
        return ("🏳️", "Unknown")

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
            params = parse_qs(url.query)
            return {
                'uuid': url.username,
                'address': address,
                'port': int(port),
                'flow': params.get('flow', [''])[0],
                'sni': params.get('sni', [address])[0],
                'type': params.get('type', ['tcp'])[0],
                'path': params.get('path', [''])[0],
                'host': params.get('host', [address])[0],
                'security': params.get('security', ['none'])[0]
            }
        except (ValueError, TypeError, AttributeError) as e:
            logger.warning(f"Failed to parse vless: {e}")
            return None

    def parse_trojan(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            if url.scheme.lower() != 'trojan' or not url.hostname:
                return None
            port = url.port or 443
            params = parse_qs(url.query)
            return {
                'password': url.username,
                'address': url.hostname,
                'port': port,
                'sni': params.get('sni', [url.hostname])[0],
                'alpn': params.get('alpn', [''])[0],
                'type': params.get('type', ['tcp'])[0],
                'path': params.get('path', [''])[0],
                'host': params.get('host', [url.hostname])[0]
            }
        except (ValueError, TypeError, AttributeError) as e:
            logger.warning(f"Failed to parse trojan: {e}")
            return None

    def parse_hysteria2(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            if url.scheme.lower() not in ['hysteria2', 'hy2'] or not url.hostname or not url.port:
                return None
            query = dict(pair.split('=') for pair in url.query.split('&')) if url.query else {}
            return {
                'address': url.hostname,
                'port': url.port,
                'password': url.username or query.get('password', ''),
                'sni': query.get('sni', url.hostname)
            }
        except (ValueError, TypeError, AttributeError) as e:
            logger.warning(f"Failed to parse hysteria2: {e}")
            return None

    def parse_shadowsocks(self, config: str) -> Optional[Dict]:
        try:
            parts = config.replace('ss://', '').split('@')
            if len(parts) != 2:
                return None
            method_pass_b64 = parts[0].replace('-', '+').replace('_', '/')
            padding = '=' * (-len(method_pass_b64) % 4)
            method_pass = base64.b64decode(method_pass_b64 + padding).decode('utf-8')
            method, password = method_pass.split(':')
            server_parts = parts[1].split('#')[0]
            host, port = server_parts.split(':')
            return {
                'method': method,
                'password': password,
                'address': host,
                'port': int(port)
            }
        except (ValueError, TypeError, AttributeError, base64.Error, UnicodeDecodeError) as e:
            logger.warning(f"Failed to parse shadowsocks: {e}")
            return None

    def rename_config(self, config: str, index: int, protocol_type: str) -> Optional[str]:
        try:
            config_lower = config.lower()
            
            if config_lower.startswith('vmess://'):
                data = self.decode_vmess(config)
                if not data or not all(k in data for k in ['add', 'port', 'id']):
                    return None
                flag, country = self.get_location(data['add'])
                new_name = f"{flag} {index} - {protocol_type} - {country} : {data['port']}"
                data['ps'] = new_name
                encoded = base64.b64encode(json.dumps(data, ensure_ascii=False).encode('utf-8')).decode('utf-8')
                return f"vmess://{encoded}"
            
            elif config_lower.startswith('vless://'):
                data = self.parse_vless(config)
                if not data:
                    return None
                flag, country = self.get_location(data['address'])
                new_name = f"{flag} {index} - {protocol_type} - {country} : {data['port']}"
                url = urlparse(config)
                params = parse_qs(url.query)
                query_string = '&'.join([f"{k}={v[0]}" for k, v in params.items()])
                new_config = f"vless://{data['uuid']}@{data['address']}:{data['port']}?{query_string}#{new_name}"
                return new_config
            
            elif config_lower.startswith('trojan://'):
                data = self.parse_trojan(config)
                if not data:
                    return None
                flag, country = self.get_location(data['address'])
                new_name = f"{flag} {index} - {protocol_type} - {country} : {data['port']}"
                url = urlparse(config)
                params = parse_qs(url.query)
                query_string = '&'.join([f"{k}={v[0]}" for k, v in params.items()])
                new_config = f"trojan://{data['password']}@{data['address']}:{data['port']}?{query_string}#{new_name}"
                return new_config
            
            elif config_lower.startswith(('hysteria2://', 'hy2://')):
                data = self.parse_hysteria2(config)
                if not data:
                    return None
                flag, country = self.get_location(data['address'])
                new_name = f"{flag} {index} - {protocol_type} - {country} : {data['port']}"
                url = urlparse(config)
                query_string = url.query
                protocol = 'hysteria2' if config_lower.startswith('hysteria2://') else 'hy2'
                new_config = f"{protocol}://{data['password']}@{data['address']}:{data['port']}?{query_string}#{new_name}"
                return new_config
            
            elif config_lower.startswith('ss://'):
                data = self.parse_shadowsocks(config)
                if not data:
                    return None
                flag, country = self.get_location(data['address'])
                new_name = f"{flag} {index} - {protocol_type} - {country} : {data['port']}"
                method_pass = f"{data['method']}:{data['password']}"
                encoded = base64.b64encode(method_pass.encode('utf-8')).decode('utf-8').replace('+', '-').replace('/', '_').rstrip('=')
                new_config = f"ss://{encoded}@{data['address']}:{data['port']}#{new_name}"
                return new_config
            
            return None
        except Exception as e:
            logger.error(f"Failed to rename config: {e}")
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

        renamed_configs = []
        header_lines = []
        configs = []
        
        for line in lines:
            line = line.strip()
            if line.startswith('//') or not line:
                if not configs:
                    header_lines.append(line)
            else:
                configs.append(line)

        counters = {"VLESS": 1, "Trojan": 1, "VMess": 1, "SS": 1, "Hysteria2": 1}
        protocol_map = {'vless': 'VLESS', 'trojan': 'Trojan', 'vmess': 'VMess', 'ss': 'SS', 'hysteria2': 'Hysteria2', 'hy2': 'Hysteria2'}

        for config in configs:
            protocol_key = config.split('://')[0].lower()
            protocol_name = protocol_map.get(protocol_key)
            
            if protocol_name:
                renamed = self.rename_config(config, counters[protocol_name], protocol_name)
                if renamed:
                    renamed_configs.append(renamed)
                    counters[protocol_name] += 1
                else:
                    renamed_configs.append(config)

        try:
            os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
            with open(output_file, 'w', encoding='utf-8') as f:
                for header in header_lines:
                    f.write(header + '\n')
                if header_lines:
                    f.write('\n')
                for config in renamed_configs:
                    f.write(config + '\n\n')
            logger.info(f"Successfully renamed {len(renamed_configs)} configs and saved to {output_file}")
        except IOError as e:
            logger.error(f"Failed to write output file: {e}")
        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}")


def main():
    if len(sys.argv) < 4:
        print("Usage: python rename_configs.py <location.json> <input.txt> <output.txt>")
        sys.exit(1)
    
    location_file = sys.argv[1]
    input_file = sys.argv[2]
    output_file = sys.argv[3]

    renamer = ConfigRenamer(location_file)
    renamer.process_configs(input_file, output_file)

if __name__ == '__main__':
    main()
