import os
import json
import subprocess
import time
import tempfile
import concurrent.futures
import random
import sys
import logging
import requests
import platform
import shutil
import socket

# 被墙网站用于验证（梯子必须能访问这些）
TEST_URLS_GFW = [
    'http://www.google.com/generate_204',
    'http://www.youtube.com',
    'http://twitter.com',
    'http://facebook.com',
]

# IP检测服务
IP_CHECK_URLS = [
    'http://ipinfo.io/ip',
    'http://api.ipify.org',
]

# UDP测试目标（用于hysteria2/tuic）
UDP_TEST_HOST = '8.8.8.8'
UDP_TEST_PORT = 53


class Validator:
    def __init__(self, sing_box_path=None):
        if sing_box_path and os.path.exists(sing_box_path):
            self.sing_box_path = sing_box_path
        else:
            self.sing_box_path = self._find_sing_box()
        
        if self.sing_box_path and os.path.exists(self.sing_box_path):
            print(f"Validator: Using sing-box at {self.sing_box_path}")
        else:
            print(f"Validator: sing-box binary not found. Validation will be skipped.")
        
        self.logger = logging.getLogger('Validator')
        self.original_ip = self._get_original_ip()
        print(f"Validator: Original IP (GitHub Actions): {self.original_ip}")

    def _get_original_ip(self):
        """获取当前机器的真实IP（不经过代理）"""
        for url in IP_CHECK_URLS:
            try:
                resp = requests.get(url, timeout=5)
                if resp.status_code == 200:
                    ip = resp.text.strip()
                    if ip:
                        return ip
            except:
                continue
        return None

    def _find_sing_box(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        bin_dir = os.path.join(base_dir, 'bin')
        
        system = platform.system().lower()
        machine = platform.machine().lower()
        if machine == 'x86_64':
            machine = 'amd64'
        elif machine == 'aarch64':
            machine = 'arm64'
        
        possible_names = [
            f"sing-box-{system}-{machine}",
            "sing-box",
            f"sing-box-{system}-amd64",
            f"sing-box-{system}-arm64",
        ]
        
        for name in possible_names:
            path = os.path.join(bin_dir, name)
            if os.path.exists(path):
                return path
        
        global_path = shutil.which('sing-box')
        if global_path:
            return global_path
        
        return None

    def tcp_ping(self, host, port, timeout=3):
        try:
            with socket.create_connection((host, int(port)), timeout=timeout):
                return True
        except:
            return False

    def check_udp_support(self, listen_port, timeout=3):
        """
        检测SOCKS5代理是否支持UDP转发
        hysteria2/tuic必须支持UDP
        """
        try:
            import socks
            s = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
            s.set_proxy(socks.SOCKS5, '127.0.0.1', listen_port)
            s.settimeout(timeout)
            # 发送DNS查询测试UDP
            dns_query = b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01'
            s.sendto(dns_query, (UDP_TEST_HOST, UDP_TEST_PORT))
            data, addr = s.recvfrom(1024)
            s.close()
            return len(data) > 0
        except:
            return False

    def validate_nodes_parallel(self, nodes, timeout=5, max_workers=50):
        if not self.sing_box_path or not os.path.exists(self.sing_box_path):
            print(f"Warning: sing-box not available, skipping validation. All {len(nodes)} nodes will be kept.")
            return nodes
        
        valid_nodes = []
        print(f"Starting ULTRA strict validation for {len(nodes)} nodes with {max_workers} threads...")
        print(f"Validation criteria:")
        print(f"  1) IP must change (≠ {self.original_ip})")
        print(f"  2) Must access GFW-blocked sites (Google/YouTube/Twitter)")
        print(f"  3) hysteria2/tuic must support UDP")
        print(f"  4) Latency < 3000ms")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_node = {executor.submit(self.validate_node_ultra_strict, node, timeout): node for node in nodes}
            for i, future in enumerate(concurrent.futures.as_completed(future_to_node)):
                node = future_to_node[future]
                try:
                    if future.result():
                        valid_nodes.append(node)
                except Exception as exc:
                    pass
                if (i + 1) % 50 == 0:
                    print(f"Validated {i + 1}/{len(nodes)} nodes, {len(valid_nodes)} valid so far...")
        
        print(f"Validation complete: {len(valid_nodes)}/{len(nodes)} nodes passed ultra-strict checks")
        return valid_nodes

    def validate_node_ultra_strict(self, node, timeout=5):
        """
        超严格验证（梯子专用）：
        1. TCP 连通性
        2. 出口IP ≠ 原始IP
        3. 能访问被墙网站（Google/YouTube/Twitter至少一个）
        4. hysteria2/tuic 必须UDP通
        5. 延迟 < 3000ms
        """
        if not self.sing_box_path or not os.path.exists(self.sing_box_path):
            return True

        server = node.get('server')
        port = node.get('server_port') or node.get('port')
        node_type = node.get('type', '').lower()
        
        if server and port:
            if not self.tcp_ping(server, port, timeout=2):
                return False

        node_config = node.copy()
        keys_to_remove = [k for k in list(node_config.keys()) if k.startswith('_')]
        for k in keys_to_remove:
            del node_config[k]
        
        if "tag" not in node_config:
            node_config["tag"] = "proxy"

        listen_port = random.randint(10000, 60000)
        
        test_config = {
            "log": {
                "level": "fatal",
                "timestamp": True
            },
            "inbounds": [
                {
                    "type": "socks",
                    "tag": "socks-in",
                    "listen": "127.0.0.1",
                    "listen_port": listen_port
                }
            ],
            "outbounds": [
                node_config,
                {
                    "type": "direct",
                    "tag": "direct"
                }
            ],
            "route": {
                "rules": [
                    {
                        "inbound": "socks-in",
                        "outbound": node_config.get("tag", "proxy")
                    }
                ]
            }
        }
        
        proc = None
        tmp_config_path = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp_file:
                json.dump(test_config, tmp_file)
                tmp_config_path = tmp_file.name
            
            cmd = [self.sing_box_path, 'run', '-c', tmp_config_path]
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            
            time.sleep(1)
            
            if proc.poll() is not None:
                return False
            
            proxies = {
                'http': f'socks5://127.0.0.1:{listen_port}',
                'https': f'socks5://127.0.0.1:{listen_port}'
            }
            
            # === 验证 1: 出口IP必须变化 ===
            ip_changed = False
            for ip_url in IP_CHECK_URLS:
                try:
                    resp = requests.get(ip_url, proxies=proxies, timeout=timeout)
                    if resp.status_code == 200:
                        proxy_ip = resp.text.strip()
                        if proxy_ip and proxy_ip != self.original_ip:
                            ip_changed = True
                            break
                except:
                    continue
            
            if not ip_changed:
                return False
            
            # === 验证 2: 必须能访问被墙网站（梯子核心功能）===
            can_access_gfw = False
            latency_ok = False
            
            for gfw_url in TEST_URLS_GFW:
                try:
                    start = time.time()
                    resp = requests.get(gfw_url, proxies=proxies, timeout=timeout, allow_redirects=True)
                    latency = time.time() - start
                    
                    if resp.status_code in [200, 204, 301, 302]:
                        can_access_gfw = True
                        if latency < 3.0:  # 3秒延迟限制
                            latency_ok = True
                            break
                except:
                    continue
            
            if not can_access_gfw:
                return False
            
            if not latency_ok:
                return False
            
            # === 验证 3: UDP支持（hysteria2/tuic必须）===
            if node_type in ['hysteria2', 'hy2', 'tuic']:
                # 尝试安装PySocks进行UDP测试
                try:
                    import socks
                    udp_ok = self.check_udp_support(listen_port, timeout=3)
                    if not udp_ok:
                        return False
                except ImportError:
                    # 没有PySocks，跳过UDP测试但打警告
                    print(f"Warning: PySocks not installed, skipping UDP check for {node_type} node")
            
            return True
                
        except Exception as e:
            return False
        finally:
            if proc:
                try:
                    proc.terminate()
                    proc.wait(timeout=1)
                except:
                    proc.kill()
            
            if tmp_config_path and os.path.exists(tmp_config_path):
                try:
                    os.remove(tmp_config_path)
                except:
                    pass
