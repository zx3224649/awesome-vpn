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

# 国内网站用于验证（GitHub Actions在国外，直连这些应该很慢或不通）
TEST_URLS_CN = [
    'http://www.baidu.com',
    'http://www.163.com', 
    'http://www.qq.com',
]

# IP检测服务
IP_CHECK_URLS = [
    'http://ipinfo.io/ip',
    'http://api.ipify.org',
    'http://checkip.amazonaws.com',
]

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
        # 获取本机原始IP作为基准
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
        import socket
        try:
            with socket.create_connection((host, int(port)), timeout=timeout):
                return True
        except:
            return False

    def validate_nodes_parallel(self, nodes, timeout=5, max_workers=50):
        if not self.sing_box_path or not os.path.exists(self.sing_box_path):
            print(f"Warning: sing-box not available, skipping validation. All {len(nodes)} nodes will be kept.")
            return nodes
        
        valid_nodes = []
        print(f"Starting strict validation for {len(nodes)} nodes with {max_workers} threads...")
        print(f"Validation criteria: 1) IP must change 2) Must access CN websites")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_node = {executor.submit(self.validate_node_strict, node, timeout): node for node in nodes}
            for i, future in enumerate(concurrent.futures.as_completed(future_to_node)):
                node = future_to_node[future]
                try:
                    if future.result():
                        valid_nodes.append(node)
                except Exception as exc:
                    pass
                if (i + 1) % 50 == 0:
                    print(f"Validated {i + 1}/{len(nodes)} nodes, {len(valid_nodes)} valid so far...")
        
        print(f"Validation complete: {len(valid_nodes)}/{len(nodes)} nodes passed strict checks")
        return valid_nodes

    def validate_node_strict(self, node, timeout=5):
        """
        严格验证：
        1. 通过代理获取出口IP，必须与本机IP不同（确保流量走了代理）
        2. 通过代理访问国内网站，必须能通（确保可访问CN）
        """
        if not self.sing_box_path or not os.path.exists(self.sing_box_path):
            return True

        server = node.get('server')
        port = node.get('server_port') or node.get('port')
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
            
            # === 严格验证 1: 出口IP必须变化 ===
            ip_changed = False
            proxy_ip = None
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
                # IP没变，说明代理没生效或节点无效
                return False
            
            # === 严格验证 2: 必须能访问国内网站 ===
            can_access_cn = False
            for cn_url in TEST_URLS_CN:
                try:
                    resp = requests.get(cn_url, proxies=proxies, timeout=timeout, allow_redirects=True)
                    if resp.status_code == 200:
                        can_access_cn = True
                        break
                except:
                    continue
            
            if not can_access_cn:
                # 不能访问国内网站，对很多用户来说没用
                return False
            
            # 两个条件都满足才算有效
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
