#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UFW 防火墙日志分析程序
功能：
1. 读取 UFW 历史日志
2. 分析本地网络结构（自动检测网络接口、IP地址、网关等）
3. 统计进出记录（区分本地网络和互联网流量）
4. 识别网络攻击（标注攻击来源类型）
5. 识别系统漏洞
"""

import re
import os
import sys
import socket
import subprocess
import ipaddress
import gzip
import glob
import urllib.request
import urllib.error
import urllib.parse
import time
import hashlib
import logging
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Set, Any, TYPE_CHECKING
from functools import lru_cache
import json

# 类型检查导入（避免循环导入）
if TYPE_CHECKING:
    from type_definitions import (
        LogEntry, StatisticsSummary, TrafficByDirection,
        AttackResult, VulnerabilityResult, ProxyAnalysisResult,
        DeviceFingerprintResult, NetworkInfo
    )
else:
    # 运行时导入
    try:
        from type_definitions import (
            LogEntry, StatisticsSummary, TrafficByDirection,
            AttackResult, VulnerabilityResult, ProxyAnalysisResult,
            DeviceFingerprintResult, NetworkInfo
        )
    except ImportError:
        # 如果 type_definitions.py 不存在，使用通用类型
        LogEntry = Dict[str, Any]
        StatisticsSummary = Dict[str, Any]
        TrafficByDirection = Dict[str, Any]
        AttackResult = Dict[str, Any]
        VulnerabilityResult = Dict[str, Any]
        ProxyAnalysisResult = Dict[str, Any]
        DeviceFingerprintResult = Dict[str, Any]
        NetworkInfo = Dict[str, Any]

# 导入配置模块
try:
    from config import get_config, AppConfig
    _config_available = True
except ImportError:
    _config_available = False
    # 如果配置模块不可用，使用默认值
    class AppConfig:
        pass

# 导入工具函数（需要在初始化日志之前导入）
from ufw_analyzer.utils.logging_utils import setup_logging
from ufw_analyzer.utils.ip_utils import get_source_type_label

# 初始化日志记录器
logger = logging.getLogger('ufw_analyzer')
if not logger.handlers:
    # 如果没有配置，使用默认配置
    setup_logging()

# 导入已拆分的模块
from ufw_analyzer.analysis.attack_detector import AttackDetector, AdvancedAttackDetector
from ufw_analyzer.analysis.vulnerability import VulnerabilityScanner
from ufw_analyzer.core.network import NetworkAnalyzer
from ufw_analyzer.core.parser import UFWLogParser
from ufw_analyzer.analysis.statistics import UFWStatistics
from ufw_analyzer.analysis.proxy import ProxyAnalyzer
from ufw_analyzer.data.device_fingerprint import DeviceFingerprint
from ufw_analyzer.data.security_db import SecurityDatabaseManager
from ufw_analyzer.data.vulnerability_db import VulnerabilityDatabase


class NetworkAnalyzer:
    """网络结构分析器"""
    
    def __init__(self):
        self.local_networks: Set[ipaddress.IPv4Network] = set()
        self.local_interfaces: List[Dict] = []
        self.gateway_ip: Optional[str] = None
        self.host_ip: Optional[str] = None
        self.switch_ips: Set[str] = set()  # 交换机/网关IP地址集合
        
    def get_local_interfaces(self) -> List[Dict]:
        """获取本地网络接口信息"""
        interfaces = []
        
        try:
            # 获取所有网络接口
            import netifaces
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        ip = addr_info.get('addr')
                        netmask = addr_info.get('netmask')
                        if ip and netmask:
                            try:
                                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                                interfaces.append({
                                    'interface': interface,
                                    'ip': ip,
                                    'netmask': netmask,
                                    'network': str(network.network_address),
                                    'cidr': str(network)
                                })
                                self.local_networks.add(network)
                            except (ipaddress.AddressValueError, ValueError) as e:
                                # 记录无效的网络地址格式，但不中断处理
                                logger.debug(f"无效的网络地址格式: IP={ip}, 子网掩码={netmask}, 接口={interface}, 错误: {e}")
                                pass
        except ImportError:
            # 如果没有 netifaces，使用 ip 命令
            try:
                result = subprocess.run(['ip', 'addr', 'show'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    current_interface = None
                    for line in result.stdout.split('\n'):
                        # 匹配接口名
                        if_match = re.match(r'^\d+:\s+(\w+):', line)
                        if if_match:
                            current_interface = if_match.group(1)
                        
                        # 匹配 IP 地址和子网掩码
                        inet_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', line)
                        if inet_match and current_interface:
                            ip = inet_match.group(1)
                            prefix = int(inet_match.group(2))
                            try:
                                network = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
                                interfaces.append({
                                    'interface': current_interface,
                                    'ip': ip,
                                    'netmask': str(network.netmask),
                                    'network': str(network.network_address),
                                    'cidr': str(network)
                                })
                                self.local_networks.add(network)
                            except (ipaddress.AddressValueError, ValueError) as e:
                                # 记录无效的网络地址格式，但不中断处理
                                logger.debug(f"无效的网络地址格式: IP={ip}, 前缀={prefix}, 接口={current_interface}, 错误: {e}")
                                pass
            except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                logger.debug(f"ip 命令不可用或超时: {type(e).__name__}, 错误: {e}，尝试使用 ifconfig")
                # 如果 ip 命令不可用，尝试使用 ifconfig
                try:
                    result = subprocess.run(['ifconfig'], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        current_interface = None
                        for line in result.stdout.split('\n'):
                            # 匹配接口名
                            if_match = re.match(r'^(\w+):', line)
                            if if_match:
                                current_interface = if_match.group(1)
                            
                            # 匹配 IP 地址和子网掩码
                            inet_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(\d+\.\d+\.\d+\.\d+)', line)
                            if inet_match and current_interface:
                                ip = inet_match.group(1)
                                netmask = inet_match.group(2)
                                try:
                                    # 将点分十进制子网掩码转换为前缀长度
                                    prefix = sum(bin(int(x)).count('1') for x in netmask.split('.'))
                                    network = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
                                    interfaces.append({
                                        'interface': current_interface,
                                        'ip': ip,
                                        'netmask': netmask,
                                        'network': str(network.network_address),
                                        'cidr': str(network)
                                    })
                                    self.local_networks.add(network)
                                except (ipaddress.AddressValueError, ValueError) as e:
                                    # 记录无效的网络地址格式，但不中断处理
                                    logger.debug(f"无效的网络地址格式: IP={ip}, 子网掩码={netmask}, 接口={current_interface}, 错误: {e}")
                                    pass
                except (subprocess.SubprocessError, FileNotFoundError, OSError) as e:
                    # 记录 ifconfig 命令执行失败，但不中断处理
                    logger.debug(f"ifconfig 命令执行失败: {type(e).__name__}, 错误: {e}")
                    pass
        
        # 添加标准私有网络范围
        private_ranges = [
            ipaddress.IPv4Network('10.0.0.0/8'),
            ipaddress.IPv4Network('172.16.0.0/12'),
            ipaddress.IPv4Network('192.168.0.0/16'),
            ipaddress.IPv4Network('127.0.0.0/8'),  # 本地回环
        ]
        for network in private_ranges:
            self.local_networks.add(network)
        
        self.local_interfaces = interfaces
        
        # 获取主机IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            self.host_ip = s.getsockname()[0]
            s.close()
        except (socket.error, OSError) as e:
            # 记录 socket 连接失败（可能是网络不可用），但不中断处理
            logger.debug(f"无法获取主机IP（socket连接失败）: {type(e).__name__}, 错误: {e}")
            pass
        
        # 获取网关IP
        try:
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                match = re.search(r'via\s+(\d+\.\d+\.\d+\.\d+)', result.stdout)
                if match:
                    self.gateway_ip = match.group(1)
                    self.switch_ips.add(self.gateway_ip)
        except (subprocess.SubprocessError, FileNotFoundError, OSError) as e:
            # 记录路由查询失败，但不中断处理
            logger.debug(f"无法获取网关IP（路由查询失败）: {type(e).__name__}, 错误: {e}")
            pass
        
        # 识别常见的交换机/网关地址模式
        self._identify_switch_addresses()
        
        return interfaces
    
    def _identify_switch_addresses(self):
        """识别交换机/网关地址"""
        # 只对实际检测到的网络接口所在的子网识别交换机地址
        # 不对大的私有网络范围（10.0.0.0/8等）识别，这些只是用来判断IP类型的
        
        # 标准私有网络范围（用于排除）
        private_ranges = {
            ipaddress.IPv4Network('10.0.0.0/8'),
            ipaddress.IPv4Network('172.16.0.0/12'),
            ipaddress.IPv4Network('192.168.0.0/16'),
            ipaddress.IPv4Network('127.0.0.0/8'),
        }
        
        # 只对实际接口所在的子网识别交换机地址
        for network in self.local_networks:
            # 跳过大的私有网络范围
            if network in private_ranges:
                continue
            
            # 只对较小的子网（通常是/24或更小）识别交换机地址
            # 避免对大的网络范围误识别
            if network.prefixlen < 24:
                continue
            
            network_addr = network.network_address
            broadcast_addr = network.broadcast_address
            
            # 常见的网关地址模式：
            # 1. 网络地址 + 1 (如 192.168.1.1)
            # 2. 广播地址 - 1 (如 192.168.1.254)
            try:
                # 网络地址 + 1
                if network.num_addresses > 1:
                    first_host = ipaddress.IPv4Address(int(network_addr) + 1)
                    if first_host in network:
                        self.switch_ips.add(str(first_host))
                
                # 广播地址 - 1 (通常是 .254)
                if network.num_addresses > 1:
                    last_host = ipaddress.IPv4Address(int(broadcast_addr) - 1)
                    if last_host in network and last_host != first_host:
                        self.switch_ips.add(str(last_host))
            except (ipaddress.AddressValueError, ValueError, OverflowError) as e:
                # 记录无效的IP地址计算，但不中断处理
                logger.debug(f"无效的IP地址计算: 网络={network}, 错误: {e}")
                pass
        
        # 添加已知的网关IP
        if self.gateway_ip:
            self.switch_ips.add(self.gateway_ip)
    
    def is_local_ip(self, ip_str: Optional[str]) -> bool:
        """判断IP地址是否为本地网络"""
        if not ip_str:
            return False
        
        try:
            ip = ipaddress.IPv4Address(ip_str)
            
            # 检查是否在已知的本地网络中
            for network in self.local_networks:
                if ip in network:
                    return True
            
            # 检查是否为私有IP地址
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except (ipaddress.AddressValueError, ValueError) as e:
            # 记录IP地址解析失败，返回False
            logger.debug(f"本地IP地址解析失败: {ip_str}, 错误: {e}")
            return False
    
    def is_internet_ip(self, ip_str: Optional[str]) -> bool:
        """判断IP地址是否为互联网地址"""
        if not ip_str:
            return False
        return not self.is_local_ip(ip_str)
    
    def is_switch_ip(self, ip_str: Optional[str]) -> bool:
        """判断IP地址是否为交换机/网关地址"""
        if not ip_str:
            return False
        
        # 直接检查是否在已知的交换机IP列表中
        if ip_str in self.switch_ips:
            return True
        
        # 检查是否为网关IP
        if ip_str == self.gateway_ip:
            return True
        
        # 检查是否符合常见的网关地址模式（只对实际接口所在的子网）
        # 标准私有网络范围（用于排除）
        private_ranges = {
            ipaddress.IPv4Network('10.0.0.0/8'),
            ipaddress.IPv4Network('172.16.0.0/12'),
            ipaddress.IPv4Network('192.168.0.0/16'),
            ipaddress.IPv4Network('127.0.0.0/8'),
        }
        
        try:
            ip = ipaddress.IPv4Address(ip_str)
            
            # 对于每个本地网络，检查是否为网关地址
            for network in self.local_networks:
                # 跳过大的私有网络范围
                if network in private_ranges:
                    continue
                
                # 只对较小的子网（通常是/24或更小）检查
                if network.prefixlen < 24:
                    continue
                
                if ip in network:
                    network_addr = network.network_address
                    broadcast_addr = network.broadcast_address
                    
                    # 检查是否为网络地址 + 1 (如 192.168.1.1)
                    if network.num_addresses > 1:
                        first_host = ipaddress.IPv4Address(int(network_addr) + 1)
                        if ip == first_host:
                            self.switch_ips.add(ip_str)  # 缓存结果
                            return True
                    
                    # 检查是否为广播地址 - 1 (如 192.168.1.254)
                    if network.num_addresses > 1:
                        last_host = ipaddress.IPv4Address(int(broadcast_addr) - 1)
                        if ip == last_host:
                            self.switch_ips.add(ip_str)  # 缓存结果
                            return True
        except (ipaddress.AddressValueError, ValueError, OverflowError) as e:
            # 记录无效的IP地址计算，但不中断处理
            logger.debug(f"无效的IP地址计算: IP={ip_str}, 网络={network}, 错误: {e}")
            pass
        
        return False
    
    def get_ip_type(self, ip_str: Optional[str]) -> str:
        """获取IP地址类型：'switch'（交换机/网关）、'local'（本地网络）、'internet'（互联网）"""
        if not ip_str:
            return 'unknown'
        
        if self.is_switch_ip(ip_str):
            return 'switch'
        elif self.is_local_ip(ip_str):
            return 'local'
        else:
            return 'internet'
    
    def get_network_info(self) -> Dict:
        """获取网络信息摘要"""
        return {
            'host_ip': self.host_ip,
            'gateway_ip': self.gateway_ip,
            'switch_ips': sorted(list(self.switch_ips)),
            'local_interfaces': self.local_interfaces,
            'local_networks': [str(net) for net in sorted(self.local_networks, key=lambda x: x.network_address)],
            'total_local_networks': len(self.local_networks)
        }


class UFWLogParser:
    """UFW 日志解析器"""
    
    def __init__(self, log_path: str = "/var/log/ufw.log", read_archived: bool = True):
        self.log_path = log_path
        self.log_entries = []
        self.read_archived = read_archived  # 是否读取压缩的历史日志
        self.log_files_read = []  # 记录已读取的日志文件
        
    def find_log_files(self) -> List[str]:
        """查找所有相关的日志文件（包括压缩的历史日志）"""
        log_files = []
        log_dir = os.path.dirname(self.log_path)
        log_basename = os.path.basename(self.log_path)
        log_name_without_ext = os.path.splitext(log_basename)[0]
        
        # 1. 添加当前日志文件（如果存在）
        if os.path.exists(self.log_path):
            log_files.append(self.log_path)
        
        if not self.read_archived:
            return log_files
        
        # 2. 查找压缩的历史日志文件
        # 模式: ufw.log.1.gz, ufw.log.2.gz, 等
        pattern1 = os.path.join(log_dir, f"{log_name_without_ext}.*.gz")
        # 模式: ufw.log.1, ufw.log.2, 等（未压缩的旧日志）
        pattern2 = os.path.join(log_dir, f"{log_name_without_ext}.*")
        
        # 查找所有匹配的文件
        found_files = set()
        for pattern in [pattern1, pattern2]:
            for file_path in glob.glob(pattern):
                # 排除当前日志文件本身
                if file_path != self.log_path:
                    found_files.add(file_path)
        
        # 按文件名排序（数字越大越旧，但我们要从旧到新读取）
        sorted_files = sorted(found_files, key=lambda x: self._extract_log_number(x), reverse=True)
        log_files.extend(sorted_files)
        
        return log_files
    
    def _extract_log_number(self, file_path: str) -> int:
        """从日志文件名中提取数字（用于排序）"""
        # 例如: ufw.log.1.gz -> 1, ufw.log.2.gz -> 2
        basename = os.path.basename(file_path)
        match = re.search(r'\.(\d+)(?:\.gz)?$', basename)
        if match:
            return int(match.group(1))
        return 0
    
    def read_file(self, file_path: str) -> List['LogEntry']:
        """读取单个日志文件（支持压缩和未压缩）"""
        entries = []
        
        try:
            # 判断是否为压缩文件
            if file_path.endswith('.gz'):
                # 读取压缩文件
                with gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        entry = self.parse_log_line(line)
                        if entry:
                            entry['source_file'] = file_path  # 记录来源文件
                            entries.append(entry)
            else:
                # 读取普通文本文件
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        entry = self.parse_log_line(line)
                        if entry:
                            entry['source_file'] = file_path  # 记录来源文件
                            entries.append(entry)
        except PermissionError as e:
            logger.warning(f"没有权限读取日志文件: {file_path}", exc_info=True)
        except Exception as e:
            logger.error(f"读取日志文件时出错: {file_path}, 错误类型: {type(e).__name__}, 错误信息: {e}", exc_info=True)
        
        return entries
    
    def read_logs(self) -> List['LogEntry']:
        """读取并解析 UFW 日志文件（包括压缩的历史日志）"""
        # 查找所有日志文件
        log_files = self.find_log_files()
        
        if not log_files:
            logger.warning(f"未找到日志文件: {self.log_path} 及其历史文件")
            return []
        
        all_entries = []
        self.log_files_read = []
        
        print(f"找到 {len(log_files)} 个日志文件:")
        for log_file in log_files:
            file_type = "压缩" if log_file.endswith('.gz') else "普通"
            print(f"  读取 {file_type} 文件: {os.path.basename(log_file)}")
            
            entries = self.read_file(log_file)
            all_entries.extend(entries)
            self.log_files_read.append({
                'path': log_file,
                'entries': len(entries),
                'type': file_type
            })
            print(f"    已读取 {len(entries)} 条记录")
        
        self.log_entries = all_entries
        print(f"\n总计读取 {len(all_entries)} 条日志记录")
        return all_entries
    
    def parse_log_line(self, line: str) -> Optional['LogEntry']:
        """解析单行日志"""
        # UFW 日志格式示例:
        # Jan  1 12:00:00 hostname kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=192.168.1.100 DST=192.168.1.1 LEN=... PROTO=TCP SPT=12345 DPT=80
        
        # 匹配 UFW 日志条目
        ufw_pattern = r'\[UFW\s+(\w+)\]'
        match = re.search(ufw_pattern, line)
        if not match:
            return None
        
        action = match.group(1)  # BLOCK, ALLOW, DENY 等
        
        # 提取时间戳
        timestamp_match = re.match(r'(\w+\s+\d+\s+\d+:\d+:\d+)', line)
        timestamp = timestamp_match.group(1) if timestamp_match else None
        
        # 提取字段
        fields = {}
        field_patterns = {
            'IN': r'IN=(\S+)',
            'OUT': r'OUT=(\S+)',
            'SRC': r'SRC=([\d.]+)',
            'DST': r'DST=([\d.]+)',
            'PROTO': r'PROTO=(\w+)',
            'SPT': r'SPT=(\d+)',
            'DPT': r'DPT=(\d+)',
            'LEN': r'LEN=(\d+)',
            'MAC': r'MAC=([\S]+)',
        }
        
        for key, pattern in field_patterns.items():
            match = re.search(pattern, line)
            if match:
                fields[key] = match.group(1)
        
        # 识别服务类型
        service_type = None
        dns_type = None
        dst_port = fields.get('DPT')
        protocol = fields.get('PROTO', '').upper()
        
        if dst_port and dst_port.isdigit():
            try:
                port = int(dst_port)
                if port == 80:
                    service_type = 'HTTP'
                elif port == 443:
                    # 可能是HTTPS或DOH，需要进一步判断
                    service_type = 'HTTPS/DOH'
                    # DNS over HTTPS 通常通过443端口，但难以从日志直接识别
                    dns_type = 'Possible-DOH'
                elif port == 53:
                    service_type = 'DNS'
                    if protocol == 'UDP':
                        dns_type = 'DNS'
                    elif protocol == 'TCP':
                        dns_type = 'DNS-TCP'
                elif port == 853:
                    service_type = 'DOT'  # DNS over TLS
                    dns_type = 'DOT'  # DNS over TLS
            except (ValueError, TypeError):
                pass
        
        return {
            'timestamp': timestamp,
            'action': action,
            'interface_in': fields.get('IN'),
            'interface_out': fields.get('OUT'),
            'src_ip': fields.get('SRC'),
            'dst_ip': fields.get('DST'),
            'protocol': fields.get('PROTO'),
            'src_port': fields.get('SPT'),
            'dst_port': dst_port,
            'length': fields.get('LEN'),
            'mac': fields.get('MAC'),
            'service_type': service_type,  # HTTP/HTTPS/DNS等
            'dns_type': dns_type,  # DNS/DOT/DOH
            'raw_line': line.strip()
        }


class UFWStatistics:
    """UFW 统计模块"""
    
    def __init__(self, log_entries: List[Dict], network_analyzer: Optional[NetworkAnalyzer] = None):
        self.log_entries = log_entries
        self.network_analyzer = network_analyzer
    
    def get_summary(self) -> 'StatisticsSummary':
        """获取统计摘要"""
        total = len(self.log_entries)
        actions = Counter(entry['action'] for entry in self.log_entries)
        protocols = Counter(entry.get('protocol', 'UNKNOWN') for entry in self.log_entries)
        
        # 进出统计
        in_count = sum(1 for entry in self.log_entries if entry.get('interface_in'))
        out_count = sum(1 for entry in self.log_entries if entry.get('interface_out'))
        
        # IP 统计
        src_ips = Counter(entry.get('src_ip') for entry in self.log_entries if entry.get('src_ip'))
        dst_ips = Counter(entry.get('dst_ip') for entry in self.log_entries if entry.get('dst_ip'))
        
        # 端口统计
        dst_ports = Counter(entry.get('dst_port') for entry in self.log_entries if entry.get('dst_port'))
        
        # TCP/UDP 统计
        tcp_count = sum(1 for entry in self.log_entries if entry.get('protocol', '').upper() == 'TCP')
        udp_count = sum(1 for entry in self.log_entries if entry.get('protocol', '').upper() == 'UDP')
        
        # HTTP/HTTPS 统计
        http_count = sum(1 for entry in self.log_entries if entry.get('service_type') == 'HTTP')
        https_count = sum(1 for entry in self.log_entries if entry.get('service_type') in ['HTTPS/DOH', 'HTTPS'])
        
        # DNS/DOT/DOH 统计
        dns_count = sum(1 for entry in self.log_entries if entry.get('dns_type') in ['DNS', 'DNS-TCP'])
        dot_count = sum(1 for entry in self.log_entries if entry.get('dns_type') == 'DOT')
        doh_count = sum(1 for entry in self.log_entries if entry.get('dns_type') == 'Possible-DOH')
        
        # MAC 地址统计
        mac_addresses = Counter(entry.get('mac') for entry in self.log_entries if entry.get('mac'))
        entries_with_mac = sum(1 for entry in self.log_entries if entry.get('mac'))
        entries_with_ip = sum(1 for entry in self.log_entries if entry.get('src_ip') or entry.get('dst_ip'))
        
        result = {
            'total_entries': total,
            'actions': dict(actions),
            'protocols': dict(protocols),
            'inbound_count': in_count,
            'outbound_count': out_count,
            'top_source_ips': dict(src_ips.most_common(10)),
            'top_destination_ips': dict(dst_ips.most_common(10)),
            'top_destination_ports': dict(dst_ports.most_common(10)),
            # TCP/UDP 区分
            'tcp_udp': {
                'tcp_count': tcp_count,
                'udp_count': udp_count,
                'tcp_percentage': round(tcp_count / total * 100, 2) if total > 0 else 0,
                'udp_percentage': round(udp_count / total * 100, 2) if total > 0 else 0
            },
            # HTTP/HTTPS 区分
            'http_https': {
                'http_count': http_count,
                'https_count': https_count,
                'http_percentage': round(http_count / total * 100, 2) if total > 0 else 0,
                'https_percentage': round(https_count / total * 100, 2) if total > 0 else 0
            },
            # DNS/DOT/DOH 区分
            'dns_types': {
                'dns_count': dns_count,
                'dot_count': dot_count,
                'doh_count': doh_count,
                'total_dns': dns_count + dot_count + doh_count
            },
            # IP/MAC 区分
            'ip_mac': {
                'entries_with_ip': entries_with_ip,
                'entries_with_mac': entries_with_mac,
                'ip_percentage': round(entries_with_ip / total * 100, 2) if total > 0 else 0,
                'mac_percentage': round(entries_with_mac / total * 100, 2) if total > 0 else 0,
                'top_mac_addresses': dict(mac_addresses.most_common(10))
            }
        }
        
        # 如果启用了网络分析，添加交换机/本地网络/互联网区分统计
        if self.network_analyzer:
            switch_src_ips = Counter()
            local_src_ips = Counter()
            internet_src_ips = Counter()
            switch_dst_ips = Counter()
            local_dst_ips = Counter()
            internet_dst_ips = Counter()
            
            for entry in self.log_entries:
                src_ip = entry.get('src_ip')
                dst_ip = entry.get('dst_ip')
                
                if src_ip:
                    ip_type = self.network_analyzer.get_ip_type(src_ip)
                    if ip_type == 'switch':
                        switch_src_ips[src_ip] += 1
                    elif ip_type == 'local':
                        local_src_ips[src_ip] += 1
                    else:
                        internet_src_ips[src_ip] += 1
                
                if dst_ip:
                    ip_type = self.network_analyzer.get_ip_type(dst_ip)
                    if ip_type == 'switch':
                        switch_dst_ips[dst_ip] += 1
                    elif ip_type == 'local':
                        local_dst_ips[dst_ip] += 1
                    else:
                        internet_dst_ips[dst_ip] += 1
            
            result['ip_classification'] = {
                'switch_source_ips': len(switch_src_ips),
                'local_source_ips': len(local_src_ips),
                'internet_source_ips': len(internet_src_ips),
                'switch_destination_ips': len(switch_dst_ips),
                'local_destination_ips': len(local_dst_ips),
                'internet_destination_ips': len(internet_dst_ips),
                'top_switch_source_ips': dict(switch_src_ips.most_common(10)),
                'top_local_source_ips': dict(local_src_ips.most_common(10)),
                'top_internet_source_ips': dict(internet_src_ips.most_common(10)),
                'top_switch_destination_ips': dict(switch_dst_ips.most_common(10)),
                'top_local_destination_ips': dict(local_dst_ips.most_common(10)),
                'top_internet_destination_ips': dict(internet_dst_ips.most_common(10))
            }
            
            # 保持向后兼容
            result['local_vs_internet'] = {
                'local_source_ips': len(local_src_ips) + len(switch_src_ips),
                'internet_source_ips': len(internet_src_ips),
                'local_destination_ips': len(local_dst_ips) + len(switch_dst_ips),
                'internet_destination_ips': len(internet_dst_ips),
                'top_local_source_ips': dict((local_src_ips + switch_src_ips).most_common(10)),
                'top_internet_source_ips': dict(internet_src_ips.most_common(10)),
                'top_local_destination_ips': dict((local_dst_ips + switch_dst_ips).most_common(10)),
                'top_internet_destination_ips': dict(internet_dst_ips.most_common(10))
            }
        
        return result
    
    def get_traffic_by_direction(self) -> Dict:
        """按方向统计流量"""
        inbound = []
        outbound = []
        
        for entry in self.log_entries:
            if entry.get('interface_in') and not entry.get('interface_out'):
                inbound.append(entry)
            elif entry.get('interface_out'):
                outbound.append(entry)
        
        result = {
            'inbound': {
                'count': len(inbound),
                'blocked': sum(1 for e in inbound if e['action'] in ['BLOCK', 'DENY']),
                'allowed': sum(1 for e in inbound if e['action'] == 'ALLOW')
            },
            'outbound': {
                'count': len(outbound),
                'blocked': sum(1 for e in outbound if e['action'] in ['BLOCK', 'DENY']),
                'allowed': sum(1 for e in outbound if e['action'] == 'ALLOW')
            }
        }
        
        # 如果启用了网络分析，添加交换机/本地网络/互联网流量区分
        if self.network_analyzer:
            inbound_switch = []
            inbound_local = []
            inbound_internet = []
            outbound_switch = []
            outbound_local = []
            outbound_internet = []
            
            for entry in inbound:
                src_ip = entry.get('src_ip')
                if src_ip:
                    ip_type = self.network_analyzer.get_ip_type(src_ip)
                    if ip_type == 'switch':
                        inbound_switch.append(entry)
                    elif ip_type == 'local':
                        inbound_local.append(entry)
                    else:
                        inbound_internet.append(entry)
            
            for entry in outbound:
                dst_ip = entry.get('dst_ip')
                if dst_ip:
                    ip_type = self.network_analyzer.get_ip_type(dst_ip)
                    if ip_type == 'switch':
                        outbound_switch.append(entry)
                    elif ip_type == 'local':
                        outbound_local.append(entry)
                    else:
                        outbound_internet.append(entry)
            
            result['inbound_switch'] = {
                'count': len(inbound_switch),
                'blocked': sum(1 for e in inbound_switch if e['action'] in ['BLOCK', 'DENY']),
                'allowed': sum(1 for e in inbound_switch if e['action'] == 'ALLOW')
            }
            result['inbound_local'] = {
                'count': len(inbound_local),
                'blocked': sum(1 for e in inbound_local if e['action'] in ['BLOCK', 'DENY']),
                'allowed': sum(1 for e in inbound_local if e['action'] == 'ALLOW')
            }
            result['inbound_internet'] = {
                'count': len(inbound_internet),
                'blocked': sum(1 for e in inbound_internet if e['action'] in ['BLOCK', 'DENY']),
                'allowed': sum(1 for e in inbound_internet if e['action'] == 'ALLOW')
            }
            result['outbound_switch'] = {
                'count': len(outbound_switch),
                'blocked': sum(1 for e in outbound_switch if e['action'] in ['BLOCK', 'DENY']),
                'allowed': sum(1 for e in outbound_switch if e['action'] == 'ALLOW')
            }
            result['outbound_local'] = {
                'count': len(outbound_local),
                'blocked': sum(1 for e in outbound_local if e['action'] in ['BLOCK', 'DENY']),
                'allowed': sum(1 for e in outbound_local if e['action'] == 'ALLOW')
            }
            result['outbound_internet'] = {
                'count': len(outbound_internet),
                'blocked': sum(1 for e in outbound_internet if e['action'] in ['BLOCK', 'DENY']),
                'allowed': sum(1 for e in outbound_internet if e['action'] == 'ALLOW')
            }
        
        return result


class ProxyAnalyzer:
    """代理服务分析器（针对特殊代理IP）"""
    
    # 代理IP地址（198.18.0.0/15 是RFC 2544测试网络，常用于代理服务）
    PROXY_IP = '198.18.0.2'
    PROXY_NETWORK = ipaddress.IPv4Network('198.18.0.0/15')
    
    # 代理类型端口映射
    PROXY_PORTS = {
        # HTTP代理
        'http_proxy': {
            'ports': [8080, 3128, 8888, 8000, 8880, 8118, 8123, 9999],
            'description': 'HTTP代理服务'
        },
        # SOCKS代理
        'socks_proxy': {
            'ports': [1080, 1081, 1082, 1083, 1084, 1085, 9050, 9051],
            'description': 'SOCKS代理服务（SOCKS4/SOCKS5）'
        },
        # Trojan代理
        'trojan_proxy': {
            'ports': [443, 8443, 4433, 4443, 9443],
            'description': 'Trojan代理服务（基于TLS）'
        },
        # DNS代理
        'dns_proxy': {
            'ports': [53, 5353, 853],
            'description': 'DNS代理服务（DNS over UDP/TCP/TLS）'
        },
        # 其他常见代理端口
        'other_proxy': {
            'ports': [7890, 7891, 10808, 10809, 10810, 10811],
            'description': '其他代理服务'
        },
        # Clash/Mihomo 代理端口（动态端口范围）
        'clash_proxy': {
            'ports': [10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007, 10008, 10009, 
                      10010, 10011, 10012, 10013, 10014, 10015, 10016, 10017, 10018, 10019],
            'description': 'Clash/Mihomo 代理服务（动态端口）'
        }
    }
    
    def __init__(self):
        self.proxy_entries: List[Dict] = []
        self.proxy_stats: Dict = defaultdict(lambda: {
            'count': 0,
            'ports': Counter(),
            'protocols': Counter(),
            'actions': Counter(),
            'directions': Counter(),
            'target_ips': set(),
            'target_ports': set()
        })
    
    def analyze_proxy_traffic(self, log_entries: List[Dict]) -> Dict:
        """分析代理流量"""
        proxy_entries = []
        
        for entry in log_entries:
            src_ip = entry.get('src_ip')
            dst_ip = entry.get('dst_ip')
            
            # 检查是否为代理IP相关的流量
            is_proxy_related = False
            proxy_role = None  # 'source' 或 'destination'
            
            if src_ip == self.PROXY_IP:
                is_proxy_related = True
                proxy_role = 'source'
            elif dst_ip == self.PROXY_IP:
                is_proxy_related = True
                proxy_role = 'destination'
            elif src_ip and self._is_proxy_network(src_ip):
                is_proxy_related = True
                proxy_role = 'source'
            elif dst_ip and self._is_proxy_network(dst_ip):
                is_proxy_related = True
                proxy_role = 'destination'
            
            if is_proxy_related:
                entry_copy = entry.copy()
                entry_copy['proxy_role'] = proxy_role
                entry_copy['proxy_ip'] = src_ip if proxy_role == 'source' else dst_ip
                proxy_entries.append(entry_copy)
        
        self.proxy_entries = proxy_entries
        
        # 分析代理类型
        proxy_type_analysis = self._analyze_proxy_types(proxy_entries)
        
        # 统计代理流量
        proxy_traffic_stats = self._analyze_proxy_traffic(proxy_entries)
        
        return {
            'proxy_ip': self.PROXY_IP,
            'total_entries': len(proxy_entries),
            'proxy_types': proxy_type_analysis,
            'traffic_stats': proxy_traffic_stats,
            'detailed_analysis': self._get_detailed_analysis(proxy_entries)
        }
    
    def _is_proxy_network(self, ip_str: str) -> bool:
        """检查IP是否属于代理网络范围"""
        try:
            ip = ipaddress.IPv4Address(ip_str)
            return ip in self.PROXY_NETWORK
        except (ipaddress.AddressValueError, ValueError) as e:
            # IP地址解析失败，返回False
            return False
    
    def _analyze_proxy_types(self, proxy_entries: List[Dict]) -> Dict:
        """分析代理类型分布"""
        type_stats = {
            'http_proxy': {'count': 0, 'ports': set(), 'entries': []},
            'socks_proxy': {'count': 0, 'ports': set(), 'entries': []},
            'trojan_proxy': {'count': 0, 'ports': set(), 'entries': []},
            'dns_proxy': {'count': 0, 'ports': set(), 'entries': []},
            'other_proxy': {'count': 0, 'ports': set(), 'entries': []},
            'clash_proxy': {'count': 0, 'ports': set(), 'entries': []},
            'unknown': {'count': 0, 'ports': set(), 'entries': []}
        }
        
        for entry in proxy_entries:
            dst_port = entry.get('dst_port')
            src_port = entry.get('src_port')
            protocol = entry.get('protocol', '').upper()
            
            # 确定使用的端口（根据代理角色）
            proxy_role = entry.get('proxy_role')
            if proxy_role == 'source':
                # 代理作为源，使用源端口
                port = src_port
            else:
                # 代理作为目标，使用目标端口
                port = dst_port
            
            if not port:
                type_stats['unknown']['count'] += 1
                type_stats['unknown']['entries'].append(entry)
                continue
            
            try:
                port_num = int(port)
                proxy_type = None
                
                # 根据端口识别代理类型
                if port_num in self.PROXY_PORTS['clash_proxy']['ports']:
                    proxy_type = 'clash_proxy'
                elif port_num in self.PROXY_PORTS['http_proxy']['ports']:
                    proxy_type = 'http_proxy'
                elif port_num in self.PROXY_PORTS['socks_proxy']['ports']:
                    proxy_type = 'socks_proxy'
                elif port_num in self.PROXY_PORTS['trojan_proxy']['ports']:
                    # Trojan通常使用TLS，检查协议
                    if protocol == 'TCP':
                        proxy_type = 'trojan_proxy'
                    else:
                        proxy_type = 'other_proxy'
                elif port_num in self.PROXY_PORTS['dns_proxy']['ports']:
                    proxy_type = 'dns_proxy'
                elif port_num in self.PROXY_PORTS['other_proxy']['ports']:
                    proxy_type = 'other_proxy'
                else:
                    # 根据协议和端口模式推断
                    if port_num == 53 and protocol in ['UDP', 'TCP']:
                        proxy_type = 'dns_proxy'
                    elif port_num == 443 and protocol == 'TCP':
                        proxy_type = 'trojan_proxy'
                    elif port_num in [8080, 3128, 8888] and protocol == 'TCP':
                        proxy_type = 'http_proxy'
                    elif port_num in [1080, 1081] and protocol == 'TCP':
                        proxy_type = 'socks_proxy'
                    else:
                        proxy_type = 'unknown'
                
                # 安全检查：确保代理类型在 type_stats 中存在
                if proxy_type not in type_stats:
                    logger.warning(f"未知的代理类型: {proxy_type}，归类为 unknown")
                    proxy_type = 'unknown'
                
                type_stats[proxy_type]['count'] += 1
                type_stats[proxy_type]['ports'].add(port_num)
                type_stats[proxy_type]['entries'].append(entry)
                
            except (ValueError, TypeError) as e:
                logger.debug(f"端口转换失败: dst_port={dst_port}, src_port={src_port}, 错误: {e}")
                type_stats['unknown']['count'] += 1
                type_stats['unknown']['entries'].append(entry)
        
        # 转换为可序列化格式
        result = {}
        for proxy_type, stats in type_stats.items():
            result[proxy_type] = {
                'count': stats['count'],
                'ports': sorted(list(stats['ports'])),
                'description': self.PROXY_PORTS.get(proxy_type, {}).get('description', '未知代理类型'),
                'percentage': round(stats['count'] / len(proxy_entries) * 100, 2) if proxy_entries else 0
            }
        
        return result
    
    def _analyze_proxy_traffic(self, proxy_entries: List[Dict]) -> Dict:
        """分析代理流量统计"""
        stats = {
            'inbound': {'count': 0, 'allowed': 0, 'blocked': 0},
            'outbound': {'count': 0, 'allowed': 0, 'blocked': 0},
            'protocols': Counter(),
            'actions': Counter(),
            'top_source_ips': Counter(),
            'top_destination_ips': Counter(),
            'top_ports': Counter(),
            'time_distribution': defaultdict(int)
        }
        
        for entry in proxy_entries:
            action = entry.get('action')
            protocol = entry.get('protocol', 'UNKNOWN')
            src_ip = entry.get('src_ip')
            dst_ip = entry.get('dst_ip')
            dst_port = entry.get('dst_port')
            src_port = entry.get('src_port')
            proxy_role = entry.get('proxy_role')
            timestamp = entry.get('timestamp')
            
            # 统计协议
            stats['protocols'][protocol] += 1
            
            # 统计操作
            stats['actions'][action] += 1
            
            # 统计端口
            if dst_port:
                stats['top_ports'][dst_port] += 1
            if src_port:
                stats['top_ports'][src_port] += 1
            
            # 根据代理角色统计方向
            if proxy_role == 'source':
                # 代理作为源，这是出站流量
                stats['outbound']['count'] += 1
                if action == 'ALLOW':
                    stats['outbound']['allowed'] += 1
                elif action in ['BLOCK', 'DENY']:
                    stats['outbound']['blocked'] += 1
                
                if dst_ip:
                    stats['top_destination_ips'][dst_ip] += 1
            else:
                # 代理作为目标，这是入站流量
                stats['inbound']['count'] += 1
                if action == 'ALLOW':
                    stats['inbound']['allowed'] += 1
                elif action in ['BLOCK', 'DENY']:
                    stats['inbound']['blocked'] += 1
                
                if src_ip:
                    stats['top_source_ips'][src_ip] += 1
            
            # 时间分布（简化版，只统计有时间戳的）
            if timestamp:
                # 提取日期部分（简化处理）
                try:
                    date_part = timestamp.split()[0] if ' ' in timestamp else timestamp[:10]
                    stats['time_distribution'][date_part] += 1
                except (AttributeError, IndexError, KeyError) as e:
                    # 记录时间戳解析错误，但不中断处理
                    logger.debug(f"时间戳解析错误: timestamp={timestamp}, 错误: {e}")
                    pass
        
        # 转换为可序列化格式
        return {
            'inbound': stats['inbound'],
            'outbound': stats['outbound'],
            'protocols': dict(stats['protocols']),
            'actions': dict(stats['actions']),
            'top_source_ips': dict(stats['top_source_ips'].most_common(10)),
            'top_destination_ips': dict(stats['top_destination_ips'].most_common(10)),
            'top_ports': dict(stats['top_ports'].most_common(10)),
            'time_distribution': dict(stats['time_distribution'])
        }
    
    def _get_detailed_analysis(self, proxy_entries: List[Dict]) -> Dict:
        """获取详细分析"""
        # 分析代理使用模式
        usage_patterns = {
            'http_patterns': [],
            'socks_patterns': [],
            'trojan_patterns': [],
            'dns_patterns': []
        }
        
        # 按代理类型分组分析
        for entry in proxy_entries:
            dst_port = entry.get('dst_port')
            src_port = entry.get('src_port')
            protocol = entry.get('protocol', '').upper()
            proxy_role = entry.get('proxy_role')
            
            port = src_port if proxy_role == 'source' else dst_port
            
            if not port:
                continue
            
            try:
                port_num = int(port)
                
                # HTTP代理模式
                if port_num in self.PROXY_PORTS['http_proxy']['ports']:
                    usage_patterns['http_patterns'].append({
                        'port': port_num,
                        'protocol': protocol,
                        'action': entry.get('action'),
                        'role': proxy_role
                    })
                
                # SOCKS代理模式
                elif port_num in self.PROXY_PORTS['socks_proxy']['ports']:
                    usage_patterns['socks_patterns'].append({
                        'port': port_num,
                        'protocol': protocol,
                        'action': entry.get('action'),
                        'role': proxy_role
                    })
                
                # Trojan代理模式
                elif port_num in self.PROXY_PORTS['trojan_proxy']['ports'] and protocol == 'TCP':
                    usage_patterns['trojan_patterns'].append({
                        'port': port_num,
                        'protocol': protocol,
                        'action': entry.get('action'),
                        'role': proxy_role
                    })
                
                # DNS代理模式
                elif port_num in self.PROXY_PORTS['dns_proxy']['ports']:
                    usage_patterns['dns_patterns'].append({
                        'port': port_num,
                        'protocol': protocol,
                        'action': entry.get('action'),
                        'role': proxy_role
                    })
            except (ValueError, TypeError):
                pass
        
        # 统计每种模式的使用频率
        pattern_stats = {}
        for pattern_type, patterns in usage_patterns.items():
            if patterns:
                port_counter = Counter(p['port'] for p in patterns)
                protocol_counter = Counter(p['protocol'] for p in patterns)
                action_counter = Counter(p['action'] for p in patterns)
                
                pattern_stats[pattern_type] = {
                    'total_usage': len(patterns),
                    'unique_ports': len(port_counter),
                    'top_ports': dict(port_counter.most_common(5)),
                    'protocols': dict(protocol_counter),
                    'actions': dict(action_counter)
                }
        
        return {
            'usage_patterns': pattern_stats,
            'proxy_network_range': str(self.PROXY_NETWORK),
            'detected_proxy_ips': self._get_detected_proxy_ips(proxy_entries)
        }
    
    def _get_detected_proxy_ips(self, proxy_entries: List[Dict]) -> List[str]:
        """获取检测到的代理IP列表"""
        proxy_ips = set()
        for entry in proxy_entries:
            proxy_ip = entry.get('proxy_ip')
            if proxy_ip:
                proxy_ips.add(proxy_ip)
        return sorted(list(proxy_ips))
    
    def detect_proxy_attacks(self, proxy_entries: List[Dict]) -> List[Dict]:
        """检测代理相关的攻击模式"""
        attacks = []
        
        # 统计每个源IP对代理的使用
        ip_proxy_usage = defaultdict(lambda: {
            'count': 0,
            'proxy_types': set(),
            'ports': set(),
            'blocked_count': 0
        })
        
        for entry in proxy_entries:
            src_ip = entry.get('src_ip')
            dst_ip = entry.get('dst_ip')
            proxy_role = entry.get('proxy_role')
            action = entry.get('action')
            dst_port = entry.get('dst_port')
            src_port = entry.get('src_port')
            
            # 确定客户端IP（非代理IP）
            client_ip = None
            if proxy_role == 'source':
                client_ip = dst_ip  # 代理作为源，客户端是目标
            else:
                client_ip = src_ip  # 代理作为目标，客户端是源
            
            if client_ip and client_ip != self.PROXY_IP:
                ip_proxy_usage[client_ip]['count'] += 1
                if action in ['BLOCK', 'DENY']:
                    ip_proxy_usage[client_ip]['blocked_count'] += 1
                
                # 识别代理类型
                port = src_port if proxy_role == 'source' else dst_port
                if port:
                    try:
                        port_num = int(port)
                        if port_num in self.PROXY_PORTS['clash_proxy']['ports']:
                            ip_proxy_usage[client_ip]['proxy_types'].add('Clash/Mihomo')
                        elif port_num in self.PROXY_PORTS['http_proxy']['ports']:
                            ip_proxy_usage[client_ip]['proxy_types'].add('HTTP')
                        elif port_num in self.PROXY_PORTS['socks_proxy']['ports']:
                            ip_proxy_usage[client_ip]['proxy_types'].add('SOCKS')
                        elif port_num in self.PROXY_PORTS['trojan_proxy']['ports']:
                            ip_proxy_usage[client_ip]['proxy_types'].add('Trojan')
                        elif port_num in self.PROXY_PORTS['dns_proxy']['ports']:
                            ip_proxy_usage[client_ip]['proxy_types'].add('DNS')
                        
                        ip_proxy_usage[client_ip]['ports'].add(port_num)
                    except (ValueError, TypeError):
                        pass
        
        # 检测异常代理使用
        for client_ip, usage in ip_proxy_usage.items():
            # 检测大量被阻止的代理连接
            if usage['blocked_count'] > 50:
                attacks.append({
                    'type': '代理连接被大量阻止',
                    'client_ip': client_ip,
                    'proxy_ip': self.PROXY_IP,
                    'blocked_count': usage['blocked_count'],
                    'total_attempts': usage['count'],
                    'proxy_types': list(usage['proxy_types']),
                    'ports_used': sorted(list(usage['ports'])),
                    'severity': 'high' if usage['blocked_count'] > 100 else 'medium',
                    'description': f'客户端 {client_ip} 对代理 {self.PROXY_IP} 的 {usage["blocked_count"]} 次连接被阻止'
                })
            
            # 检测多种代理类型的使用（可能是代理滥用）
            if len(usage['proxy_types']) >= 3:
                attacks.append({
                    'type': '可疑的多代理类型使用',
                    'client_ip': client_ip,
                    'proxy_ip': self.PROXY_IP,
                    'proxy_types': list(usage['proxy_types']),
                    'ports_used': sorted(list(usage['ports'])),
                    'total_usage': usage['count'],
                    'severity': 'medium',
                    'description': f'客户端 {client_ip} 使用了多种代理类型: {", ".join(usage["proxy_types"])}'
                })
        
        return attacks


class DeviceFingerprint:
    """设备指纹识别器（基于IP和MAC地址）"""
    
    def __init__(self, network_analyzer: Optional[NetworkAnalyzer] = None):
        self.network_analyzer = network_analyzer
        # IP-MAC 关联映射
        self.ip_mac_map: Dict[str, Set[str]] = defaultdict(set)  # IP -> MAC集合
        self.mac_ip_map: Dict[str, Set[str]] = defaultdict(set)  # MAC -> IP集合
        self.device_fingerprints: Dict[str, Dict] = {}  # 设备指纹
        self._device_type_cache: Dict[str, str] = {}  # MAC -> 设备类型缓存
    
    def analyze_log_entries(self, log_entries: List[Dict]):
        """分析日志条目，建立IP-MAC关联"""
        for entry in log_entries:
            src_ip = entry.get('src_ip')
            mac = entry.get('mac')
            
            if src_ip and mac:
                # 清理MAC地址格式（可能包含多个MAC，取第一个）
                mac_clean = self._clean_mac(mac)
                if mac_clean:
                    self.ip_mac_map[src_ip].add(mac_clean)
                    self.mac_ip_map[mac_clean].add(src_ip)
    
    def _clean_mac(self, mac_str: str) -> Optional[str]:
        """清理MAC地址格式"""
        if not mac_str:
            return None
        
        # MAC地址可能包含多个，格式如 "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55" 或 "aa:bb:cc:dd:ee:ff"
        # 提取第一个有效的MAC地址（6组十六进制数）
        mac_pattern = r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}'
        match = re.search(mac_pattern, mac_str)
        if match:
            return match.group(0).replace('-', ':').lower()
        return None
    
    def get_device_fingerprint(self, ip: str, mac: Optional[str] = None) -> Dict:
        """
        获取设备指纹（带缓存）
        
        Args:
            ip: IP地址
            mac: MAC地址，可选
            
        Returns:
            Dict: 设备指纹信息
        """
        fingerprint_key = f"{ip}_{mac}" if mac else ip
        
        # 使用手动缓存（因为实例方法不能直接使用 @lru_cache）
        if fingerprint_key not in self.device_fingerprints:
            # 获取IP类型
            ip_type = 'unknown'
            if self.network_analyzer:
                ip_type = self.network_analyzer.get_ip_type(ip)
            
            # 获取关联的MAC地址
            associated_macs = list(self.ip_mac_map.get(ip, set()))
            
            # 获取MAC地址关联的IP
            associated_ips = []
            if mac:
                mac_clean = self._clean_mac(mac)
                if mac_clean:
                    associated_ips = list(self.mac_ip_map.get(mac_clean, set()))
            
            # 识别设备类型（基于MAC地址OUI）
            device_type = self._identify_device_type(mac if mac else (associated_macs[0] if associated_macs else None))
            
            self.device_fingerprints[fingerprint_key] = {
                'ip': ip,
                'mac': mac,
                'ip_type': ip_type,
                'associated_macs': associated_macs,
                'associated_ips': associated_ips,
                'device_type': device_type,
                'fingerprint_id': fingerprint_key
            }
        
        return self.device_fingerprints[fingerprint_key]
    
    def _identify_device_type(self, mac: Optional[str]) -> str:
        """基于MAC地址OUI识别设备类型"""
        if not mac:
            return '未知'
        
        mac_clean = self._clean_mac(mac)
        if not mac_clean:
            return '未知'
        
        # 提取OUI（前3个字节）
        oui = ':'.join(mac_clean.split(':')[:3]).upper()
        
        # 常见OUI数据库（简化版，包含最常见厂商）
        oui_database = {
            # 虚拟化
            '00:50:56': 'VMware', '00:0C:29': 'VMware', '00:05:69': 'VMware',
            '08:00:27': 'VirtualBox', '52:54:00': 'QEMU/KVM',
            # 网络设备
            '00:1B:44': 'Cisco', '00:1E:13': 'Cisco', '00:23:04': 'Cisco', '00:50:F2': 'Cisco',
            # 芯片厂商
            '00:26:CA': 'Intel', '00:1E:67': 'Intel', '00:21:70': 'Intel',
            '00:1D:7D': 'Realtek', '00:1B:21': 'Broadcom',
            '00:1F:3A': 'Qualcomm', '00:1E:67': 'Marvell',
            # 消费电子
            '00:25:00': 'Apple', '00:23:DF': 'Apple', '00:26:4A': 'Apple',
            '00:1D:7D': 'Samsung', '00:16:6F': 'Samsung',
            '00:1E:58': 'Huawei', '00:1F:3C': 'Huawei',
            '00:1B:21': 'Xiaomi', '00:1D:7D': 'OnePlus',
            '00:1B:21': 'Oppo', '00:1D:7D': 'Vivo',
            # PC厂商
            '00:1B:21': 'Dell', '00:1D:7D': 'HP', '00:1B:21': 'Lenovo',
            '00:1D:7D': 'ASUS', '00:1B:21': 'Acer',
            # 其他
            '00:1D:7D': 'Microsoft', '00:1B:21': 'Google',
            '00:1B:21': 'Raspberry Pi',
        }
        
        device_type = oui_database.get(oui, '未知设备')
        # 缓存结果（限制缓存大小）
        if len(self._device_type_cache) < 1000:
            self._device_type_cache[mac_clean] = device_type
        return device_type
    
    def get_device_summary(self) -> Dict:
        """获取设备指纹摘要"""
        return {
            'total_devices': len(self.device_fingerprints),
            'ip_mac_pairs': len(self.ip_mac_map),
            'mac_ip_pairs': len(self.mac_ip_map),
            'devices': list(self.device_fingerprints.values())
        }


# AdvancedAttackDetector 和 AttackDetector 已移至 ufw_analyzer/analysis/attack_detector.py
# 以下代码已删除，请从模块导入：
# from ufw_analyzer.analysis.attack_detector import AttackDetector, AdvancedAttackDetector

# 导入流程管理器
from ufw_analyzer.pipeline import AnalysisPipeline


class UFWAnalyzer:
    """
    UFW 分析器主类（轻量级协调器）
    
    重构为轻量级协调器，使用 AnalysisPipeline 管理整个分析流程。
    实现统一数据流和单次遍历优化。
    """
    
    def __init__(self, log_path: str = "/var/log/ufw.log", 
                 enable_network_analysis: bool = True, 
                 read_archived: bool = True,
                 enable_online_db: bool = True):
        """
        初始化 UFW 分析器
        
        Args:
            log_path: 日志文件路径
            enable_network_analysis: 是否启用网络分析
            read_archived: 是否读取压缩的历史日志
            enable_online_db: 是否启用在线漏洞数据库
        """
        # 使用流程管理器
        self.pipeline = AnalysisPipeline(
            log_path=log_path,
            enable_network_analysis=enable_network_analysis,
            read_archived=read_archived,
            enable_online_db=enable_online_db
        )
        
        # 保持向后兼容的属性
        self.parser = self.pipeline.parser
        self.log_entries = []
        self.statistics = None
        self.attack_detector = None
        self.vulnerability_scanner = None
        self.network_analyzer = None
        self.proxy_analyzer = None
        self.enable_network_analysis = enable_network_analysis
        
        # 分析结果
        self._results: Optional[Dict[str, Any]] = None
    
    def analyze(self):
        """执行完整分析（使用流程管理器）"""
        # 使用流程管理器执行分析
        self._results = self.pipeline.run()
        
        # 更新兼容性属性
        self.log_entries = self.pipeline.log_entries
        self.network_analyzer = self.pipeline.network_analyzer
        self.statistics = self.pipeline.statistics
        self.attack_detector = self.pipeline.attack_detector
        self.vulnerability_scanner = self.pipeline.vulnerability_scanner
        self.proxy_analyzer = self.pipeline.proxy_analyzer
        
        # 输出结果（保持原有接口）
        if self._results:
            summary = self._results.get('summary', {})
            traffic = self._results.get('traffic', {})
            attacks = self._results.get('attacks', [])
            vulnerabilities = self._results.get('vulnerabilities', [])
            proxy_analysis = self._results.get('proxy_analysis')
            proxy_attacks = self._results.get('proxy_attacks')
            
            # 调试信息：检查 summary 是否为空
            if not summary:
                print(f"\n[调试] summary 为空，检查 statistics 对象...")
                print(f"  - self.statistics 存在: {self.statistics is not None}")
                print(f"  - log_entries 数量: {len(self.log_entries) if self.log_entries else 0}")
                if self.statistics:
                    print(f"  - 尝试重新获取 summary...")
                    summary = self.statistics.get_summary()
                    print(f"  - 重新获取后 summary 是否为空: {not summary}")
                    if summary:
                        print(f"  - summary 键: {list(summary.keys())}")
            
            self.print_results(summary, traffic, attacks, vulnerabilities, proxy_analysis, proxy_attacks)
        else:
            print("错误: 分析流程未返回结果")
    
    def print_results(self, summary: Dict, traffic: Dict, attacks: List[Dict], vulnerabilities: List[Dict], 
                     proxy_analysis: Optional[Dict] = None, proxy_attacks: Optional[List[Dict]] = None):
        """打印分析结果（增强版，包含代理分析）"""
        # 网络结构信息
        if self.network_analyzer:
            print("\n" + "=" * 60)
            print("本地网络结构")
            print("=" * 60)
            network_info = self.network_analyzer.get_network_info()
            if network_info.get('host_ip'):
                print(f"主机 IP: {network_info['host_ip']}")
            if network_info.get('gateway_ip'):
                print(f"网关 IP: {network_info['gateway_ip']}")
            if network_info.get('switch_ips'):
                print(f"交换机/网关 IP 列表:")
                for switch_ip in network_info['switch_ips']:
                    print(f"  {switch_ip}")
            if network_info.get('interfaces'):
                print(f"\n本地网络接口:")
                for iface in network_info['interfaces']:
                    print(f"  {iface['interface']}: {iface['ip']} ({iface['cidr']})")
            if network_info.get('local_networks'):
                print(f"\n本地网络范围:")
                for net in network_info['local_networks'][:10]:  # 显示前10个
                    print(f"  {net}")
                if len(network_info['local_networks']) > 10:
                    print(f"  ... 共 {len(network_info['local_networks'])} 个网络范围")
        
        # 统计摘要
        print("\n" + "=" * 60)
        print("统计摘要")
        print("=" * 60)
        
        # 如果 summary 为空，尝试从 statistics 对象重新获取
        if not summary:
            if self.statistics:
                print(f"[调试] summary 为空，尝试从 statistics 对象重新获取...")
                print(f"  - statistics.log_entries 数量: {len(self.statistics.log_entries) if hasattr(self.statistics, 'log_entries') else 'N/A'}")
                try:
                    summary = self.statistics.get_summary()
                    print(f"  - 重新获取后 summary: {summary is not None}, 键: {list(summary.keys()) if summary else []}")
                except Exception as e:
                    print(f"  - 获取 summary 时出错: {e}")
                    import traceback
                    traceback.print_exc()
            else:
                print(f"[调试] summary 为空，且 statistics 对象不存在")
                print(f"  - self.statistics: {self.statistics}")
                print(f"  - log_entries 数量: {len(self.log_entries) if self.log_entries else 0}")
                # 尝试直接创建 statistics 对象
                if self.log_entries:
                    print(f"  - 尝试创建新的 statistics 对象...")
                    try:
                        from ufw_analyzer.analysis.statistics import UFWStatistics
                        self.statistics = UFWStatistics(self.log_entries, self.network_analyzer)
                        summary = self.statistics.get_summary()
                        print(f"  - 创建后 summary: {summary is not None}, 键: {list(summary.keys()) if summary else []}")
                    except Exception as e:
                        print(f"  - 创建 statistics 对象时出错: {e}")
                        import traceback
                        traceback.print_exc()
        
        if not summary:
            print("无统计信息")
            if self.log_entries:
                print(f"警告: 有 {len(self.log_entries)} 条日志记录，但统计信息为空")
            return
        
        total_entries = summary.get('total_entries', 0)
        if total_entries == 0:
            print("警告: 总日志条目数为 0")
        print(f"总日志条目数: {total_entries}")
        
        actions = summary.get('actions', {})
        if actions:
            print(f"\n操作统计:")
            for action, count in actions.items():
                print(f"  {action}: {count}")
        
        protocols = summary.get('protocols', {})
        if protocols:
            print(f"\n协议统计:")
            for protocol, count in protocols.items():
                print(f"  {protocol}: {count}")
        
        # TCP/UDP 区分
        if 'tcp_udp' in summary:
            tcp_udp = summary['tcp_udp']
            print(f"\nTCP/UDP 协议统计:")
            print(f"  TCP: {tcp_udp['tcp_count']} ({tcp_udp['tcp_percentage']}%)")
            print(f"  UDP: {tcp_udp['udp_count']} ({tcp_udp['udp_percentage']}%)")
        
        # HTTP/HTTPS 区分
        if 'http_https' in summary:
            http_https = summary['http_https']
            print(f"\nHTTP/HTTPS 服务统计:")
            print(f"  HTTP: {http_https['http_count']} ({http_https['http_percentage']}%)")
            print(f"  HTTPS/DOH: {http_https['https_count']} ({http_https['https_percentage']}%)")
        
        # DNS/DOT/DOH 区分
        if 'dns_types' in summary:
            dns_types = summary['dns_types']
            if dns_types['total_dns'] > 0:
                print(f"\nDNS 服务统计:")
                print(f"  DNS (标准): {dns_types['dns_count']}")
                print(f"  DOT (DNS over TLS): {dns_types['dot_count']}")
                print(f"  DOH (DNS over HTTPS): {dns_types['doh_count']}")
                print(f"  总计: {dns_types['total_dns']}")
        
        # IP/MAC 区分
        if 'ip_mac' in summary:
            ip_mac = summary['ip_mac']
            print(f"\nIP/MAC 地址统计:")
            print(f"  包含 IP 地址的记录: {ip_mac['entries_with_ip']} ({ip_mac['ip_percentage']}%)")
            print(f"  包含 MAC 地址的记录: {ip_mac['entries_with_mac']} ({ip_mac['mac_percentage']}%)")
            if ip_mac['top_mac_addresses']:
                print(f"\nTop 5 MAC 地址:")
                for mac, count in list(ip_mac['top_mac_addresses'].items())[:5]:
                    print(f"  {mac}: {count}")
        
        # 流量方向统计
        # 如果 traffic 为空，尝试从 statistics 对象重新获取
        if not traffic and self.statistics:
            traffic = self.statistics.get_traffic_by_direction()
        
        if traffic:
            print(f"\n流量方向统计:")
            inbound = traffic.get('inbound', {})
            outbound = traffic.get('outbound', {})
            print(f"  入站: {inbound.get('count', 0)} (允许: {inbound.get('allowed', 0)}, 阻止: {inbound.get('blocked', 0)})")
            print(f"  出站: {outbound.get('count', 0)} (允许: {outbound.get('allowed', 0)}, 阻止: {outbound.get('blocked', 0)})")
        else:
            print("\n流量方向统计: 无数据")
        
        # 交换机/本地网络/互联网流量区分
        if self.network_analyzer and 'ip_classification' in summary:
            print(f"\nIP 地址分类统计:")
            ip_class = summary['ip_classification']
            print(f"  交换机/网关源 IP 数: {ip_class['switch_source_ips']}")
            print(f"  本地网络源 IP 数: {ip_class['local_source_ips']}")
            print(f"  互联网源 IP 数: {ip_class['internet_source_ips']}")
            print(f"  交换机/网关目标 IP 数: {ip_class['switch_destination_ips']}")
            print(f"  本地网络目标 IP 数: {ip_class['local_destination_ips']}")
            print(f"  互联网目标 IP 数: {ip_class['internet_destination_ips']}")
            
            inbound_switch = traffic.get('inbound_switch')
            inbound_local = traffic.get('inbound_local')
            inbound_internet = traffic.get('inbound_internet')
            if inbound_switch or inbound_local or inbound_internet:
                print(f"\n入站流量分类:")
                if inbound_switch:
                    print(f"  来自交换机/网关: {inbound_switch.get('count', 0)} (允许: {inbound_switch.get('allowed', 0)}, 阻止: {inbound_switch.get('blocked', 0)})")
                if inbound_local:
                    print(f"  来自本地网络: {inbound_local.get('count', 0)} (允许: {inbound_local.get('allowed', 0)}, 阻止: {inbound_local.get('blocked', 0)})")
                if inbound_internet:
                    print(f"  来自互联网: {inbound_internet.get('count', 0)} (允许: {inbound_internet.get('allowed', 0)}, 阻止: {inbound_internet.get('blocked', 0)})")
            
            outbound_switch = traffic.get('outbound_switch')
            outbound_local = traffic.get('outbound_local')
            outbound_internet = traffic.get('outbound_internet')
            if outbound_switch or outbound_local or outbound_internet:
                print(f"\n出站流量分类:")
                if outbound_switch:
                    print(f"  前往交换机/网关: {outbound_switch.get('count', 0)} (允许: {outbound_switch.get('allowed', 0)}, 阻止: {outbound_switch.get('blocked', 0)})")
                if outbound_local:
                    print(f"  前往本地网络: {outbound_local.get('count', 0)} (允许: {outbound_local.get('allowed', 0)}, 阻止: {outbound_local.get('blocked', 0)})")
                if outbound_internet:
                    print(f"  前往互联网: {outbound_internet.get('count', 0)} (允许: {outbound_internet.get('allowed', 0)}, 阻止: {outbound_internet.get('blocked', 0)})")
            
            top_switch_source_ips = ip_class.get('top_switch_source_ips', {})
            if top_switch_source_ips:
                print(f"\nTop 5 交换机/网关源 IP:")
                for ip, count in list(top_switch_source_ips.items())[:5]:
                    print(f"  {ip}: {count}")
            
            top_local_source_ips = ip_class.get('top_local_source_ips', {})
            if top_local_source_ips:
                print(f"\nTop 5 本地网络源 IP:")
                for ip, count in list(top_local_source_ips.items())[:5]:
                    print(f"  {ip}: {count}")
            
            top_internet_source_ips = ip_class.get('top_internet_source_ips', {})
            if top_internet_source_ips:
                print(f"\nTop 5 互联网源 IP:")
                for ip, count in list(top_internet_source_ips.items())[:5]:
                    print(f"  {ip}: {count}")
        
        top_source_ips = summary.get('top_source_ips', {})
        if top_source_ips:
            print(f"\nTop 10 源 IP:")
            for ip, count in list(top_source_ips.items())[:10]:
                type_label = get_source_type_label(ip, self.network_analyzer)
                print(f"  {ip} ({type_label}): {count}")
        
        top_destination_ports = summary.get('top_destination_ports', {})
        if top_destination_ports:
            print(f"\nTop 10 目标端口:")
            for port, count in list(top_destination_ports.items())[:10]:
                print(f"  {port}: {count}")
        
        # 攻击检测结果
        print("\n" + "=" * 60)
        print("网络攻击检测结果")
        print("=" * 60)
        if attacks:
            # 按来源类型分类
            switch_attacks = [a for a in attacks if a.get('source_type') == '交换机/网关']
            local_attacks = [a for a in attacks if a.get('source_type') == '本地网络']
            internet_attacks = [a for a in attacks if a.get('source_type') == '互联网']
            
            # 按攻击类型分类
            injection_attacks = [a for a in attacks if '注入' in a.get('type', '')]
            mitm_attacks = [a for a in attacks if '中间人' in a.get('type', '')]
            scan_attacks = [a for a in attacks if '扫描' in a.get('type', '')]
            brute_force_attacks = [a for a in attacks if '暴力破解' in a.get('type', '')]
            spoofing_attacks = [a for a in attacks if '欺骗' in a.get('type', '') or '伪装' in a.get('type', '')]
            dos_attacks = [a for a in attacks if 'DoS' in a.get('type', '') or '拒绝服务' in a.get('type', '')]
            other_attacks = [a for a in attacks if a not in injection_attacks + mitm_attacks + scan_attacks + brute_force_attacks + spoofing_attacks + dos_attacks]
            
            print(f"检测到 {len(attacks)} 个潜在攻击:")
            print(f"\n攻击类型分布:")
            if injection_attacks:
                sql_injections = [a for a in injection_attacks if 'SQL注入' in a.get('type', '')]
                other_injections = [a for a in injection_attacks if 'SQL注入' not in a.get('type', '')]
                print(f"  注入攻击: {len(injection_attacks)} 个")
                if sql_injections:
                    print(f"    - SQL注入: {len(sql_injections)} 个 (严重威胁)")
                    # 显示SQL注入统计信息
                    if sql_injections and 'sql_statistics' in sql_injections[0]:
                        sql_stats = sql_injections[0]['sql_statistics']
                        print(f"\n  SQL注入详细统计:")
                        print(f"    总攻击次数: {sql_stats['total_attacks']}")
                        print(f"    唯一攻击源IP: {sql_stats['unique_source_ips']}")
                        print(f"    目标端口数: {sql_stats['unique_target_ports']}")
                        if sql_stats['by_type']:
                            print(f"    按类型分布:")
                            for sql_type, count in sql_stats['by_type'].items():
                                print(f"      - {sql_type}: {count} 次")
                        if sql_stats['by_severity']:
                            print(f"    按严重程度分布:")
                            for severity, count in sql_stats['by_severity'].items():
                                severity_cn = {'critical': '严重', 'high': '高', 'medium': '中等', 'low': '低'}.get(severity, severity)
                                print(f"      - {severity_cn}: {count} 次")
                        if sql_stats['top_attackers']:
                            print(f"    Top 5 攻击源:")
                            for attacker in sql_stats['top_attackers']:
                                print(f"      - {attacker['ip']}: {attacker['count']} 次")
                        if sql_stats['top_targets']:
                            print(f"    Top 5 目标端口:")
                            for target in sql_stats['top_targets']:
                                print(f"      - 端口 {target['port']}: {target['count']} 次")
                if other_injections:
                    print(f"    - 其他注入攻击: {len(other_injections)} 个")
            if mitm_attacks:
                print(f"  中间人攻击: {len(mitm_attacks)} 个")
            if scan_attacks:
                print(f"  漏洞扫描: {len(scan_attacks)} 个")
            if brute_force_attacks:
                print(f"  暴力破解: {len(brute_force_attacks)} 个")
            if spoofing_attacks:
                print(f"  伪装攻击: {len(spoofing_attacks)} 个")
            if dos_attacks:
                print(f"  拒绝服务攻击: {len(dos_attacks)} 个")
            if other_attacks:
                print(f"  其他攻击: {len(other_attacks)} 个")
            
            print(f"\n来源类型分布:")
            if switch_attacks:
                print(f"  来自交换机/网关: {len(switch_attacks)} 个")
            if local_attacks:
                print(f"  来自本地网络: {len(local_attacks)} 个")
            if internet_attacks:
                print(f"  来自互联网: {len(internet_attacks)} 个")
            
            for i, attack in enumerate(attacks, 1):
                print(f"\n[{i}] {attack['type']}")
                if 'source_ip' in attack and attack['source_ip']:
                    print(f"    源 IP: {attack['source_ip']}")
                if 'spoofed_ip' in attack:
                    print(f"    被欺骗的IP: {attack['spoofed_ip']}")
                if 'spoofed_mac' in attack:
                    print(f"    被欺骗的MAC: {attack['spoofed_mac']}")
                if 'source_mac' in attack and attack['source_mac']:
                    print(f"    源 MAC: {attack['source_mac']}")
                if 'device_type' in attack and attack['device_type']:
                    print(f"    设备类型: {attack['device_type']}")
                if 'source_type' in attack:
                    print(f"    来源类型: {attack['source_type']}")
                if 'target_port' in attack:
                    print(f"    目标端口: {attack['target_port']} ({attack.get('service', '')})")
                if 'target_service' in attack:
                    print(f"    目标服务: {attack['target_service']}")
                if 'ports_scanned' in attack:
                    print(f"    扫描端口数: {attack['ports_scanned']}")
                if 'sql_injection_type' in attack:
                    print(f"    SQL注入类型: {attack['sql_injection_type']}")
                if 'matched_text' in attack and attack['matched_text']:
                    print(f"    匹配的文本: {attack['matched_text'][:100]}...")
                if 'pattern_matched' in attack:
                    pattern_str = attack['pattern_matched']
                    if isinstance(pattern_str, str) and len(pattern_str) > 100:
                        print(f"    匹配的模式: {pattern_str[:100]}...")
                    else:
                        print(f"    匹配的模式: {pattern_str}")
                if 'raw_line_sample' in attack:
                    print(f"    日志样本: {attack['raw_line_sample']}")
                if 'recommendation' in attack:
                    print(f"    修复建议: {attack['recommendation']}")
                if 'attempts' in attack:
                    print(f"    尝试次数: {attack['attempts']}")
                if 'failed_attempts' in attack:
                    print(f"    失败尝试次数: {attack['failed_attempts']}")
                if 'blocked_attempts' in attack:
                    print(f"    被阻止次数: {attack['blocked_attempts']}")
                if 'blocked_ratio' in attack:
                    print(f"    阻止率: {attack['blocked_ratio']}%")
                if 'target_ports_count' in attack:
                    print(f"    目标端口数: {attack['target_ports_count']}")
                if 'target_ips_count' in attack:
                    print(f"    目标IP数: {attack['target_ips_count']}")
                if 'associated_macs' in attack:
                    print(f"    关联的MAC地址: {', '.join(attack['associated_macs'][:5])}")
                    if len(attack['associated_macs']) > 5:
                        print(f"    ... 共 {len(attack['associated_macs'])} 个MAC地址")
                if 'associated_ips' in attack:
                    print(f"    关联的IP地址: {', '.join(attack['associated_ips'][:5])}")
                    if len(attack['associated_ips']) > 5:
                        print(f"    ... 共 {len(attack['associated_ips'])} 个IP地址")
                if 'mac_count' in attack:
                    print(f"    MAC地址数量: {attack['mac_count']}")
                if 'ip_count' in attack:
                    print(f"    IP地址数量: {attack['ip_count']}")
                if 'dns_queries' in attack:
                    print(f"    DNS查询次数: {attack['dns_queries']}")
                if 'blocked_queries' in attack:
                    print(f"    被阻止的DNS查询: {attack['blocked_queries']}")
                if 'unique_dns_servers' in attack:
                    print(f"    唯一DNS服务器数: {attack['unique_dns_servers']}")
                if 'https_attempts' in attack:
                    print(f"    HTTPS尝试次数: {attack['https_attempts']}")
                if 'http_attempts' in attack:
                    print(f"    HTTP尝试次数: {attack['http_attempts']}")
                if 'failed_ssl' in attack:
                    print(f"    SSL失败次数: {attack['failed_ssl']}")
                if 'enumeration_attempts' in attack:
                    print(f"    枚举尝试次数: {attack['enumeration_attempts']}")
                if 'unique_attackers' in attack:
                    print(f"    唯一攻击者数: {attack['unique_attackers']}")
                if 'attacker_ips' in attack:
                    print(f"    攻击者IP列表: {', '.join(attack['attacker_ips'][:10])}")
                    if len(attack['attacker_ips']) > 10:
                        print(f"    ... 共 {len(attack['attacker_ips'])} 个攻击者IP")
                if 'unique_spoofed_ips' in attack:
                    print(f"    被欺骗的IP数量: {attack['unique_spoofed_ips']}")
                if 'total_attempts' in attack:
                    print(f"    总尝试次数: {attack['total_attempts']}")
                if 'sample_ips' in attack:
                    print(f"    样本IP: {', '.join(attack['sample_ips'][:10])}")
                if 'avg_packet_length' in attack:
                    print(f"    平均数据包长度: {attack['avg_packet_length']}")
                if 'std_deviation' in attack:
                    print(f"    标准差: {attack['std_deviation']}")
                if 'is_ip_spoofing' in attack and attack['is_ip_spoofing']:
                    print(f"    ⚠️  IP欺骗警告: {attack.get('warning', '')}")
                if 'unique_macs' in attack:
                    print(f"    关联MAC地址数: {attack['unique_macs']}")
                if 'recommendation' in attack:
                    print(f"    建议: {attack['recommendation']}")
                if 'warning' in attack and attack['warning']:
                    print(f"    ⚠️  警告: {attack['warning']}")
                print(f"    严重程度: {attack['severity']}")
        else:
            print("未检测到明显的网络攻击")
        
        # 漏洞扫描结果
        print("\n" + "=" * 60)
        print("系统漏洞扫描结果（增强分析）")
        print("=" * 60)
        if vulnerabilities:
            # 按严重程度分类
            critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'critical']
            high_vulns = [v for v in vulnerabilities if v.get('severity') == 'high']
            medium_vulns = [v for v in vulnerabilities if v.get('severity') == 'medium']
            low_vulns = [v for v in vulnerabilities if v.get('severity') == 'low']
            
            # 按类型分类
            port_vulns = [v for v in vulnerabilities if v.get('type') == '开放危险端口']
            auth_vulns = [v for v in vulnerabilities if '认证风险' in v.get('type', '')]
            protocol_vulns = [v for v in vulnerabilities if v.get('type') in ['不安全协议', '未加密通信']]
            attack_vulns = [v for v in vulnerabilities if '攻击' in v.get('type', '')]
            exposed_vulns = [v for v in vulnerabilities if '暴露' in v.get('type', '')]
            
            print(f"检测到 {len(vulnerabilities)} 个潜在漏洞:")
            print(f"  严重 (Critical): {len(critical_vulns)} 个")
            print(f"  高 (High): {len(high_vulns)} 个")
            print(f"  中 (Medium): {len(medium_vulns)} 个")
            print(f"  低 (Low): {len(low_vulns)} 个")
            print(f"\n漏洞类型分布:")
            print(f"  开放危险端口: {len(port_vulns)} 个")
            print(f"  认证风险: {len(auth_vulns)} 个")
            print(f"  不安全协议: {len(protocol_vulns)} 个")
            print(f"  攻击模式: {len(attack_vulns)} 个")
            print(f"  互联网暴露服务: {len(exposed_vulns)} 个")
            
            for i, vuln in enumerate(vulnerabilities, 1):
                print(f"\n[{i}] {vuln['type']}")
                if 'port' in vuln:
                    print(f"    端口: {vuln['port']}")
                if 'service' in vuln:
                    print(f"    服务: {vuln['service']}")
                if 'source_ip' in vuln:
                    print(f"    源 IP: {vuln['source_ip']} ({vuln.get('source_type', '未知')})")
                print(f"    描述: {vuln['description']}")
                print(f"    严重程度: {vuln.get('severity', 'unknown').upper()}")
                
                # 显示CVE信息（增强版，包含在线数据库信息）
                if 'common_cves' in vuln and vuln['common_cves']:
                    cve_list = ', '.join(vuln['common_cves'][:5])  # 显示前5个
                    print(f"    相关CVE: {cve_list}")
                
                # 显示增强的CVE信息（从在线数据库获取）
                if 'enhanced_cves' in vuln and vuln['enhanced_cves']:
                    print(f"    增强CVE信息（来自权威数据库）:")
                    for enhanced_cve in vuln['enhanced_cves'][:3]:  # 显示前3个
                        cve_id = enhanced_cve.get('cve_id', '')
                        sources = ', '.join(enhanced_cve.get('sources', []))
                        cvss = enhanced_cve.get('cvss_score')
                        severity = enhanced_cve.get('severity')
                        
                        info_parts = [f"{cve_id}"]
                        if sources:
                            info_parts.append(f"来源: {sources}")
                        if cvss:
                            info_parts.append(f"CVSS: {cvss}")
                        if severity:
                            info_parts.append(f"严重程度: {severity}")
                        
                        print(f"      - {' | '.join(info_parts)}")
                        
                        # 显示相关URL
                        urls = enhanced_cve.get('urls', [])
                        if urls:
                            for url in urls[:2]:  # 显示前2个URL
                                print(f"        链接: {url}")
                
                # 显示攻击模式
                if 'attack_patterns' in vuln and vuln['attack_patterns']:
                    patterns = ', '.join(vuln['attack_patterns'][:5])
                    print(f"    攻击模式: {patterns}")
                
                # 显示统计信息
                if 'access_count' in vuln:
                    print(f"    访问次数: {vuln['access_count']}")
                if 'unique_sources' in vuln:
                    print(f"    唯一来源: {vuln['unique_sources']}")
                if 'total_failures' in vuln:
                    print(f"    总失败次数: {vuln['total_failures']}")
                if 'unique_attackers' in vuln:
                    print(f"    攻击者数量: {vuln['unique_attackers']}")
                
                if 'recommendation' in vuln:
                    print(f"    建议: {vuln['recommendation']}")
        else:
            print("未检测到明显的系统漏洞")
        
        # 代理服务分析结果
        if proxy_analysis and proxy_analysis.get('total_entries', 0) > 0:
            print("\n" + "=" * 60)
            print("代理服务分析结果（198.18.0.2）")
            print("=" * 60)
            print(f"检测到代理IP: {proxy_analysis['proxy_ip']}")
            print(f"代理相关流量总数: {proxy_analysis['total_entries']}")
            
            # 代理类型分布
            if proxy_analysis.get('proxy_types'):
                print(f"\n代理类型分布:")
                proxy_types = proxy_analysis['proxy_types']
                for proxy_type, stats in proxy_types.items():
                    if stats['count'] > 0:
                        print(f"  {stats['description']}: {stats['count']} ({stats['percentage']}%)")
                        if stats['ports']:
                            print(f"    使用端口: {', '.join(map(str, stats['ports'][:10]))}")
                
                # 统计主要代理类型
                http_count = proxy_types.get('http_proxy', {}).get('count', 0)
                socks_count = proxy_types.get('socks_proxy', {}).get('count', 0)
                trojan_count = proxy_types.get('trojan_proxy', {}).get('count', 0)
                dns_count = proxy_types.get('dns_proxy', {}).get('count', 0)
                other_count = proxy_types.get('other_proxy', {}).get('count', 0)
                
                print(f"\n代理类型汇总:")
                print(f"  HTTP代理: {http_count} 条")
                print(f"  SOCKS代理: {socks_count} 条")
                print(f"  Trojan代理: {trojan_count} 条")
                print(f"  DNS代理: {dns_count} 条")
                print(f"  其他代理: {other_count} 条")
            
            # 流量统计
            if proxy_analysis.get('traffic_stats'):
                traffic_stats = proxy_analysis['traffic_stats']
                print(f"\n代理流量统计:")
                print(f"  入站: {traffic_stats['inbound']['count']} (允许: {traffic_stats['inbound']['allowed']}, 阻止: {traffic_stats['inbound']['blocked']})")
                print(f"  出站: {traffic_stats['outbound']['count']} (允许: {traffic_stats['outbound']['allowed']}, 阻止: {traffic_stats['outbound']['blocked']})")
                
                if traffic_stats.get('protocols'):
                    print(f"\n协议分布:")
                    for protocol, count in traffic_stats['protocols'].items():
                        print(f"  {protocol}: {count}")
                
                if traffic_stats.get('top_ports'):
                    print(f"\nTop 5 代理端口:")
                    for port, count in list(traffic_stats['top_ports'].items())[:5]:
                        print(f"  {port}: {count}")
                
                if traffic_stats.get('top_source_ips'):
                    print(f"\nTop 5 代理客户端IP:")
                    for ip, count in list(traffic_stats['top_source_ips'].items())[:5]:
                        print(f"  {ip}: {count}")
            
            # 详细分析
            if proxy_analysis.get('detailed_analysis'):
                detailed = proxy_analysis['detailed_analysis']
                if detailed.get('usage_patterns'):
                    print(f"\n代理使用模式:")
                    for pattern_type, pattern_stats in detailed['usage_patterns'].items():
                        pattern_name = {
                            'http_patterns': 'HTTP代理',
                            'socks_patterns': 'SOCKS代理',
                            'trojan_patterns': 'Trojan代理',
                            'dns_patterns': 'DNS代理'
                        }.get(pattern_type, pattern_type)
                        print(f"  {pattern_name}:")
                        print(f"    使用次数: {pattern_stats['total_usage']}")
                        print(f"    使用端口数: {pattern_stats['unique_ports']}")
                        if pattern_stats.get('top_ports'):
                            ports_str = ', '.join(f"{p}({c})" for p, c in list(pattern_stats['top_ports'].items())[:5])
                            print(f"    主要端口: {ports_str}")
                        if pattern_stats.get('protocols'):
                            protocols_str = ', '.join(f"{p}({c})" for p, c in pattern_stats['protocols'].items())
                            print(f"    协议: {protocols_str}")
            
            # 检测到的代理IP
            if detailed.get('detected_proxy_ips'):
                print(f"\n检测到的代理IP地址:")
                for proxy_ip in detailed['detected_proxy_ips']:
                    print(f"  {proxy_ip}")
        
        # 代理相关攻击
        if proxy_attacks:
            print("\n" + "=" * 60)
            print("代理相关安全事件")
            print("=" * 60)
            print(f"检测到 {len(proxy_attacks)} 个代理相关安全事件:")
            for i, attack in enumerate(proxy_attacks, 1):
                print(f"\n[{i}] {attack['type']}")
                if 'client_ip' in attack:
                    print(f"    客户端IP: {attack['client_ip']}")
                if 'proxy_ip' in attack:
                    print(f"    代理IP: {attack['proxy_ip']}")
                if 'proxy_types' in attack:
                    print(f"    代理类型: {', '.join(attack['proxy_types'])}")
                if 'ports_used' in attack:
                    print(f"    使用端口: {', '.join(map(str, attack['ports_used'][:10]))}")
                if 'blocked_count' in attack:
                    print(f"    被阻止次数: {attack['blocked_count']}")
                if 'total_attempts' in attack:
                    print(f"    总尝试次数: {attack['total_attempts']}")
                print(f"    描述: {attack.get('description', '')}")
                print(f"    严重程度: {attack.get('severity', 'unknown')}")
        
        print("\n" + "=" * 60)
        print("分析完成")
        print("=" * 60)
    
    def export_json(self, output_file: str = "ufw_analysis.json"):
        """导出分析结果为 JSON"""
        if not self.log_entries:
            print("请先运行 analyze() 方法")
            return
        
        summary = self.statistics.get_summary()
        traffic = self.statistics.get_traffic_by_direction()
        attacks = self.attack_detector.detect_all_attacks()
        vulnerabilities = self.vulnerability_scanner.scan_all_vulnerabilities()
        
        result = {
            'analysis_time': datetime.now().isoformat(),
            'total_log_entries': len(self.log_entries),
            'statistics': summary,
            'traffic': traffic,
            'attacks': attacks,
            'vulnerabilities': vulnerabilities
        }
        
        # 添加网络结构信息
        if self.network_analyzer:
            result['network_info'] = self.network_analyzer.get_network_info()
        
        # 添加代理分析信息
        if self.proxy_analyzer:
            proxy_analysis = self.proxy_analyzer.analyze_proxy_traffic(self.log_entries)
            proxy_attacks = self.proxy_analyzer.detect_proxy_attacks(self.proxy_analyzer.proxy_entries)
            result['proxy_analysis'] = proxy_analysis
            result['proxy_attacks'] = proxy_attacks
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        
        print(f"分析结果已导出到: {output_file}")


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='UFW 防火墙日志分析程序')
    parser.add_argument('-l', '--log', default='/var/log/ufw.log',
                       help='UFW 日志文件路径 (默认: /var/log/ufw.log)')
    parser.add_argument('-o', '--output', default=None,
                       help='导出 JSON 结果到指定文件')
    parser.add_argument('-j', '--json-only', action='store_true',
                       help='仅导出 JSON，不显示详细输出')
    parser.add_argument('--no-network-analysis', action='store_true',
                       help='禁用本地网络结构分析')
    parser.add_argument('--no-archived', action='store_true',
                       help='不读取压缩的历史日志文件，仅读取当前日志')
    
    args = parser.parse_args()
    
    analyzer = UFWAnalyzer(args.log, 
                          enable_network_analysis=not args.no_network_analysis,
                          read_archived=not args.no_archived)
    
    if args.json_only:
        analyzer.analyze()
        output_file = args.output or "ufw_analysis.json"
        analyzer.export_json(output_file)
    else:
        analyzer.analyze()
        if args.output:
            analyzer.export_json(args.output)


if __name__ == '__main__':
    main()

