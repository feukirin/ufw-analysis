#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
统一日志处理器 - 单次遍历优化
实现单次遍历完成所有分析，大幅提升性能
"""

from typing import Dict, List, Any, Optional
from collections import defaultdict, Counter
import logging

logger = logging.getLogger('ufw_analyzer')


class UnifiedLogProcessor:
    """
    统一日志处理器
    
    单次遍历日志，同时完成所有分析任务，大幅提升性能。
    替代原来的多次遍历方式。
    """
    
    def __init__(self, log_entries: List[Dict], network_analyzer=None):
        """
        初始化统一日志处理器
        
        Args:
            log_entries: 日志条目列表
            network_analyzer: 网络分析器实例
        """
        self.log_entries = log_entries
        self.network_analyzer = network_analyzer
        
        # 初始化所有收集器
        self._init_collectors()
    
    def _init_collectors(self):
        """初始化所有数据收集器"""
        # 统计收集器
        self.stats = {
            'total': 0,
            'actions': Counter(),
            'protocols': Counter(),
            'src_ips': Counter(),
            'dst_ips': Counter(),
            'dst_ports': Counter(),
            'inbound': {'count': 0, 'allowed': 0, 'blocked': 0},
            'outbound': {'count': 0, 'allowed': 0, 'blocked': 0},
        }
        
        # 攻击检测收集器
        self.attack_data = {
            'port_scan': defaultdict(set),  # IP -> 端口集合
            'brute_force': defaultdict(lambda: defaultdict(int)),  # IP -> 端口 -> 次数
            'suspicious_ips': defaultdict(int),  # IP -> 阻止次数
            'dos_data': defaultdict(lambda: {
                'blocked': 0,
                'total': 0,
                'ips': set(),
                'macs': set()
            }),
        }
        
        # 漏洞扫描收集器
        self.vuln_data = {
            'open_ports': set(),
            'dangerous_ports': defaultdict(int),
            'auth_failures': defaultdict(lambda: defaultdict(int)),
            'insecure_protocols': Counter(),
        }
        
        # 代理分析收集器
        self.proxy_data = {
            'proxy_entries': [],
            'proxy_stats': defaultdict(lambda: {
                'count': 0,
                'ports': Counter(),
                'protocols': Counter(),
                'actions': Counter(),
            }),
        }
        
        # 设备指纹收集器
        self.device_data = {
            'ip_mac_map': defaultdict(set),
            'mac_ip_map': defaultdict(set),
        }
    
    def process(self) -> Dict[str, Any]:
        """
        单次遍历处理所有日志条目
        
        Returns:
            Dict: 包含所有分析结果的字典
        """
        logger.info(f"开始统一处理 {len(self.log_entries)} 条日志记录")
        
        # 单次遍历，所有收集器同时工作
        for entry in self.log_entries:
            self._process_statistics(entry)
            self._process_attack_detection(entry)
            self._process_vulnerability_scanning(entry)
            self._process_proxy_analysis(entry)
            self._process_device_fingerprint(entry)
        
        logger.info("统一处理完成")
        
        return {
            'statistics': self._get_statistics_result(),
            'attack_data': self.attack_data,
            'vulnerability_data': self.vuln_data,
            'proxy_data': self.proxy_data,
            'device_data': self.device_data,
        }
    
    def _process_statistics(self, entry: Dict):
        """处理统计信息"""
        self.stats['total'] += 1
        
        # 操作统计
        action = entry.get('action')
        if action:
            self.stats['actions'][action] += 1
        
        # 协议统计
        protocol = entry.get('protocol', 'UNKNOWN')
        self.stats['protocols'][protocol.upper()] += 1
        
        # IP统计
        src_ip = entry.get('src_ip')
        if src_ip:
            self.stats['src_ips'][src_ip] += 1
        
        dst_ip = entry.get('dst_ip')
        if dst_ip:
            self.stats['dst_ips'][dst_ip] += 1
        
        # 端口统计
        dst_port = entry.get('dst_port')
        if dst_port:
            self.stats['dst_ports'][dst_port] += 1
        
        # 方向统计
        if entry.get('interface_in'):
            self.stats['inbound']['count'] += 1
            if action == 'ALLOW':
                self.stats['inbound']['allowed'] += 1
            elif action in ['BLOCK', 'DENY']:
                self.stats['inbound']['blocked'] += 1
        elif entry.get('interface_out'):
            self.stats['outbound']['count'] += 1
            if action == 'ALLOW':
                self.stats['outbound']['allowed'] += 1
            elif action in ['BLOCK', 'DENY']:
                self.stats['outbound']['blocked'] += 1
    
    def _process_attack_detection(self, entry: Dict):
        """处理攻击检测"""
        src_ip = entry.get('src_ip')
        dst_port = entry.get('dst_port')
        action = entry.get('action')
        
        if not src_ip:
            return
        
        # 端口扫描检测
        if dst_port:
            self.attack_data['port_scan'][src_ip].add(dst_port)
        
        # 暴力破解检测
        if action in ['BLOCK', 'DENY'] and dst_port:
            self.attack_data['brute_force'][src_ip][dst_port] += 1
        
        # 可疑活动检测
        if action in ['BLOCK', 'DENY']:
            self.attack_data['suspicious_ips'][src_ip] += 1
        
        # DoS检测
        if action in ['BLOCK', 'DENY']:
            key = src_ip
            self.attack_data['dos_data'][key]['blocked'] += 1
            self.attack_data['dos_data'][key]['total'] += 1
            
            mac = entry.get('mac')
            if mac:
                self.attack_data['dos_data'][key]['macs'].add(mac)
    
    def _process_vulnerability_scanning(self, entry: Dict):
        """处理漏洞扫描"""
        dst_port = entry.get('dst_port')
        action = entry.get('action')
        
        # 开放端口检测
        if action == 'ALLOW' and dst_port:
            try:
                port_num = int(dst_port)
                self.vuln_data['open_ports'].add(port_num)
                
                # 危险端口检测
                dangerous_ports = {22, 23, 3306, 5432, 3389, 5900, 1433, 27017, 6379}
                if port_num in dangerous_ports:
                    self.vuln_data['dangerous_ports'][port_num] += 1
            except (ValueError, TypeError):
                pass
        
        # 认证失败检测
        if action in ['BLOCK', 'DENY']:
            src_ip = entry.get('src_ip')
            if src_ip and dst_port:
                self.vuln_data['auth_failures'][dst_port][src_ip] += 1
        
        # 不安全协议检测
        protocol = entry.get('protocol', '').upper()
        if protocol == 'TELNET' or (dst_port == '23' and action == 'ALLOW'):
            self.vuln_data['insecure_protocols']['TELNET'] += 1
    
    def _process_proxy_analysis(self, entry: Dict):
        """处理代理分析"""
        src_ip = entry.get('src_ip')
        dst_ip = entry.get('dst_ip')
        
        # 检查是否为代理相关流量（198.18.0.0/15）
        is_proxy = False
        if src_ip and (src_ip.startswith('198.18.') or src_ip.startswith('198.19.')):
            is_proxy = True
        elif dst_ip and (dst_ip.startswith('198.18.') or dst_ip.startswith('198.19.')):
            is_proxy = True
        
        if is_proxy:
            self.proxy_data['proxy_entries'].append(entry)
            
            # 统计代理流量
            key = src_ip if src_ip and (src_ip.startswith('198.18.') or src_ip.startswith('198.19.')) else dst_ip
            self.proxy_data['proxy_stats'][key]['count'] += 1
            
            dst_port = entry.get('dst_port')
            if dst_port:
                self.proxy_data['proxy_stats'][key]['ports'][dst_port] += 1
            
            protocol = entry.get('protocol', 'UNKNOWN')
            self.proxy_data['proxy_stats'][key]['protocols'][protocol] += 1
            
            action = entry.get('action')
            if action:
                self.proxy_data['proxy_stats'][key]['actions'][action] += 1
    
    def _process_device_fingerprint(self, entry: Dict):
        """处理设备指纹"""
        src_ip = entry.get('src_ip')
        mac = entry.get('mac')
        
        if src_ip and mac:
            self.device_data['ip_mac_map'][src_ip].add(mac)
            self.device_data['mac_ip_map'][mac].add(src_ip)
    
    def _get_statistics_result(self) -> Dict[str, Any]:
        """获取统计结果"""
        return {
            'total': self.stats['total'],
            'actions': dict(self.stats['actions']),
            'protocols': dict(self.stats['protocols']),
            'top_source_ips': dict(self.stats['src_ips'].most_common(10)),
            'top_destination_ips': dict(self.stats['dst_ips'].most_common(10)),
            'top_destination_ports': dict(self.stats['dst_ports'].most_common(10)),
            'inbound': self.stats['inbound'],
            'outbound': self.stats['outbound'],
        }

