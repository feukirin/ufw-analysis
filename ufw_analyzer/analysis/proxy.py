#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
代理服务分析器
针对特殊代理IP进行流量分析和攻击检测
"""

import ipaddress
from collections import defaultdict, Counter
from typing import Dict, List, Optional, Any
import logging

logger = logging.getLogger('ufw_analyzer')


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
        except (ipaddress.AddressValueError, ValueError):
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
                port = src_port
            else:
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
            
            stats['protocols'][protocol] += 1
            stats['actions'][action] += 1
            
            if dst_port:
                stats['top_ports'][dst_port] += 1
            if src_port:
                stats['top_ports'][src_port] += 1
            
            # 根据代理角色统计方向
            if proxy_role == 'source':
                stats['outbound']['count'] += 1
                if action == 'ALLOW':
                    stats['outbound']['allowed'] += 1
                elif action in ['BLOCK', 'DENY']:
                    stats['outbound']['blocked'] += 1
                
                if dst_ip:
                    stats['top_destination_ips'][dst_ip] += 1
            else:
                stats['inbound']['count'] += 1
                if action == 'ALLOW':
                    stats['inbound']['allowed'] += 1
                elif action in ['BLOCK', 'DENY']:
                    stats['inbound']['blocked'] += 1
                
                if src_ip:
                    stats['top_source_ips'][src_ip] += 1
            
            # 时间分布
            if timestamp:
                try:
                    date_part = timestamp.split()[0] if ' ' in timestamp else timestamp[:10]
                    stats['time_distribution'][date_part] += 1
                except (AttributeError, IndexError, KeyError) as e:
                    logger.debug(f"时间戳解析错误: timestamp={timestamp}, 错误: {e}")
        
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
        usage_patterns = {
            'http_patterns': [],
            'socks_patterns': [],
            'trojan_patterns': [],
            'dns_patterns': []
        }
        
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
                
                if port_num in self.PROXY_PORTS['http_proxy']['ports']:
                    usage_patterns['http_patterns'].append({
                        'port': port_num,
                        'protocol': protocol,
                        'action': entry.get('action'),
                        'role': proxy_role
                    })
                elif port_num in self.PROXY_PORTS['socks_proxy']['ports']:
                    usage_patterns['socks_patterns'].append({
                        'port': port_num,
                        'protocol': protocol,
                        'action': entry.get('action'),
                        'role': proxy_role
                    })
                elif port_num in self.PROXY_PORTS['trojan_proxy']['ports'] and protocol == 'TCP':
                    usage_patterns['trojan_patterns'].append({
                        'port': port_num,
                        'protocol': protocol,
                        'action': entry.get('action'),
                        'role': proxy_role
                    })
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
                client_ip = dst_ip
            else:
                client_ip = src_ip
            
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

