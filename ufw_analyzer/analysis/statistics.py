#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UFW统计模块
提供日志统计和分析功能
"""

from collections import Counter, defaultdict
from typing import Dict, List, Optional, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ..core.network import NetworkAnalyzer
    from type_definitions import StatisticsSummary, TrafficByDirection
else:
    NetworkAnalyzer = None
    StatisticsSummary = Dict[str, Any]
    TrafficByDirection = Dict[str, Any]


class UFWStatistics:
    """UFW 统计模块"""
    
    def __init__(self, log_entries: List[Dict], network_analyzer: Optional['NetworkAnalyzer'] = None):
        """
        初始化统计模块
        
        Args:
            log_entries: 日志条目列表
            network_analyzer: 网络分析器实例，用于IP类型判断
        """
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
        tcp_count = sum(1 for entry in self.log_entries if (entry.get('protocol') or '').upper() == 'TCP')
        udp_count = sum(1 for entry in self.log_entries if (entry.get('protocol') or '').upper() == 'UDP')
        
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
    
    def get_traffic_by_direction(self) -> 'TrafficByDirection':
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

