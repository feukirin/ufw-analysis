#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
控制台输出格式化器
提供控制台友好的格式化输出
"""

from typing import Dict, List, Optional, Any
from .base import BaseFormatter


class ConsoleFormatter(BaseFormatter):
    """控制台输出格式化器"""
    
    def __init__(self, network_analyzer=None):
        """
        初始化控制台格式化器
        
        Args:
            network_analyzer: NetworkAnalyzer实例，用于IP类型判断
        """
        self.network_analyzer = network_analyzer
        self.separator = "=" * 60
    
    def format_network_info(self, network_info: Dict[str, Any]) -> str:
        """格式化网络结构信息"""
        if not network_info:
            return ""
        
        lines = [f"\n{self.separator}", "本地网络结构", self.separator]
        
        if network_info.get('host_ip'):
            lines.append(f"主机 IP: {network_info['host_ip']}")
        if network_info.get('gateway_ip'):
            lines.append(f"网关 IP: {network_info['gateway_ip']}")
        
        if network_info.get('switch_ips'):
            lines.append("交换机/网关 IP 列表:")
            for switch_ip in network_info['switch_ips']:
                lines.append(f"  {switch_ip}")
        
        if network_info.get('local_interfaces'):
            lines.append("\n本地网络接口:")
            for iface in network_info['local_interfaces']:
                lines.append(f"  {iface['interface']}: {iface['ip']} ({iface['cidr']})")
        
        if network_info.get('local_networks'):
            lines.append("\n本地网络范围:")
            networks = network_info['local_networks'][:10]
            for net in networks:
                lines.append(f"  {net}")
            if len(network_info['local_networks']) > 10:
                lines.append(f"  ... 共 {len(network_info['local_networks'])} 个网络范围")
        
        return "\n".join(lines)
    
    def format_summary(self, summary: Dict[str, Any]) -> str:
        """格式化统计摘要"""
        lines = [f"\n{self.separator}", "统计摘要", self.separator]
        lines.append(f"总日志条目数: {summary.get('total_entries', 0)}")
        
        if summary.get('actions'):
            lines.append("\n操作统计:")
            for action, count in summary['actions'].items():
                lines.append(f"  {action}: {count}")
        
        if summary.get('protocols'):
            lines.append("\n协议统计:")
            for protocol, count in summary['protocols'].items():
                lines.append(f"  {protocol}: {count}")
        
        # TCP/UDP 区分
        if 'tcp_udp' in summary:
            tcp_udp = summary['tcp_udp']
            lines.append(f"\nTCP/UDP 协议统计:")
            lines.append(f"  TCP: {tcp_udp['tcp_count']} ({tcp_udp['tcp_percentage']}%)")
            lines.append(f"  UDP: {tcp_udp['udp_count']} ({tcp_udp['udp_percentage']}%)")
        
        # HTTP/HTTPS 区分
        if 'http_https' in summary:
            http_https = summary['http_https']
            lines.append(f"\nHTTP/HTTPS 服务统计:")
            lines.append(f"  HTTP: {http_https['http_count']} ({http_https['http_percentage']}%)")
            lines.append(f"  HTTPS/DOH: {http_https['https_count']} ({http_https['https_percentage']}%)")
        
        # DNS/DOT/DOH 区分
        if 'dns_types' in summary:
            dns_types = summary['dns_types']
            if dns_types['total_dns'] > 0:
                lines.append(f"\nDNS 服务统计:")
                lines.append(f"  DNS (标准): {dns_types['dns_count']}")
                lines.append(f"  DOT (DNS over TLS): {dns_types['dot_count']}")
                lines.append(f"  DOH (DNS over HTTPS): {dns_types['doh_count']}")
                lines.append(f"  总计: {dns_types['total_dns']}")
        
        # Top IPs
        if summary.get('top_source_ips'):
            lines.append(f"\nTop 10 源 IP:")
            for ip, count in list(summary['top_source_ips'].items())[:10]:
                if self.network_analyzer:
                    from ..utils.ip_utils import get_source_type_label
                    type_label = get_source_type_label(ip, self.network_analyzer)
                    lines.append(f"  {ip} ({type_label}): {count}")
                else:
                    lines.append(f"  {ip}: {count}")
        
        # Top Ports
        if summary.get('top_destination_ports'):
            lines.append(f"\nTop 10 目标端口:")
            for port, count in list(summary['top_destination_ports'].items())[:10]:
                lines.append(f"  {port}: {count}")
        
        return "\n".join(lines)
    
    def format_traffic(self, traffic: Dict[str, Any]) -> str:
        """格式化流量统计"""
        lines = []
        
        if 'inbound' in traffic and 'outbound' in traffic:
            lines.append(f"\n流量方向统计:")
            lines.append(f"  入站: {traffic['inbound']['count']} (允许: {traffic['inbound']['allowed']}, 阻止: {traffic['inbound']['blocked']})")
            lines.append(f"  出站: {traffic['outbound']['count']} (允许: {traffic['outbound']['allowed']}, 阻止: {traffic['outbound']['blocked']})")
        
        return "\n".join(lines)
    
    def format_attacks(self, attacks: List[Dict[str, Any]]) -> str:
        """格式化攻击检测结果"""
        lines = [f"\n{self.separator}", "网络攻击检测结果", self.separator]
        
        if not attacks:
            lines.append("未检测到明显的网络攻击")
            return "\n".join(lines)
        
        lines.append(f"检测到 {len(attacks)} 个潜在攻击")
        
        # 按类型分类
        injection_attacks = [a for a in attacks if '注入' in a.get('type', '')]
        if injection_attacks:
            lines.append(f"\n注入攻击: {len(injection_attacks)} 个")
        
        # 显示前10个攻击
        for i, attack in enumerate(attacks[:10], 1):
            lines.append(f"\n[{i}] {attack.get('type', '未知攻击')}")
            if attack.get('source_ip'):
                lines.append(f"    源 IP: {attack['source_ip']}")
            if attack.get('severity'):
                lines.append(f"    严重程度: {attack['severity']}")
        
        if len(attacks) > 10:
            lines.append(f"\n... 还有 {len(attacks) - 10} 个攻击未显示")
        
        return "\n".join(lines)
    
    def format_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """格式化漏洞扫描结果"""
        lines = [f"\n{self.separator}", "系统漏洞扫描结果", self.separator]
        
        if not vulnerabilities:
            lines.append("未检测到明显的系统漏洞")
            return "\n".join(lines)
        
        # 按严重程度分类
        critical = len([v for v in vulnerabilities if v.get('severity') == 'critical'])
        high = len([v for v in vulnerabilities if v.get('severity') == 'high'])
        medium = len([v for v in vulnerabilities if v.get('severity') == 'medium'])
        low = len([v for v in vulnerabilities if v.get('severity') == 'low'])
        
        lines.append(f"检测到 {len(vulnerabilities)} 个潜在漏洞:")
        lines.append(f"  严重 (Critical): {critical} 个")
        lines.append(f"  高 (High): {high} 个")
        lines.append(f"  中 (Medium): {medium} 个")
        lines.append(f"  低 (Low): {low} 个")
        
        # 显示前10个漏洞
        for i, vuln in enumerate(vulnerabilities[:10], 1):
            lines.append(f"\n[{i}] {vuln.get('type', '未知漏洞')}")
            if vuln.get('port'):
                lines.append(f"    端口: {vuln['port']}")
            if vuln.get('severity'):
                lines.append(f"    严重程度: {vuln['severity'].upper()}")
        
        if len(vulnerabilities) > 10:
            lines.append(f"\n... 还有 {len(vulnerabilities) - 10} 个漏洞未显示")
        
        return "\n".join(lines)
    
    def format_proxy_analysis(self, proxy_analysis: Optional[Dict[str, Any]], 
                             proxy_attacks: Optional[List[Dict[str, Any]]]) -> str:
        """格式化代理分析结果"""
        lines = []
        
        if proxy_analysis and proxy_analysis.get('total_entries', 0) > 0:
            lines.append(f"\n{self.separator}")
            lines.append("代理服务分析结果")
            lines.append(self.separator)
            lines.append(f"代理相关流量总数: {proxy_analysis.get('total_entries', 0)}")
        
        if proxy_attacks:
            lines.append(f"\n代理相关安全事件: {len(proxy_attacks)} 个")
        
        return "\n".join(lines) if lines else ""
    
    def format_all(self, network_info: Optional[Dict[str, Any]], 
                  summary: Dict[str, Any], traffic: Dict[str, Any],
                  attacks: List[Dict[str, Any]], vulnerabilities: List[Dict[str, Any]],
                  proxy_analysis: Optional[Dict[str, Any]] = None,
                  proxy_attacks: Optional[List[Dict[str, Any]]] = None) -> str:
        """格式化所有结果"""
        parts = []
        
        if network_info:
            parts.append(self.format_network_info(network_info))
        
        parts.append(self.format_summary(summary))
        parts.append(self.format_traffic(traffic))
        parts.append(self.format_attacks(attacks))
        parts.append(self.format_vulnerabilities(vulnerabilities))
        
        proxy_output = self.format_proxy_analysis(proxy_analysis, proxy_attacks)
        if proxy_output:
            parts.append(proxy_output)
        
        parts.append(f"\n{self.separator}")
        parts.append("分析完成")
        parts.append(self.separator)
        
        return "\n".join(parts)

