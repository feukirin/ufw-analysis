#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
类型定义模块
使用 TypedDict 和 Protocol 定义所有数据结构类型和接口
"""

from typing import TypedDict, Protocol, List, Dict, Set, Optional, Any, Union
from datetime import datetime


# ==================== 日志条目类型 ====================

class LogEntry(TypedDict, total=False):
    """UFW 日志条目类型定义"""
    timestamp: Optional[datetime]  # 时间戳
    action: str  # 操作：ALLOW, BLOCK, DENY
    protocol: str  # 协议：TCP, UDP, ICMP等
    src_ip: Optional[str]  # 源IP地址
    dst_ip: Optional[str]  # 目标IP地址
    src_port: Optional[str]  # 源端口
    dst_port: Optional[str]  # 目标端口
    length: Optional[str]  # 数据包长度
    ttl: Optional[str]  # TTL值
    id: Optional[str]  # 数据包ID
    interface_in: Optional[str]  # 入接口
    interface_out: Optional[str]  # 出接口
    mac: Optional[str]  # MAC地址
    service_type: Optional[str]  # 服务类型：HTTP, HTTPS等
    dns_type: Optional[str]  # DNS类型：DNS, DOT, DOH等
    raw_line: str  # 原始日志行


# ==================== 统计结果类型 ====================

class TrafficDirection(TypedDict):
    """流量方向统计"""
    count: int  # 总数量
    allowed: int  # 允许数量
    blocked: int  # 阻止数量


class StatisticsSummary(TypedDict):
    """统计摘要"""
    total_entries: int  # 总条目数
    actions: Dict[str, int]  # 操作统计
    protocols: Dict[str, int]  # 协议统计
    inbound_count: int  # 入站数量
    outbound_count: int  # 出站数量
    top_source_ips: Dict[str, int]  # 前10个源IP
    top_destination_ips: Dict[str, int]  # 前10个目标IP
    top_destination_ports: Dict[str, int]  # 前10个目标端口
    tcp_count: int  # TCP数量
    udp_count: int  # UDP数量
    http_count: int  # HTTP数量
    https_count: int  # HTTPS数量
    dns_count: int  # DNS数量
    dot_count: int  # DOT数量
    doh_count: int  # DOH数量
    mac_addresses_count: int  # MAC地址数量
    entries_with_mac: int  # 包含MAC的条目数
    entries_with_ip: int  # 包含IP的条目数


class TrafficByDirection(TypedDict):
    """按方向分类的流量统计"""
    inbound: TrafficDirection  # 入站流量
    outbound: TrafficDirection  # 出站流量


# ==================== 攻击检测结果类型 ====================

class AttackResult(TypedDict, total=False):
    """攻击检测结果"""
    type: str  # 攻击类型
    source_ip: Optional[str]  # 源IP
    destination_ip: Optional[str]  # 目标IP
    destination_port: Optional[str]  # 目标端口
    count: int  # 攻击次数
    severity: str  # 严重程度：critical, high, medium, low
    description: str  # 描述
    timestamp: Optional[datetime]  # 时间戳
    mac: Optional[str]  # MAC地址
    source_type: Optional[str]  # 源类型：本地网络、互联网、交换机/网关
    ports_scanned: Optional[List[str]]  # 扫描的端口列表
    time_window: Optional[str]  # 时间窗口
    recommendations: Optional[List[str]]  # 建议


class SQLInjectionStats(TypedDict):
    """SQL注入统计"""
    total_detections: int  # 总检测数
    unique_ips: int  # 唯一IP数
    unique_ports: int  # 唯一端口数
    by_type: Dict[str, int]  # 按类型统计
    by_severity: Dict[str, int]  # 按严重程度统计
    by_source_type: Dict[str, int]  # 按源类型统计
    top_source_ips: Dict[str, int]  # 前10个源IP
    top_target_ports: Dict[str, int]  # 前10个目标端口


# ==================== 漏洞扫描结果类型 ====================

class VulnerabilityResult(TypedDict, total=False):
    """漏洞扫描结果"""
    type: str  # 漏洞类型
    port: Optional[str]  # 端口
    service: Optional[str]  # 服务名称
    severity: str  # 严重程度：critical, high, medium, low
    description: str  # 描述
    recommendation: str  # 建议
    cve_ids: Optional[List[str]]  # CVE编号列表
    affected_ips: Optional[List[str]]  # 受影响的IP列表
    count: Optional[int]  # 数量


# ==================== 代理分析结果类型 ====================

class ProxyTypeStats(TypedDict):
    """代理类型统计"""
    count: int  # 数量
    ports: List[int]  # 使用的端口列表
    description: str  # 描述
    percentage: float  # 百分比


class ProxyAnalysisResult(TypedDict):
    """代理分析结果"""
    total_proxy_entries: int  # 总代理条目数
    proxy_types: Dict[str, ProxyTypeStats]  # 代理类型统计
    traffic_stats: Dict[str, Any]  # 流量统计
    detailed_analysis: Dict[str, Any]  # 详细分析


class ProxyAttackResult(TypedDict, total=False):
    """代理攻击检测结果"""
    type: str  # 攻击类型
    client_ip: str  # 客户端IP
    proxy_ip: str  # 代理IP
    proxy_types: Optional[List[str]]  # 代理类型列表
    ports_used: Optional[List[int]]  # 使用的端口列表
    total_usage: int  # 总使用次数
    severity: str  # 严重程度
    description: str  # 描述
    blocked_count: Optional[int]  # 阻止次数


# ==================== 设备指纹类型 ====================

class DeviceFingerprintResult(TypedDict, total=False):
    """设备指纹结果"""
    ip: str  # IP地址
    mac: Optional[str]  # MAC地址
    ip_type: str  # IP类型：switch, local, internet, unknown
    device_type: str  # 设备类型
    associated_macs: List[str]  # 关联的MAC地址列表
    associated_ips: List[str]  # 关联的IP地址列表
    manufacturer: Optional[str]  # 制造商


class DeviceSummary(TypedDict):
    """设备摘要"""
    total_devices: int  # 总设备数
    ip_mac_pairs: int  # IP-MAC对数量
    mac_ip_pairs: int  # MAC-IP对数量
    devices: List[DeviceFingerprintResult]  # 设备列表


# ==================== 网络分析类型 ====================

class NetworkInterface(TypedDict):
    """网络接口信息"""
    name: str  # 接口名称
    ip_addresses: List[str]  # IP地址列表
    mac_address: Optional[str]  # MAC地址
    netmask: Optional[str]  # 子网掩码
    network: Optional[str]  # 网络地址


class NetworkInfo(TypedDict):
    """网络信息"""
    interfaces: List[NetworkInterface]  # 网络接口列表
    gateway_ip: Optional[str]  # 网关IP
    host_ip: Optional[str]  # 主机IP
    local_networks: List[str]  # 本地网络列表
    switch_ips: List[str]  # 交换机/网关IP列表
    total_local_networks: int  # 总本地网络数


# ==================== 接口定义 (Protocol) ====================

class NetworkAnalyzerProtocol(Protocol):
    """网络分析器接口"""
    def get_ip_type(self, ip_str: Optional[str]) -> str:
        """获取IP类型：'switch', 'local', 'internet', 'unknown'"""
        ...
    
    def is_local_ip(self, ip_str: Optional[str]) -> bool:
        """判断是否为本地IP"""
        ...
    
    def is_internet_ip(self, ip_str: Optional[str]) -> bool:
        """判断是否为互联网IP"""
        ...
    
    def is_switch_ip(self, ip_str: Optional[str]) -> bool:
        """判断是否为交换机/网关IP"""
        ...


class LogParserProtocol(Protocol):
    """日志解析器接口"""
    def read_logs(self) -> List[LogEntry]:
        """读取日志"""
        ...
    
    def parse_log_line(self, line: str) -> Optional[LogEntry]:
        """解析单行日志"""
        ...


class StatisticsProtocol(Protocol):
    """统计模块接口"""
    def get_summary(self) -> StatisticsSummary:
        """获取统计摘要"""
        ...
    
    def get_traffic_by_direction(self) -> TrafficByDirection:
        """获取按方向分类的流量统计"""
        ...


class AttackDetectorProtocol(Protocol):
    """攻击检测器接口"""
    def detect_all_attacks(self) -> List[AttackResult]:
        """检测所有攻击"""
        ...
    
    def detect_port_scan(self, threshold: Optional[int] = None) -> List[AttackResult]:
        """检测端口扫描"""
        ...
    
    def detect_brute_force(self, threshold: Optional[int] = None) -> List[AttackResult]:
        """检测暴力破解"""
        ...


class VulnerabilityScannerProtocol(Protocol):
    """漏洞扫描器接口"""
    def scan_all_vulnerabilities(self) -> List[VulnerabilityResult]:
        """扫描所有漏洞"""
        ...
    
    def scan_open_ports(self) -> List[VulnerabilityResult]:
        """扫描开放端口"""
        ...


# ==================== 统一处理器结果类型 ====================

class UnifiedProcessResult(TypedDict):
    """统一处理结果"""
    statistics: Dict[str, Any]  # 统计结果
    attack_data: Dict[str, Any]  # 攻击数据
    vulnerability_data: Dict[str, Any]  # 漏洞数据
    proxy_data: Dict[str, Any]  # 代理数据
    device_data: Dict[str, Any]  # 设备数据

