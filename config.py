#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UFW 分析程序配置管理模块
集中管理所有硬编码的配置项，包括阈值、端口映射、服务名称等
"""

from typing import Dict, List, Set
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class DetectionThresholds:
    """攻击检测阈值配置"""
    port_scan: int = 10  # 端口扫描阈值：同一IP扫描的不同端口数
    port_scan_high: int = 50  # 端口扫描高风险阈值
    brute_force: int = 5  # 暴力破解阈值：同一IP对同一端口的失败尝试次数
    brute_force_high: int = 100  # 暴力破解高风险阈值
    brute_force_medium: int = 20  # 暴力破解中等风险阈值
    suspicious_activity: int = 100  # 可疑活动阈值：同一IP被阻止次数
    dos_large: int = 1000  # 大规模DoS攻击阈值
    dos_medium: int = 500  # 中等规模DoS攻击阈值
    dos_small: int = 200  # 小规模DoS攻击阈值
    loop_storm_min: int = 50  # 环路风暴最小重复次数
    loop_storm_high: int = 200  # 环路风暴高置信度阈值
    loop_storm_critical: int = 500  # 环路风暴严重阈值
    proxy_blocked: int = 50  # 代理连接被阻止阈值
    proxy_blocked_high: int = 100  # 代理连接被阻止高风险阈值
    distributed_brute_force: int = 10  # 分布式暴力破解阈值：不同IP攻击同一端口


@dataclass
class PortMappings:
    """端口到服务的映射配置"""
    dangerous_ports: Dict[int, str] = field(default_factory=lambda: {
        22: 'SSH',
        23: 'Telnet',
        80: 'HTTP',
        443: 'HTTPS',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        3389: 'RDP',
        5900: 'VNC',
        1433: 'MSSQL',
        27017: 'MongoDB',
        6379: 'Redis',
        8080: 'HTTP-Proxy',
        8443: 'HTTPS-Alt',
        25: 'SMTP',
        135: 'RPC',
        139: 'NetBIOS',
        445: 'SMB',
        514: 'Syslog',
        1434: 'MSSQL-UDP',
        1521: 'Oracle',
        161: 'SNMP',
        5985: 'WinRM',
        5986: 'WinRM-HTTPS'
    })
    
    service_ports: Dict[str, List[int]] = field(default_factory=lambda: {
        'HTTP': [80, 8080, 8000, 8888],
        'HTTPS': [443, 8443, 4433, 4443, 9443],
        'DNS': [53, 5353],
        'DOT': [853],  # DNS over TLS
        'DOH': [443],  # DNS over HTTPS (通过HTTPS端口)
        'SSH': [22],
        'Telnet': [23],
        'MySQL': [3306],
        'PostgreSQL': [5432],
        'RDP': [3389],
        'VNC': [5900],
        'MSSQL': [1433, 1434],
        'MongoDB': [27017],
        'Redis': [6379],
        'SMTP': [25],
        'RPC': [135],
        'NetBIOS': [139],
        'SMB': [445],
        'Syslog': [514],
        'Oracle': [1521],
        'SNMP': [161],
        'WinRM': [5985, 5986]
    })


@dataclass
class ProxyPortMappings:
    """代理端口映射配置"""
    http_proxy: List[int] = field(default_factory=lambda: [8080, 3128, 8888, 8000, 8880, 8118, 8123, 9999])
    socks_proxy: List[int] = field(default_factory=lambda: [1080, 1081, 1082, 1083, 1084, 1085, 9050, 9051])
    trojan_proxy: List[int] = field(default_factory=lambda: [443, 8443, 4433, 4443, 9443])
    dns_proxy: List[int] = field(default_factory=lambda: [53, 5353, 853])
    other_proxy: List[int] = field(default_factory=lambda: [7890, 7891, 10808, 10809, 10810, 10811])
    clash_proxy: List[int] = field(default_factory=lambda: list(range(10000, 10020)))  # Clash/Mihomo 动态端口范围
    
    def get_all_proxy_ports(self) -> Set[int]:
        """获取所有代理端口"""
        all_ports = set()
        all_ports.update(self.http_proxy)
        all_ports.update(self.socks_proxy)
        all_ports.update(self.trojan_proxy)
        all_ports.update(self.dns_proxy)
        all_ports.update(self.other_proxy)
        all_ports.update(self.clash_proxy)
        return all_ports


@dataclass
class NetworkConfig:
    """网络配置"""
    proxy_ip: str = '198.18.0.2'
    proxy_network: str = '198.18.0.0/15'  # RFC 2544 测试网络
    private_networks: List[str] = field(default_factory=lambda: [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '127.0.0.0/8'  # 本地回环
    ])


@dataclass
class AppConfig:
    """应用程序主配置"""
    detection_thresholds: DetectionThresholds = field(default_factory=DetectionThresholds)
    port_mappings: PortMappings = field(default_factory=PortMappings)
    proxy_port_mappings: ProxyPortMappings = field(default_factory=ProxyPortMappings)
    network_config: NetworkConfig = field(default_factory=NetworkConfig)
    
    # 日志配置
    default_log_path: str = '/var/log/ufw.log'
    cache_dir: str = '~/.ufw_analyzer_cache'
    cache_ttl: int = 86400  # 缓存有效期（秒），默认24小时
    
    # 分析选项
    enable_network_analysis: bool = True
    read_archived_logs: bool = True
    enable_online_vulnerability_db: bool = True


# 全局配置实例
_config: AppConfig = None


def get_config() -> AppConfig:
    """
    获取全局配置实例（单例模式）
    
    Returns:
        AppConfig: 应用程序配置对象
    """
    global _config
    if _config is None:
        _config = AppConfig()
    return _config


def load_config_from_file(config_path: str) -> AppConfig:
    """
    从配置文件加载配置
    
    支持 JSON 和 YAML 格式配置文件
    
    Args:
        config_path: 配置文件路径
        
    Returns:
        AppConfig: 加载的配置对象
        
    Raises:
        FileNotFoundError: 配置文件不存在
        ValueError: 配置文件格式错误
        
    Example:
        JSON格式配置文件示例:
        {
            "detection_thresholds": {
                "port_scan": 15,
                "brute_force": 10
            },
            "port_mappings": {
                "dangerous_ports": {
                    "22": "SSH",
                    "80": "HTTP"
                }
            }
        }
    """
    import os
    import json
    
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"配置文件不存在: {config_path}")
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                try:
                    import yaml
                    config_data = yaml.safe_load(f)
                except ImportError:
                    raise ValueError("YAML配置文件需要安装PyYAML: pip install pyyaml")
            else:
                # 默认使用JSON格式
                config_data = json.load(f)
        
        # 创建配置对象
        config = AppConfig()
        
        # 更新检测阈值
        if 'detection_thresholds' in config_data:
            thresholds = config_data['detection_thresholds']
            for key, value in thresholds.items():
                if hasattr(config.detection_thresholds, key):
                    setattr(config.detection_thresholds, key, value)
        
        # 更新端口映射
        if 'port_mappings' in config_data:
            port_mappings = config_data['port_mappings']
            if 'dangerous_ports' in port_mappings:
                # 转换字符串键为整数键
                dangerous_ports = {}
                for k, v in port_mappings['dangerous_ports'].items():
                    dangerous_ports[int(k)] = v
                config.port_mappings.dangerous_ports.update(dangerous_ports)
            
            if 'service_ports' in port_mappings:
                config.port_mappings.service_ports.update(port_mappings['service_ports'])
        
        # 更新代理端口映射
        if 'proxy_port_mappings' in config_data:
            proxy_mappings = config_data['proxy_port_mappings']
            for key, value in proxy_mappings.items():
                if hasattr(config.proxy_port_mappings, key):
                    setattr(config.proxy_port_mappings, key, value)
        
        # 更新网络配置
        if 'network_config' in config_data:
            network_config = config_data['network_config']
            for key, value in network_config.items():
                if hasattr(config.network_config, key):
                    setattr(config.network_config, key, value)
        
        # 更新应用配置
        app_config_keys = ['default_log_path', 'cache_dir', 'cache_ttl', 
                          'enable_network_analysis', 'read_archived_logs', 
                          'enable_online_vulnerability_db']
        for key in app_config_keys:
            if key in config_data:
                setattr(config, key, config_data[key])
        
        return config
        
    except json.JSONDecodeError as e:
        raise ValueError(f"JSON配置文件格式错误: {e}")
    except Exception as e:
        raise ValueError(f"加载配置文件失败: {e}")


def reset_config():
    """重置全局配置为默认值"""
    global _config
    _config = None

