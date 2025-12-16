#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络结构分析器
负责分析本地网络结构、IP地址分类等
"""

import os
import socket
import subprocess
import ipaddress
from typing import Dict, List, Optional, Set, Any
import logging

logger = logging.getLogger('ufw_analyzer')


class NetworkAnalyzer:
    """网络结构分析器"""
    
    def __init__(self):
        self.local_networks: Set[ipaddress.IPv4Network] = set()
        self.local_interfaces: List[Dict] = []
        self.gateway_ip: Optional[str] = None
        self.host_ip: Optional[str] = None
        self.switch_ips: Set[str] = set()  # 交换机/网关IP地址集合
        
        # IP类型缓存（手动实现，避免@lru_cache在实例方法上的问题）
        self._ip_type_cache: Dict[str, str] = {}
        self._cache_maxsize = 10000
        
        # 初始化网络信息
        self._init_network_info()
    
    def _init_network_info(self):
        """初始化网络信息"""
        try:
            self.local_interfaces = self.get_local_interfaces()
            self._identify_switch_addresses()
        except Exception as e:
            logger.warning(f"网络信息初始化失败: {e}")
    
    def get_local_interfaces(self) -> List[Dict]:
        """获取本地网络接口信息"""
        interfaces = []
        
        try:
            # 尝试使用 ip 命令
            result = subprocess.run(['ip', 'addr', 'show'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                current_interface = None
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('inet6'):
                        if ':' in line and not line.startswith(' '):
                            # 新接口
                            parts = line.split(':')
                            if len(parts) >= 2:
                                current_interface = parts[1].strip()
                        elif line.startswith('inet ') and current_interface:
                            # IP地址
                            parts = line.split()
                            if len(parts) >= 2:
                                ip_with_cidr = parts[1]
                                try:
                                    ip_obj = ipaddress.IPv4Interface(ip_with_cidr)
                                    ip_str = str(ip_obj.ip)
                                    network = ip_obj.network
                                    
                                    interfaces.append({
                                        'interface': current_interface,
                                        'ip': ip_str,
                                        'cidr': str(network)
                                    })
                                    
                                    self.local_networks.add(network)
                                    if not self.host_ip:
                                        self.host_ip = ip_str
                                except (ValueError, ipaddress.AddressValueError):
                                    pass
        except (subprocess.SubprocessError, FileNotFoundError, OSError) as e:
            logger.debug(f"ip命令执行失败: {e}")
        
        # 如果ip命令失败，尝试使用ifconfig
        if not interfaces:
            try:
                result = subprocess.run(['ifconfig'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    # 解析ifconfig输出（简化版）
                    for line in result.stdout.split('\n'):
                        if 'inet ' in line and '127.0.0.1' not in line:
                            parts = line.split()
                            for i, part in enumerate(parts):
                                if part == 'inet' and i + 1 < len(parts):
                                    ip_str = parts[i + 1]
                                    try:
                                        ip_obj = ipaddress.IPv4Address(ip_str)
                                        network = ipaddress.IPv4Network(f"{ip_str}/24", strict=False)
                                        
                                        interfaces.append({
                                            'interface': 'unknown',
                                            'ip': ip_str,
                                            'cidr': str(network)
                                        })
                                        
                                        self.local_networks.add(network)
                                        if not self.host_ip:
                                            self.host_ip = ip_str
                                    except (ValueError, ipaddress.AddressValueError):
                                        pass
            except (subprocess.SubprocessError, FileNotFoundError, OSError) as e:
                logger.debug(f"ifconfig命令执行失败: {e}")
        
        return interfaces
    
    def _identify_switch_addresses(self):
        """识别交换机/网关地址"""
        try:
            # 获取默认网关
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'default via' in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part == 'via' and i + 1 < len(parts):
                                gateway = parts[i + 1]
                                try:
                                    ipaddress.IPv4Address(gateway)
                                    self.gateway_ip = gateway
                                    self.switch_ips.add(gateway)
                                except (ValueError, ipaddress.AddressValueError):
                                    pass
        except (subprocess.SubprocessError, FileNotFoundError, OSError) as e:
            logger.debug(f"获取网关失败: {e}")
        
        # 为每个本地网络添加网关模式地址（.1地址）
        for network in self.local_networks:
            try:
                # 获取网络的主机地址范围
                hosts = list(network.hosts())
                if hosts:
                    # 通常.1是网关
                    gateway_candidate = str(hosts[0])
                    self.switch_ips.add(gateway_candidate)
            except Exception:
                pass
    
    def is_local_ip(self, ip_str: Optional[str]) -> bool:
        """判断是否为本地网络IP"""
        if not ip_str:
            return False
        
        try:
            ip = ipaddress.IPv4Address(ip_str)
            for network in self.local_networks:
                if ip in network:
                    return True
            return False
        except (ValueError, ipaddress.AddressValueError):
            return False
    
    def is_internet_ip(self, ip_str: Optional[str]) -> bool:
        """判断是否为互联网IP"""
        if not ip_str:
            return False
        
        try:
            ip = ipaddress.IPv4Address(ip_str)
            # 私有网络范围
            private_ranges = [
                ipaddress.IPv4Network('10.0.0.0/8'),
                ipaddress.IPv4Network('172.16.0.0/12'),
                ipaddress.IPv4Network('192.168.0.0/16'),
                ipaddress.IPv4Network('127.0.0.0/8'),
            ]
            
            # 检查是否为私有IP
            for private_range in private_ranges:
                if ip in private_range:
                    return False
            
            # 检查是否在本地网络中
            if self.is_local_ip(ip_str):
                return False
            
            return True
        except (ValueError, ipaddress.AddressValueError):
            return False
    
    def is_switch_ip(self, ip_str: Optional[str]) -> bool:
        """判断是否为交换机/网关IP"""
        if not ip_str:
            return False
        
        # 首先检查已知的交换机IP
        if ip_str in self.switch_ips:
            return True
        
        # 检查是否为网关IP
        if ip_str == self.gateway_ip:
            return True
        
        return False
    
    def get_ip_type(self, ip_str: Optional[str]) -> str:
        """
        获取IP地址类型
        
        Args:
            ip_str: IP地址字符串
        
        Returns:
            IP类型：'switch'（交换机/网关）、'local'（本地网络）、'internet'（互联网）
        """
        if not ip_str:
            return 'unknown'
        
        # 检查缓存
        if ip_str in self._ip_type_cache:
            return self._ip_type_cache[ip_str]
        
        # 判断类型
        if self.is_switch_ip(ip_str):
            ip_type = 'switch'
        elif self.is_local_ip(ip_str):
            ip_type = 'local'
        elif self.is_internet_ip(ip_str):
            ip_type = 'internet'
        else:
            ip_type = 'unknown'
        
        # 缓存结果（限制缓存大小）
        if len(self._ip_type_cache) < self._cache_maxsize:
            self._ip_type_cache[ip_str] = ip_type
        else:
            # 缓存已满，清空缓存
            self._ip_type_cache.clear()
            self._ip_type_cache[ip_str] = ip_type
        
        return ip_type
    
    def get_network_info(self) -> Dict[str, Any]:
        """获取网络信息摘要"""
        return {
            'interfaces': self.local_interfaces,
            'local_networks': [str(net) for net in self.local_networks],
            'gateway_ip': self.gateway_ip,
            'host_ip': self.host_ip,
            'switch_ips': list(self.switch_ips),
            'total_local_networks': len(self.local_networks)
        }

