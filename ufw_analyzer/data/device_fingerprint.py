#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
设备指纹识别器
基于IP和MAC地址进行设备识别
"""

import re
from collections import defaultdict
from typing import Dict, List, Optional, Set, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ..core.network import NetworkAnalyzer
else:
    NetworkAnalyzer = None


class DeviceFingerprint:
    """设备指纹识别器（基于IP和MAC地址）"""
    
    def __init__(self, network_analyzer: Optional['NetworkAnalyzer'] = None):
        """
        初始化设备指纹识别器
        
        Args:
            network_analyzer: 网络分析器实例，用于IP类型判断
        """
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
        
        # 检查缓存
        if mac_clean in self._device_type_cache:
            return self._device_type_cache[mac_clean]
        
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

