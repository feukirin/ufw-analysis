#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP地址工具函数
"""

from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..core.network import NetworkAnalyzer
else:
    NetworkAnalyzer = None


def get_source_type_label(ip: Optional[str], network_analyzer: Optional['NetworkAnalyzer']) -> str:
    """
    获取IP来源类型标签（统一工具函数）
    
    Args:
        ip: IP地址字符串
        network_analyzer: NetworkAnalyzer实例，可选
    
    Returns:
        IP来源类型标签：'交换机/网关'、'本地网络'、'互联网' 或 '未知'
    """
    if not ip or not network_analyzer:
        return '未知'
    
    ip_type = network_analyzer.get_ip_type(ip)
    type_map = {
        'switch': '交换机/网关',
        'local': '本地网络',
        'internet': '互联网'
    }
    return type_map.get(ip_type, '未知')

