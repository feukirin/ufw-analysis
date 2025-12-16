#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
输出格式化器基类
定义输出格式化器的接口
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any


class BaseFormatter(ABC):
    """输出格式化器基类"""
    
    @abstractmethod
    def format_network_info(self, network_info: Dict[str, Any]) -> str:
        """格式化网络结构信息"""
        pass
    
    @abstractmethod
    def format_summary(self, summary: Dict[str, Any]) -> str:
        """格式化统计摘要"""
        pass
    
    @abstractmethod
    def format_traffic(self, traffic: Dict[str, Any]) -> str:
        """格式化流量统计"""
        pass
    
    @abstractmethod
    def format_attacks(self, attacks: List[Dict[str, Any]]) -> str:
        """格式化攻击检测结果"""
        pass
    
    @abstractmethod
    def format_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """格式化漏洞扫描结果"""
        pass
    
    @abstractmethod
    def format_proxy_analysis(self, proxy_analysis: Optional[Dict[str, Any]], 
                            proxy_attacks: Optional[List[Dict[str, Any]]]) -> str:
        """格式化代理分析结果"""
        pass
    
    @abstractmethod
    def format_all(self, network_info: Optional[Dict[str, Any]], 
                  summary: Dict[str, Any], traffic: Dict[str, Any],
                  attacks: List[Dict[str, Any]], vulnerabilities: List[Dict[str, Any]],
                  proxy_analysis: Optional[Dict[str, Any]] = None,
                  proxy_attacks: Optional[List[Dict[str, Any]]] = None) -> str:
        """格式化所有结果"""
        pass

