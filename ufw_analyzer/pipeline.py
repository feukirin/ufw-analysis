#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分析流程管理器
统一管理整个分析流程，实现统一数据流
"""

from typing import Dict, List, Any, Optional
import logging
import os

from .core.network import NetworkAnalyzer
from .core.parser import UFWLogParser
from .core.processor import UnifiedLogProcessor
from .analysis.statistics import UFWStatistics
from .analysis.attack_detector import AttackDetector, AdvancedAttackDetector
from .analysis.vulnerability import VulnerabilityScanner
from .analysis.proxy import ProxyAnalyzer

logger = logging.getLogger('ufw_analyzer')


class AnalysisPipeline:
    """
    分析流程管理器
    
    统一管理整个分析流程，实现统一数据流和单次遍历优化。
    """
    
    def __init__(self, log_path: str = "/var/log/ufw.log", 
                 enable_network_analysis: bool = True, 
                 read_archived: bool = True,
                 enable_online_db: bool = True):
        """
        初始化分析流程管理器
        
        Args:
            log_path: 日志文件路径
            enable_network_analysis: 是否启用网络分析
            read_archived: 是否读取压缩的历史日志
            enable_online_db: 是否启用在线漏洞数据库
        """
        self.log_path = log_path
        self.enable_network_analysis = enable_network_analysis
        self.read_archived = read_archived
        self.enable_online_db = enable_online_db
        
        # 初始化组件
        self.parser = UFWLogParser(log_path, read_archived=read_archived)
        self.network_analyzer: Optional[NetworkAnalyzer] = None
        self.log_entries: List[Dict] = []
        
        # 分析结果
        self.processed_data: Optional[Dict[str, Any]] = None
        self.statistics: Optional[UFWStatistics] = None
        self.attack_detector: Optional[AttackDetector] = None
        self.vulnerability_scanner: Optional[VulnerabilityScanner] = None
        self.proxy_analyzer: Optional[ProxyAnalyzer] = None
    
    def run(self) -> Dict[str, Any]:
        """
        执行完整分析流程
        
        Returns:
            Dict: 包含所有分析结果的字典
        """
        logger.info("=" * 60)
        logger.info("UFW 防火墙日志分析程序")
        logger.info("=" * 60)
        
        # 阶段1: 初始化
        self._initialize()
        
        # 阶段2: 数据收集（统一数据流）
        self._collect_data()
        
        # 阶段3: 分析处理
        self._analyze()
        
        # 阶段4: 返回结果
        return self._get_results()
    
    def _initialize(self):
        """初始化阶段"""
        logger.info("阶段1: 初始化")
        
        # 分析本地网络结构
        if self.enable_network_analysis:
            logger.info("正在分析本地网络结构...")
            self.network_analyzer = NetworkAnalyzer()
            network_info = self.network_analyzer.get_local_interfaces()
            logger.info(f"检测到 {len(network_info)} 个网络接口")
            logger.info(f"识别到 {len(self.network_analyzer.local_networks)} 个本地网络范围")
        
        # 读取日志
        print("正在读取日志文件...")
        if self.read_archived:
            print("(包括压缩的历史日志文件)")
        
        # 检查日志文件是否存在
        log_path = self.parser.log_path
        if not os.path.exists(log_path):
            print(f"警告: 日志文件不存在: {log_path}")
            print(f"请检查日志文件路径是否正确")
        else:
            print(f"日志文件存在: {log_path}")
            # 检查文件权限
            if not os.access(log_path, os.R_OK):
                print(f"警告: 没有读取权限: {log_path}")
                print(f"请使用 sudo 运行程序，或检查文件权限")
        
        self.log_entries = self.parser.read_logs()
        
        if self.parser.log_files_read:
            print(f"\n已读取 {len(self.parser.log_files_read)} 个日志文件，共 {len(self.log_entries)} 条日志记录")
            if len(self.log_entries) == 0:
                print(f"警告: 日志文件存在但未解析到任何日志记录")
                print(f"可能的原因:")
                print(f"  1. 日志文件格式不正确")
                print(f"  2. 日志文件为空")
                print(f"  3. UFW 日志格式不匹配")
        else:
            print(f"已读取 {len(self.log_entries)} 条日志记录")
            if len(self.log_entries) == 0:
                print(f"警告: 未找到任何日志记录")
                print(f"可能的原因:")
                print(f"  1. 日志文件不存在: {log_path}")
                print(f"  2. 日志文件路径不正确")
                print(f"  3. 没有读取权限（需要使用 sudo）")
        
        if not self.log_entries:
            print("\n错误: 未找到日志记录，无法继续分析")
            print("请检查:")
            print(f"  1. 日志文件路径: {log_path}")
            print(f"  2. 文件是否存在: {os.path.exists(log_path) if log_path else 'N/A'}")
            print(f"  3. 是否有读取权限")
            logger.warning("未找到日志记录，无法继续分析")
            return
    
    def _collect_data(self):
        """数据收集阶段（统一数据流）"""
        logger.info("阶段2: 数据收集（统一数据流，单次遍历）")
        
        if not self.log_entries:
            logger.warning("没有日志记录，跳过数据收集")
            return
        
        # 使用统一日志处理器进行单次遍历
        processor = UnifiedLogProcessor(self.log_entries, self.network_analyzer)
        self.processed_data = processor.process()
        
        logger.info("统一数据收集完成")
    
    def _analyze(self):
        """分析处理阶段"""
        logger.info("阶段3: 分析处理")
        
        if not self.log_entries:
            logger.warning("没有日志记录，跳过分析")
            return
        
        # 统计分析（使用统一数据流的结果）
        logger.info("正在生成统计信息...")
        self.statistics = UFWStatistics(self.log_entries, self.network_analyzer)
        
        # 攻击检测（使用统一数据流的结果）
        logger.info("正在检测网络攻击（使用数据挖掘技术）...")
        self.attack_detector = AttackDetector(self.log_entries, self.network_analyzer)
        
        # 漏洞扫描
        logger.info("正在扫描系统漏洞（使用增强漏洞数据库）...")
        self.vulnerability_scanner = VulnerabilityScanner(
            self.log_entries, 
            self.network_analyzer, 
            enable_online_db=self.enable_online_db
        )
        
        # 代理服务分析
        logger.info("正在分析代理服务流量...")
        self.proxy_analyzer = ProxyAnalyzer()
    
    def _get_results(self) -> Dict[str, Any]:
        """获取分析结果"""
        logger.info("阶段4: 生成结果")
        
        if not self.log_entries:
            return {
                'error': '没有日志记录',
                'network_info': self.network_analyzer.get_network_info() if self.network_analyzer else None
            }
        
        # 确保 statistics 已初始化
        if not self.statistics:
            logger.warning("statistics 未初始化，尝试重新创建")
            self.statistics = UFWStatistics(self.log_entries, self.network_analyzer)
        
        # 获取各项分析结果
        summary = self.statistics.get_summary() if self.statistics else {}
        traffic = self.statistics.get_traffic_by_direction() if self.statistics else {}
        attacks = self.attack_detector.detect_all_attacks() if self.attack_detector else []
        vulnerabilities = self.vulnerability_scanner.scan_all_vulnerabilities() if self.vulnerability_scanner else []
        
        # 调试信息
        if not summary:
            logger.warning(f"summary 为空: statistics={self.statistics is not None}, log_entries={len(self.log_entries)}")
        else:
            logger.info(f"summary 已生成: total_entries={summary.get('total_entries', 0)}")
        
        proxy_analysis = None
        proxy_attacks = None
        if self.proxy_analyzer:
            proxy_analysis = self.proxy_analyzer.analyze_proxy_traffic(self.log_entries)
            proxy_attacks = self.proxy_analyzer.detect_proxy_attacks(self.proxy_analyzer.proxy_entries)
        
        network_info = None
        if self.network_analyzer:
            network_info = self.network_analyzer.get_network_info()
        
        return {
            'network_info': network_info,
            'summary': summary,
            'traffic': traffic,
            'attacks': attacks,
            'vulnerabilities': vulnerabilities,
            'proxy_analysis': proxy_analysis,
            'proxy_attacks': proxy_attacks,
            'processed_data': self.processed_data,  # 统一数据流的结果
        }

