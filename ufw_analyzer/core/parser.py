#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UFW日志解析器
负责读取和解析UFW日志文件
"""

import re
import os
import gzip
import glob
from typing import List, Dict, Optional, Any
import logging

logger = logging.getLogger('ufw_analyzer')


class UFWLogParser:
    """UFW日志解析器"""
    
    # UFW日志格式正则表达式
    # 支持两种时间戳格式：
    # 1. ISO 8601 格式: 2025-12-14T00:00:18.966143+08:00
    # 2. 传统格式: Dec 14 00:00:18
    # 注意：某些字段可能缺失，使用可选匹配
    LOG_PATTERN = re.compile(
        r'(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2})?|\w+\s+\d+\s+\d+:\d+:\d+)\s+'  # 时间戳（支持ISO 8601和传统格式）
        r'(\S+)\s+'  # 主机名
        r'kernel:\s+'  # kernel前缀
        r'\[.*?\]\s+'  # UFW标记
        r'(?:IN=(\S*)\s+)?'  # 入站接口（可选）
        r'(?:OUT=(\S*)\s+)?'  # 出站接口（可选）
        r'(?:MAC=([^\s:]+(?::[^\s:]+)*)\s+)?'  # MAC地址（可选，支持冒号分隔）
        r'(?:SRC=([^\s]+)\s+)?'  # 源IP（可选）
        r'(?:DST=([^\s]+)\s+)?'  # 目标IP（可选）
        r'(?:LEN=(\d+)\s+)?'  # 数据包长度（可选）
        r'(?:PROTO=(\w+)\s+)?'  # 协议（可选）
        r'(?:SPT=(\d+)\s+)?'  # 源端口（可选）
        r'(?:DPT=(\d+)\s+)?'  # 目标端口（可选）
        r'(.*)'  # 其他信息
    )
    
    def __init__(self, log_path: str = "/var/log/ufw.log", read_archived: bool = True):
        """
        初始化日志解析器
        
        Args:
            log_path: 日志文件路径
            read_archived: 是否读取压缩的历史日志文件
        """
        self.log_path = log_path
        self.read_archived = read_archived
        self.log_files_read: List[str] = []
    
    def read_logs(self) -> List[Dict[str, Any]]:
        """
        读取日志文件
        
        Returns:
            日志条目列表
        """
        log_entries = []
        
        # 读取主日志文件
        if os.path.exists(self.log_path):
            try:
                entries = self._read_single_file(self.log_path)
                log_entries.extend(entries)
                self.log_files_read.append(self.log_path)
            except PermissionError as e:
                logger.error(f"无法读取日志文件 {self.log_path}: {e}")
            except Exception as e:
                logger.warning(f"读取日志文件 {self.log_path} 时出错: {e}")
        
        # 读取压缩的历史日志文件
        if self.read_archived:
            archived_pattern = f"{self.log_path}.*.gz"
            archived_files = sorted(glob.glob(archived_pattern), reverse=True)
            
            for archived_file in archived_files:
                try:
                    entries = self._read_single_file(archived_file, compressed=True)
                    log_entries.extend(entries)
                    self.log_files_read.append(archived_file)
                except Exception as e:
                    logger.debug(f"读取压缩日志文件 {archived_file} 时出错: {e}")
        
        return log_entries
    
    def _read_single_file(self, file_path: str, compressed: bool = False) -> List[Dict[str, Any]]:
        """
        读取单个日志文件
        
        Args:
            file_path: 文件路径
            compressed: 是否为压缩文件
        
        Returns:
            日志条目列表
        """
        entries = []
        
        try:
            if compressed:
                file_handle = gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore')
            else:
                file_handle = open(file_path, 'r', encoding='utf-8', errors='ignore')
            
            with file_handle:
                for line_num, line in enumerate(file_handle, 1):
                    entry = self._parse_log_line(line.strip(), line_num)
                    if entry:
                        entries.append(entry)
        
        except PermissionError:
            raise
        except Exception as e:
            logger.warning(f"读取文件 {file_path} 时出错: {e}")
        
        return entries
    
    def _parse_log_line(self, line: str, line_num: int) -> Optional[Dict[str, Any]]:
        """
        解析单行日志
        
        Args:
            line: 日志行
            line_num: 行号
        
        Returns:
            解析后的日志条目字典，如果解析失败则返回None
        """
        if not line or 'UFW' not in line:
            return None
        
        match = self.LOG_PATTERN.search(line)
        if not match:
            return None
        
        try:
            # 提取时间戳（从原始行中提取，因为正则中的时间戳是非捕获组）
            timestamp_match = re.search(
                r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2})?|\w+\s+\d+\s+\d+:\d+:\d+)',
                line
            )
            timestamp = timestamp_match.group(1) if timestamp_match else ''
            
            # 提取其他字段（由于时间戳是非捕获组，group(1)是主机名）
            hostname = match.group(1) if match.group(1) else ''
            interface_in = match.group(2) if len(match.groups()) > 1 and match.group(2) else None
            interface_out = match.group(3) if len(match.groups()) > 2 and match.group(3) else None
            mac_raw = match.group(4) if len(match.groups()) > 3 and match.group(4) else None
            src_ip = match.group(5) if len(match.groups()) > 4 and match.group(5) else None
            
            # 解析MAC地址
            # UFW日志中的MAC字段包含完整的以太网帧头：
            # 格式：目标MAC:源MAC:以太网类型
            # 例如：bc:fc:e7:b6:f0:7d:3c:7c:3f:e0:46:08:08:00
            #       前6段是目标MAC，接下来6段是源MAC，最后2段是以太网类型
            mac = self._parse_mac_address(mac_raw) if mac_raw else None
            dst_ip = match.group(6) if len(match.groups()) > 5 and match.group(6) else None
            length = match.group(7) if len(match.groups()) > 6 and match.group(7) else None
            protocol = match.group(8) if len(match.groups()) > 7 and match.group(8) else None
            src_port = match.group(9) if len(match.groups()) > 8 and match.group(9) else None
            dst_port = match.group(10) if len(match.groups()) > 9 and match.group(10) else None
            extra = match.group(11) if len(match.groups()) > 10 and match.group(11) else ''
            
            # 提取动作（ALLOW/BLOCK/DENY）
            action = 'UNKNOWN'
            if 'ALLOW' in line:
                action = 'ALLOW'
            elif 'BLOCK' in line:
                action = 'BLOCK'
            elif 'DENY' in line:
                action = 'DENY'
            
            # 识别服务类型
            service_type = None
            dns_type = None
            
            if dst_port:
                try:
                    port = int(dst_port)
                    if port == 80:
                        service_type = 'HTTP'
                    elif port == 443:
                        service_type = 'HTTPS'
                    elif port == 53:
                        service_type = 'DNS'
                        dns_type = 'DNS'
                    elif port == 853:
                        service_type = 'DOT'
                        dns_type = 'DOT'
                except ValueError:
                    pass
            
            return {
                'timestamp': timestamp,
                'hostname': hostname,
                'action': action,
                'interface_in': interface_in,
                'interface_out': interface_out,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol,
                'src_port': src_port,
                'dst_port': dst_port,
                'length': length,
                'mac': mac,
                'service_type': service_type,
                'dns_type': dns_type,
                'raw_line': line
            }
        
        except (IndexError, AttributeError) as e:
            logger.debug(f"解析日志行 {line_num} 失败: {e}")
            return None
    
    def _parse_mac_address(self, mac_raw: Optional[str]) -> Optional[str]:
        """
        解析MAC地址
        
        UFW日志中的MAC字段包含完整的以太网帧头：
        - 目标MAC地址（6字节，12个十六进制字符）
        - 源MAC地址（6字节，12个十六进制字符）
        - 以太网类型（2字节，4个十六进制字符，如 08:00 表示IPv4）
        
        例如：bc:fc:e7:b6:f0:7d:3c:7c:3f:e0:46:08:08:00
             前6段是目标MAC，接下来6段是源MAC，最后2段是以太网类型
        
        Args:
            mac_raw: 原始MAC字段值
        
        Returns:
            解析后的源MAC地址（标准格式：XX:XX:XX:XX:XX:XX），如果解析失败则返回None
        """
        if not mac_raw:
            return None
        
        # 按冒号分割
        parts = mac_raw.split(':')
        
        # 标准MAC地址应该是6段（12个字符）
        if len(parts) == 6:
            # 已经是标准格式
            return mac_raw
        
        # UFW日志格式：目标MAC（6段）+ 源MAC（6段）+ 以太网类型（2段）= 14段
        if len(parts) >= 12:
            # 提取源MAC地址（第7-12段，索引6-11）
            src_mac_parts = parts[6:12]
            if len(src_mac_parts) == 6:
                # 验证每段都是2个字符
                if all(len(part) == 2 for part in src_mac_parts):
                    return ':'.join(src_mac_parts)
        
        # 如果格式不符合预期，记录警告并返回原始值
        logger.debug(f"无法解析MAC地址格式: {mac_raw} (共{len(parts)}段)")
        return mac_raw

