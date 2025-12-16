#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
攻击检测模块
包含基础攻击检测器和高级攻击检测器（数据挖掘版）
"""

import re
import logging
import ipaddress
from collections import defaultdict, Counter
from typing import Dict, List, Optional, Any, TYPE_CHECKING

# 类型检查导入（避免循环导入）
if TYPE_CHECKING:
    from ..core.network import NetworkAnalyzer
else:
    NetworkAnalyzer = None

# 导入依赖模块
from ..data.device_fingerprint import DeviceFingerprint
from ..utils.ip_utils import get_source_type_label

# 导入配置模块
try:
    from config import get_config
    _config_available = True
except ImportError:
    _config_available = False

# 获取日志记录器
logger = logging.getLogger('ufw_analyzer')

class AdvancedAttackDetector:
    """高级攻击检测器（数据挖掘版）"""
    
    def __init__(self, log_entries: List[Dict], network_analyzer: Optional[NetworkAnalyzer] = None):
        self.log_entries = log_entries
        self.network_analyzer = network_analyzer
        self.device_fingerprint = DeviceFingerprint(network_analyzer)
        self.device_fingerprint.analyze_log_entries(log_entries)
        
        # 注入攻击特征模式（增强版，预编译正则表达式）
        self.injection_patterns = {
            'sql_injection': [
                # 基础SQL关键字和操作符
                re.compile(r"('|(\\')|(--)|(;)|(\|\|)|(\+)|(\*)|(%)|(union)|(select)|(insert)|(update)|(delete)|(drop)|(exec)|(execute)|(script))", re.IGNORECASE),
                # 逻辑操作符注入
                re.compile(r"(or\s+\d+\s*=\s*\d+)|(and\s+\d+\s*=\s*\d+)|(or\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?)", re.IGNORECASE),
                # UNION注入
                re.compile(r"(union\s+(all\s+)?select)|(select\s+.*\s+from)|(union\s+select\s+.*\s+from)", re.IGNORECASE),
                # 布尔盲注
                re.compile(r"('(or|and).*=.*')|('(or|and)\s+\d+\s*=\s*\d+)", re.IGNORECASE),
                # URL编码的SQL注入
                re.compile(r"((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))", re.IGNORECASE),
                re.compile(r"((\%27)|(\'))((\%55)|u|(\%75))((\%4E)|n|(\%6E))((\%49)|i|(\%69))((\%4F)|o|(\%6F))((\%4E)|n|(\%6E))", re.IGNORECASE),
                # 时间盲注
                re.compile(r"(sleep\s*\(|waitfor\s+delay|benchmark\s*\(|pg_sleep\s*\()", re.IGNORECASE),
                # 堆叠查询
                re.compile(r"(;\s*(select|insert|update|delete|drop|create|alter|exec|execute))", re.IGNORECASE),
                # 注释绕过
                re.compile(r"(--|\#|/\*|\*/|/\*\*/)", re.IGNORECASE),
                # 函数调用注入
                re.compile(r"(concat\s*\(|char\s*\(|ascii\s*\(|substring\s*\(|substr\s*\(|length\s*\(|count\s*\(|version\s*\(|database\s*\()", re.IGNORECASE),
                # 数据库特定函数
                re.compile(r"(load_file\s*\(|into\s+outfile|into\s+dumpfile|xp_cmdshell|sp_executesql)", re.IGNORECASE),
                # 十六进制编码
                re.compile(r"(0x[0-9a-f]+|\\x[0-9a-f]+)", re.IGNORECASE),
                # 双引号注入
                re.compile(r"(\"|%22).*(or|and).*(\"|%22)", re.IGNORECASE),
                # 宽字节注入
                re.compile(r"(%df%27|%df%5c%27)", re.IGNORECASE),
                # 二阶注入
                re.compile(r"(insert\s+into.*values.*select|update.*set.*select)", re.IGNORECASE),
                # 报错注入
                re.compile(r"(extractvalue\s*\(|updatexml\s*\(|floor\s*\(.*rand\s*\(|exp\s*\(.*~)", re.IGNORECASE),
                # 布尔盲注变体
                re.compile(r"('|\")\s*(or|and)\s+('|\")\s*=\s*('|\")", re.IGNORECASE),
                # 数字型注入
                re.compile(r"(\d+\s*(or|and)\s*\d+\s*=\s*\d+|\d+\s*(or|and)\s*\d+\s*>\s*\d+)", re.IGNORECASE),
            ],
            'command_injection': [
                re.compile(r"(;|&|\||`|\$\(|%0a|%0d|%00|%3b|%26|%7c)", re.IGNORECASE),
                re.compile(r"(cmd|command|exec|execute|system|shell|sh|bash|powershell)", re.IGNORECASE),
                re.compile(r"((\%3b)|;)(.*)(ls|cat|pwd|whoami|id|uname)", re.IGNORECASE),
                re.compile(r"((\%26)|&)(.*)(ping|nslookup|traceroute)", re.IGNORECASE),
                re.compile(r"((\%7c)|\|)(.*)(grep|find|awk|sed)", re.IGNORECASE),
            ],
            'xss': [
                re.compile(r"(<script|</script>|javascript:|onerror=|onload=|onclick=|onmouseover=)", re.IGNORECASE),
                re.compile(r"(eval\(|alert\(|document\.cookie|window\.location)", re.IGNORECASE),
                re.compile(r"((\%3C)|<)(.*)((\%3E)|>)", re.IGNORECASE),
                re.compile(r"(vbscript:|data:text/html|base64,)", re.IGNORECASE),
            ],
            'ldap_injection': [
                re.compile(r"(\*|\(|\)|&|\|)", re.IGNORECASE),
                re.compile(r"(cn=|ou=|dc=)", re.IGNORECASE),
            ],
            'xml_injection': [
                re.compile(r"(<!\[CDATA\[|<!DOCTYPE|<!ENTITY)", re.IGNORECASE),
                re.compile(r"(<.*>.*</.*>|<\?xml)", re.IGNORECASE),
            ],
            'path_traversal': [
                re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c)", re.IGNORECASE),
                re.compile(r"(/etc/passwd|/etc/shadow|/proc/|/sys/)", re.IGNORECASE),
                re.compile(r"(c:\\windows\\|c:\\winnt\\)", re.IGNORECASE),
            ]
        }
        
        # 中间人攻击特征
        self.mitm_indicators = {
            'arp_spoofing': {
                'description': 'ARP欺骗攻击',
                'indicators': ['同一IP多个MAC', 'MAC地址频繁变化', '异常ARP响应']
            },
            'dns_spoofing': {
                'description': 'DNS欺骗攻击',
                'indicators': ['DNS响应异常', 'DNS查询模式异常', 'DNS重定向']
            },
            'ssl_stripping': {
                'description': 'SSL剥离攻击',
                'indicators': ['HTTPS降级为HTTP', 'SSL/TLS握手失败', '证书异常']
            }
        }
        
        # 伪装攻击特征
        self.spoofing_patterns = {
            'ip_spoofing': {
                'description': 'IP地址欺骗',
                'indicators': ['同一IP多个MAC地址', '私有IP作为源地址出现在公网', 'IP地址与MAC不匹配']
            },
            'mac_spoofing': {
                'description': 'MAC地址欺骗',
                'indicators': ['MAC地址频繁变化', '同一MAC多个IP', 'MAC地址格式异常']
            },
            'source_routing': {
                'description': '源路由攻击',
                'indicators': ['异常路由路径', '源IP与预期不符']
            }
        }
    
    def _is_mdns_traffic(self, entry: Dict) -> bool:
        """
        判断是否为mDNS正常服务流量
        
        mDNS（多播DNS）特征：
        1. 使用UDP协议
        2. 端口5353
        3. 目标IP通常是多播地址（224.0.0.251）或本地网络
        4. 数据包大小通常较小（DNS查询包，通常<512字节）
        5. 不包含明显的SQL注入特征组合
        
        Args:
            entry: 日志条目
        
        Returns:
            bool: 如果是mDNS正常流量返回True，否则返回False
        """
        dst_port = entry.get('dst_port')
        protocol = entry.get('protocol', '').upper()
        dst_ip = entry.get('dst_ip')
        length = entry.get('length')
        raw_line = entry.get('raw_line', '')
        
        # 检查端口和协议
        if dst_port != '5353' or protocol != 'UDP':
            return False
        
        # 检查目标IP是否为mDNS多播地址
        if dst_ip:
            # mDNS使用多播地址 224.0.0.251 (IPv4) 或 ff02::fb (IPv6)
            mdns_multicast_ips = ['224.0.0.251', 'ff02::fb']
            if dst_ip in mdns_multicast_ips:
                return True
            
            # 检查是否为本地网络地址（mDNS通常在本地网络使用）
            if self.network_analyzer:
                ip_type = self.network_analyzer.get_ip_type(dst_ip)
                if ip_type in ['local', 'switch']:
                    # 进一步检查数据包大小和内容
                    if length:
                        try:
                            pkt_len = int(length)
                            # mDNS查询包通常较小（<512字节）
                            if pkt_len < 512:
                                # 检查是否包含明显的SQL注入特征组合
                                # mDNS查询不应该包含SQL关键字组合
                                sql_keyword_combos = [
                                    r"union\s+select",
                                    r"select\s+.*\s+from",
                                    r"insert\s+into",
                                    r"update\s+.*\s+set",
                                    r"delete\s+from",
                                    r"drop\s+table",
                                    r"exec\s*\(",
                                    r"or\s+\d+\s*=\s*\d+",
                                    r"and\s+\d+\s*=\s*\d+",
                                    r"'\s*or\s*'",
                                    r"'\s*and\s*'"
                                ]
                                
                                # 如果包含SQL关键字组合，不是mDNS
                                for combo in sql_keyword_combos:
                                    if re.search(combo, raw_line, re.IGNORECASE):
                                        return False
                                
                                # 检查是否包含DNS查询特征（mDNS应该包含）
                                dns_patterns = [
                                    r"IN=.*OUT=.*DPT=5353",
                                    r"PROTO=UDP.*DPT=5353",
                                    r"DST=224\.0\.0\.251"
                                ]
                                
                                # 如果包含DNS特征，更可能是mDNS
                                for dns_pattern in dns_patterns:
                                    if re.search(dns_pattern, raw_line, re.IGNORECASE):
                                        return True
                                
                                # 如果数据包很小且没有SQL特征，可能是mDNS
                                if pkt_len < 256:
                                    return True
                        except (ValueError, TypeError):
                            pass
        
        return False
    
    def detect_injection_attacks(self) -> List[Dict]:
        """检测注入攻击（SQL注入、命令注入、XSS等）"""
        injection_attacks = []
        
        # 分析数据包长度模式（注入攻击通常会导致异常的数据包大小）
        ip_port_patterns = defaultdict(lambda: {
            'lengths': [],
            'timestamps': [],
            'blocked_count': 0,
            'total_count': 0,
            'macs': set()
        })
        
        for entry in self.log_entries:
            src_ip = entry.get('src_ip')
            dst_port = entry.get('dst_port')
            length = entry.get('length')
            timestamp = entry.get('timestamp')
            mac = entry.get('mac')
            action = entry.get('action')
            raw_line = entry.get('raw_line', '')
            
            if src_ip and dst_port:
                # 对于端口5353，先判断是否为mDNS正常服务
                if dst_port == '5353' and self._is_mdns_traffic(entry):
                    # 跳过mDNS正常流量，不进行SQL注入检测
                    logger.debug(f"跳过mDNS正常流量: {src_ip} -> {entry.get('dst_ip')}:{dst_port}")
                    continue
                
                key = f"{src_ip}:{dst_port}"
                ip_port_patterns[key]['total_count'] += 1
                if action in ['BLOCK', 'DENY']:
                    ip_port_patterns[key]['blocked_count'] += 1
                if length:
                    try:
                        ip_port_patterns[key]['lengths'].append(int(length))
                    except (ValueError, TypeError) as e:
                        # 记录无效的长度值，但不中断处理
                        logger.debug(f"无效的数据包长度: length={length}, 错误: {e}")
                        pass
                if timestamp:
                    ip_port_patterns[key]['timestamps'].append(timestamp)
                if mac:
                    ip_port_patterns[key]['macs'].add(mac)
                
                # 检查原始日志行中的注入模式
                for injection_type, patterns in self.injection_patterns.items():
                    for pattern in patterns:
                        # 处理预编译的正则表达式和字符串模式
                        if isinstance(pattern, re.Pattern):
                            match = pattern.search(raw_line)
                        else:
                            match = re.search(pattern, raw_line, re.IGNORECASE)
                        
                        if match:
                            # 对于SQL注入，再次确认不是mDNS流量（双重检查）
                            if injection_type == 'sql_injection' and dst_port == '5353':
                                if self._is_mdns_traffic(entry):
                                    logger.debug(f"SQL注入检测：确认为mDNS正常流量，跳过: {src_ip} -> {entry.get('dst_ip')}:{dst_port}")
                                    continue
                            
                            # 判断IP类型
                            source_type = get_source_type_label(src_ip, self.network_analyzer)
                            
                            # 对于SQL注入，进行更详细的分析
                            if injection_type == 'sql_injection':
                                sql_type = self._classify_sql_injection(raw_line, pattern)
                                injection_attacks.append({
                                    'type': f'SQL注入攻击 ({sql_type})',
                                    'source_ip': src_ip,
                                    'source_mac': mac,
                                    'target_port': dst_port,
                                    'source_type': source_type,
                                    'sql_injection_type': sql_type,
                                    'pattern_matched': pattern.pattern if isinstance(pattern, re.Pattern) else pattern,
                                    'matched_text': match.group(0) if match else '',
                                    'raw_line_sample': raw_line[:200] if len(raw_line) > 200 else raw_line,
                                    'severity': self._assess_sql_injection_severity(sql_type, raw_line),
                                    'description': f'检测到SQL注入攻击 ({sql_type})，源IP: {src_ip}, 目标端口: {dst_port}',
                                    'recommendation': self._get_sql_injection_recommendation(sql_type)
                                })
                            else:
                                injection_attacks.append({
                                    'type': f'{injection_type.replace("_", " ").title()} 注入攻击',
                                    'source_ip': src_ip,
                                    'source_mac': mac,
                                    'target_port': dst_port,
                                    'source_type': source_type,
                                    'pattern_matched': pattern.pattern if isinstance(pattern, re.Pattern) else pattern,
                                    'raw_line_sample': raw_line[:200] if len(raw_line) > 200 else raw_line,
                                    'severity': 'critical' if injection_type in ['sql_injection', 'command_injection'] else 'high',
                                    'description': f'检测到{injection_type.replace("_", " ")}攻击模式，源IP: {src_ip}, 目标端口: {dst_port}'
                                })
                            break
        
        # 分析异常数据包长度模式（可能的注入攻击）
        for key, pattern_data in ip_port_patterns.items():
            if pattern_data['blocked_count'] > 10 and len(pattern_data['lengths']) > 5:
                src_ip, dst_port = key.split(':')
                
                # 对于端口5353，排除mDNS正常流量
                if dst_port == '5353':
                    lengths = pattern_data['lengths']
                    avg_length = sum(lengths) / len(lengths) if lengths else 0
                    # mDNS查询包通常较小（<512字节），如果平均大小很小，可能是正常mDNS流量
                    if avg_length < 512:
                        logger.debug(f"端口5353异常模式检测：平均数据包大小 {avg_length:.2f} 字节，可能是mDNS正常流量，跳过")
                        continue
                
                lengths = pattern_data['lengths']
                avg_length = sum(lengths) / len(lengths) if lengths else 0
                std_dev = (sum((x - avg_length) ** 2 for x in lengths) / len(lengths)) ** 0.5 if len(lengths) > 1 else 0
                
                # 异常长度变化可能表示注入攻击
                if std_dev > avg_length * 0.5:  # 标准差超过平均值的50%
                    source_type = get_source_type_label(src_ip, self.network_analyzer)
                    
                    injection_attacks.append({
                        'type': '可能的注入攻击（异常数据包模式）',
                        'source_ip': src_ip,
                        'target_port': dst_port,
                        'source_type': source_type,
                        'blocked_count': pattern_data['blocked_count'],
                        'total_attempts': pattern_data['total_count'],
                        'avg_packet_length': round(avg_length, 2),
                        'std_deviation': round(std_dev, 2),
                        'unique_macs': len(pattern_data['macs']),
                        'severity': 'high',
                        'description': f'检测到异常数据包长度变化模式，可能表示注入攻击尝试'
                    })
        
        # 对SQL注入进行专门的统计分析
        sql_injections = [a for a in injection_attacks if 'SQL注入' in a.get('type', '')]
        if sql_injections:
            sql_stats = self._analyze_sql_injection_statistics(sql_injections)
            # 将统计信息添加到第一个SQL注入攻击记录中
            if sql_injections:
                sql_injections[0]['sql_statistics'] = sql_stats
        
        return injection_attacks
    
    def _classify_sql_injection(self, raw_line: str, pattern: Any) -> str:
        """
        分类SQL注入类型
        
        Args:
            raw_line: 原始日志行
            pattern: 匹配的正则表达式模式
            
        Returns:
            str: SQL注入类型（如：Union注入、布尔盲注、时间盲注等）
        """
        line_lower = raw_line.lower()
        pattern_str = pattern.pattern if isinstance(pattern, re.Pattern) else str(pattern)
        
        # Union注入
        if 'union' in line_lower and 'select' in line_lower:
            return 'Union注入'
        
        # 时间盲注
        if any(keyword in line_lower for keyword in ['sleep', 'waitfor', 'benchmark', 'pg_sleep']):
            return '时间盲注'
        
        # 报错注入
        if any(keyword in line_lower for keyword in ['extractvalue', 'updatexml', 'floor', 'exp']):
            return '报错注入'
        
        # 堆叠查询
        if ';' in line_lower and any(keyword in line_lower for keyword in ['select', 'insert', 'update', 'delete', 'drop']):
            return '堆叠查询注入'
        
        # 布尔盲注
        if ('or' in line_lower or 'and' in line_lower) and ('=' in line_lower or '>' in line_lower or '<' in line_lower):
            return '布尔盲注'
        
        # 二阶注入
        if 'insert' in line_lower and 'select' in line_lower:
            return '二阶注入'
        
        # 宽字节注入
        if '%df%27' in line_lower or '%df%5c%27' in line_lower:
            return '宽字节注入'
        
        # 数字型注入
        if re.search(r'\d+\s*(or|and)\s*\d+', line_lower):
            return '数字型注入'
        
        # 函数调用注入
        if any(keyword in line_lower for keyword in ['load_file', 'into outfile', 'xp_cmdshell']):
            return '函数调用注入（高危）'
        
        # 默认分类
        return 'SQL注入（未分类）'
    
    def _assess_sql_injection_severity(self, sql_type: str, raw_line: str) -> str:
        """
        评估SQL注入的严重程度
        
        Args:
            sql_type: SQL注入类型
            raw_line: 原始日志行
            
        Returns:
            str: 严重程度（critical/high/medium）
        """
        line_lower = raw_line.lower()
        
        # 高危操作
        high_risk_keywords = ['drop', 'delete', 'truncate', 'exec', 'xp_cmdshell', 'load_file', 'into outfile']
        if any(keyword in line_lower for keyword in high_risk_keywords):
            return 'critical'
        
        # 特定类型的高危
        if sql_type in ['函数调用注入（高危）', '堆叠查询注入', '报错注入']:
            return 'critical'
        
        # 中等风险
        if sql_type in ['Union注入', '时间盲注', '布尔盲注']:
            return 'high'
        
        # 默认中等
        return 'medium'
    
    def _get_sql_injection_recommendation(self, sql_type: str) -> str:
        """
        获取SQL注入修复建议
        
        Args:
            sql_type: SQL注入类型
            
        Returns:
            str: 修复建议
        """
        recommendations = {
            'Union注入': '建议：1) 使用参数化查询 2) 输入验证和过滤 3) 最小权限原则 4) WAF防护',
            '布尔盲注': '建议：1) 使用参数化查询 2) 输入验证 3) 错误处理（不暴露数据库错误）4) 日志监控',
            '时间盲注': '建议：1) 使用参数化查询 2) 输入验证 3) 限制查询执行时间 4) 异常检测',
            '报错注入': '建议：1) 使用参数化查询 2) 关闭错误信息显示 3) 自定义错误处理 4) 输入验证',
            '堆叠查询注入': '建议：1) 禁用多语句执行 2) 使用参数化查询 3) 输入验证 4) 严格权限控制',
            '二阶注入': '建议：1) 所有输入都进行验证 2) 使用参数化查询 3) 数据存储前清理 4) 定期安全审计',
            '宽字节注入': '建议：1) 统一字符编码（UTF-8）2) 使用参数化查询 3) 输入验证 4) 转义处理',
            '数字型注入': '建议：1) 类型验证 2) 使用参数化查询 3) 输入范围检查 4) 白名单验证',
            '函数调用注入（高危）': '建议：1) 禁用危险函数 2) 使用参数化查询 3) 严格权限控制 4) 立即修复漏洞',
            'SQL注入（未分类）': '建议：1) 使用参数化查询 2) 输入验证和过滤 3) WAF防护 4) 安全审计'
        }
        return recommendations.get(sql_type, recommendations['SQL注入（未分类）'])
    
    def _analyze_sql_injection_statistics(self, sql_injections: List[Dict]) -> Dict[str, Any]:
        """
        分析SQL注入攻击的统计信息
        
        Args:
            sql_injections: SQL注入攻击列表
            
        Returns:
            Dict[str, Any]: 统计信息
        """
        stats = {
            'total_attacks': len(sql_injections),
            'by_type': Counter(),
            'by_source_ip': Counter(),
            'by_target_port': Counter(),
            'by_severity': Counter(),
            'by_source_type': Counter(),
            'unique_ips': set(),
            'unique_ports': set(),
            'time_distribution': defaultdict(int)
        }
        
        for attack in sql_injections:
            # 按类型统计
            sql_type = attack.get('sql_injection_type', '未知')
            stats['by_type'][sql_type] += 1
            
            # 按源IP统计
            src_ip = attack.get('source_ip', '')
            if src_ip:
                stats['by_source_ip'][src_ip] += 1
                stats['unique_ips'].add(src_ip)
            
            # 按目标端口统计
            dst_port = attack.get('target_port', '')
            if dst_port:
                stats['by_target_port'][dst_port] += 1
                stats['unique_ports'].add(dst_port)
            
            # 按严重程度统计
            severity = attack.get('severity', 'unknown')
            stats['by_severity'][severity] += 1
            
            # 按来源类型统计
            source_type = attack.get('source_type', '未知')
            stats['by_source_type'][source_type] += 1
        
        # 转换为可序列化格式
        return {
            'total_attacks': stats['total_attacks'],
            'unique_source_ips': len(stats['unique_ips']),
            'unique_target_ports': len(stats['unique_ports']),
            'by_type': dict(stats['by_type'].most_common()),
            'by_source_ip': dict(stats['by_source_ip'].most_common(10)),
            'by_target_port': dict(stats['by_target_port'].most_common(10)),
            'by_severity': dict(stats['by_severity']),
            'by_source_type': dict(stats['by_source_type']),
            'top_attackers': [{'ip': ip, 'count': count} for ip, count in stats['by_source_ip'].most_common(5)],
            'top_targets': [{'port': port, 'count': count} for port, count in stats['by_target_port'].most_common(5)]
        }
    
    def detect_mitm_attacks(self) -> List[Dict]:
        """检测中间人攻击（MITM）"""
        mitm_attacks = []
        
        # 1. 检测ARP欺骗（同一IP关联多个MAC地址）
        ip_mac_mapping = defaultdict(set)
        mac_ip_mapping = defaultdict(set)
        
        for entry in self.log_entries:
            src_ip = entry.get('src_ip')
            mac = entry.get('mac')
            
            if src_ip and mac:
                ip_mac_mapping[src_ip].add(mac)
                mac_ip_mapping[mac].add(src_ip)
        
        # 检测IP-MAC异常关联
        for ip, macs in ip_mac_mapping.items():
            if len(macs) > 3:  # 一个IP关联超过3个MAC可能是ARP欺骗
                source_type = get_source_type_label(ip, self.network_analyzer)
                
                mitm_attacks.append({
                    'type': 'ARP欺骗攻击（中间人攻击）',
                    'source_ip': ip,
                    'associated_macs': list(macs),
                    'mac_count': len(macs),
                    'source_type': source_type,
                    'severity': 'critical',
                    'description': f'检测到IP {ip} 关联了 {len(macs)} 个不同的MAC地址，可能是ARP欺骗攻击',
                    'recommendation': '建议：1) 检查ARP表 2) 启用ARP防护 3) 使用静态ARP绑定'
                })
        
        # 2. 检测DNS欺骗（DNS查询模式异常）
        dns_queries = defaultdict(lambda: {
            'count': 0,
            'responses': [],
            'blocked': 0,
            'unique_destinations': set()
        })
        
        for entry in self.log_entries:
            if entry.get('dns_type') or entry.get('dst_port') == '53':
                src_ip = entry.get('src_ip')
                dst_ip = entry.get('dst_ip')
                action = entry.get('action')
                
                if src_ip:
                    dns_queries[src_ip]['count'] += 1
                    if dst_ip:
                        dns_queries[src_ip]['unique_destinations'].add(dst_ip)
                    if action in ['BLOCK', 'DENY']:
                        dns_queries[src_ip]['blocked'] += 1
        
        # 检测异常DNS模式
        for src_ip, dns_data in dns_queries.items():
            if dns_data['blocked'] > 20 and len(dns_data['unique_destinations']) > 5:
                source_type = get_source_type_label(src_ip, self.network_analyzer)
                
                mitm_attacks.append({
                    'type': 'DNS欺骗攻击（中间人攻击）',
                    'source_ip': src_ip,
                    'dns_queries': dns_data['count'],
                    'blocked_queries': dns_data['blocked'],
                    'unique_dns_servers': len(dns_data['unique_destinations']),
                    'source_type': source_type,
                    'severity': 'high',
                    'description': f'检测到来自 {src_ip} 的异常DNS查询模式，可能是DNS欺骗攻击',
                    'recommendation': '建议：1) 使用DNSSEC 2) 检查DNS服务器配置 3) 监控DNS流量'
                })
        
        # 3. 检测SSL/TLS降级攻击
        ssl_patterns = defaultdict(lambda: {
            'https_count': 0,
            'http_count': 0,
            'failed_ssl': 0
        })
        
        for entry in self.log_entries:
            dst_port = entry.get('dst_port')
            src_ip = entry.get('src_ip')
            action = entry.get('action')
            
            if src_ip and dst_port:
                if dst_port == '443':
                    ssl_patterns[src_ip]['https_count'] += 1
                    if action in ['BLOCK', 'DENY']:
                        ssl_patterns[src_ip]['failed_ssl'] += 1
                elif dst_port == '80':
                    ssl_patterns[src_ip]['http_count'] += 1
        
        # 检测SSL剥离模式
        for src_ip, ssl_data in ssl_patterns.items():
            if ssl_data['failed_ssl'] > 10 and ssl_data['http_count'] > ssl_data['https_count']:
                source_type = get_source_type_label(src_ip, self.network_analyzer)
                
                mitm_attacks.append({
                    'type': 'SSL剥离攻击（中间人攻击）',
                    'source_ip': src_ip,
                    'https_attempts': ssl_data['https_count'],
                    'http_attempts': ssl_data['http_count'],
                    'failed_ssl': ssl_data['failed_ssl'],
                    'source_type': source_type,
                    'severity': 'critical',
                    'description': f'检测到来自 {src_ip} 的SSL/TLS降级模式，可能是SSL剥离攻击',
                    'recommendation': '建议：1) 启用HSTS 2) 强制HTTPS 3) 检查SSL证书'
                })
        
        return mitm_attacks
    
    def detect_vulnerability_scanning(self) -> List[Dict]:
        """检测漏洞扫描攻击（增强版数据挖掘）"""
        scan_attacks = []
        
        # 1. 端口扫描模式（多端口快速扫描）
        ip_port_scan = defaultdict(lambda: {
            'ports': set(),
            'timestamps': [],
            'time_window': None,
            'blocked_count': 0,
            'total_count': 0
        })
        
        for entry in self.log_entries:
            src_ip = entry.get('src_ip')
            dst_port = entry.get('dst_port')
            timestamp = entry.get('timestamp')
            action = entry.get('action')
            
            if src_ip and dst_port:
                ip_port_scan[src_ip]['ports'].add(dst_port)
                ip_port_scan[src_ip]['total_count'] += 1
                if action in ['BLOCK', 'DENY']:
                    ip_port_scan[src_ip]['blocked_count'] += 1
                if timestamp:
                    ip_port_scan[src_ip]['timestamps'].append(timestamp)
        
        # 分析扫描模式
        for src_ip, scan_data in ip_port_scan.items():
            port_count = len(scan_data['ports'])
            
            # 计算时间窗口（如果时间戳可用）
            time_window_seconds = None
            if len(scan_data['timestamps']) > 1:
                try:
                    # 简化时间窗口计算
                    timestamps_sorted = sorted(scan_data['timestamps'])
                    first_time = timestamps_sorted[0]
                    last_time = timestamps_sorted[-1]
                    # 这里简化处理，实际应该解析时间戳
                    time_window_seconds = len(scan_data['timestamps'])
                except (ValueError, IndexError, AttributeError) as e:
                    # 记录时间戳处理错误，但不中断处理
                    logger.debug(f"时间戳处理错误: timestamps={scan_data.get('timestamps', [])}, 错误: {e}")
                    pass
            
            # 检测扫描特征
            is_scan = False
            scan_type = None
            severity = 'medium'
            
            if port_count >= 20:
                is_scan = True
                scan_type = '大规模端口扫描'
                severity = 'high'
            elif port_count >= 10:
                is_scan = True
                scan_type = '端口扫描'
                severity = 'medium'
            elif port_count >= 5 and scan_data['blocked_count'] > port_count * 0.8:
                is_scan = True
                scan_type = '针对性端口扫描'
                severity = 'medium'
            
            if is_scan:
                source_type = get_source_type_label(src_ip, self.network_analyzer)
                
                # 获取设备指纹
                device_fp = self.device_fingerprint.get_device_fingerprint(src_ip)
                device_type = device_fp.get('device_type', '未知设备')
                
                scan_attacks.append({
                    'type': scan_type,
                    'source_ip': src_ip,
                    'device_type': device_type,
                    'source_type': source_type,
                    'ports_scanned': port_count,
                    'total_attempts': scan_data['total_count'],
                    'blocked_attempts': scan_data['blocked_count'],
                    'blocked_ratio': round(scan_data['blocked_count'] / scan_data['total_count'] * 100, 2) if scan_data['total_count'] > 0 else 0,
                    'time_window': time_window_seconds,
                    'severity': severity,
                    'description': f'检测到来自 {src_ip} 的漏洞扫描，扫描了 {port_count} 个不同端口'
                })
        
        # 2. 服务枚举攻击（针对特定服务的多次尝试）
        service_enumeration = defaultdict(lambda: defaultdict(int))
        
        for entry in self.log_entries:
            src_ip = entry.get('src_ip')
            dst_port = entry.get('dst_port')
            service_type = entry.get('service_type')
            
            if src_ip and dst_port and service_type:
                key = f"{service_type}:{dst_port}"
                service_enumeration[src_ip][key] += 1
        
        for src_ip, services in service_enumeration.items():
            for service_key, count in services.items():
                if count > 50:  # 对同一服务的多次访问
                    service, port = service_key.split(':')
                    source_type = get_source_type_label(src_ip, self.network_analyzer)
                    
                    scan_attacks.append({
                        'type': '服务枚举攻击',
                        'source_ip': src_ip,
                        'target_service': service,
                        'target_port': port,
                        'source_type': source_type,
                        'enumeration_attempts': count,
                        'severity': 'medium',
                        'description': f'检测到来自 {src_ip} 对 {service} 服务的 {count} 次枚举尝试'
                    })
        
        return scan_attacks
    
    def detect_brute_force_advanced(self) -> List[Dict]:
        """检测暴力破解攻击（增强版数据挖掘）"""
        brute_force_attacks = []
        
        # 1. 基于时间窗口的暴力破解检测
        ip_port_time_patterns = defaultdict(lambda: {'timestamps': [], 'count': 0})
        
        for entry in self.log_entries:
            if entry.get('action') in ['BLOCK', 'DENY']:
                src_ip = entry.get('src_ip')
                dst_port = entry.get('dst_port')
                timestamp = entry.get('timestamp')
                
                if src_ip and dst_port:
                    key = f"{src_ip}:{dst_port}"
                    if timestamp:
                        ip_port_time_patterns[key]['timestamps'].append(timestamp)
                    ip_port_time_patterns[key]['count'] += 1
        
        # 分析时间模式
        for key, pattern_data in ip_port_time_patterns.items():
            if pattern_data['count'] >= 5:  # 至少5次失败尝试
                src_ip, dst_port = key.split(':')
                timestamps = pattern_data['timestamps']
                
                # 计算尝试频率
                if len(timestamps) > 1:
                    # 简化：使用时间戳数量作为频率指标
                    attempt_frequency = len(timestamps)
                else:
                    attempt_frequency = pattern_data['count']
                
                # 判断是否为暴力破解
                is_brute_force = False
                severity = 'medium'
                
                if pattern_data['count'] > 100:
                    is_brute_force = True
                    severity = 'critical'
                elif pattern_data['count'] > 50:
                    is_brute_force = True
                    severity = 'high'
                elif pattern_data['count'] > 20:
                    is_brute_force = True
                    severity = 'high'
                elif pattern_data['count'] >= 5:
                    is_brute_force = True
                    severity = 'medium'
                
                if is_brute_force:
                    # 识别服务类型
                    service = 'Unknown'
                    try:
                        port_num = int(dst_port)
                        service_map = {
                            22: 'SSH', 23: 'Telnet', 3306: 'MySQL',
                            5432: 'PostgreSQL', 3389: 'RDP', 5900: 'VNC',
                            1433: 'MSSQL', 6379: 'Redis', 27017: 'MongoDB',
                            1521: 'Oracle', 5985: 'WinRM', 5986: 'WinRM-HTTPS'
                        }
                        service = service_map.get(port_num, f'Port {dst_port}')
                    except (ValueError, TypeError) as e:
                        # 记录端口转换失败，使用默认服务名
                        logger.debug(f"端口转换失败: dst_port={dst_port}, 错误: {e}")
                        service = f'Port {dst_port}'
                    
                    source_type = get_source_type_label(src_ip, self.network_analyzer)
                    
                    # 获取设备指纹
                    device_fp = self.device_fingerprint.get_device_fingerprint(src_ip)
                    device_type = device_fp.get('device_type', '未知设备')
                    
                    brute_force_attacks.append({
                        'type': '暴力破解攻击',
                        'source_ip': src_ip,
                        'device_type': device_type,
                        'source_type': source_type,
                        'target_port': dst_port,
                        'service': service,
                        'failed_attempts': pattern_data['count'],
                        'attempt_frequency': attempt_frequency,
                        'severity': severity,
                        'description': f'检测到来自 {src_ip} 对 {service} (端口 {dst_port}) 的 {pattern_data["count"]} 次暴力破解尝试'
                    })
        
        # 2. 分布式暴力破解检测（多个IP攻击同一端口）
        port_attackers = defaultdict(set)
        
        for entry in self.log_entries:
            if entry.get('action') in ['BLOCK', 'DENY']:
                src_ip = entry.get('src_ip')
                dst_port = entry.get('dst_port')
                
                if src_ip and dst_port:
                    port_attackers[dst_port].add(src_ip)
        
        for dst_port, attackers in port_attackers.items():
            if len(attackers) >= 10:  # 10个以上不同IP攻击同一端口
                try:
                    port_num = int(dst_port)
                    service_map = {
                        22: 'SSH', 23: 'Telnet', 3306: 'MySQL',
                        5432: 'PostgreSQL', 3389: 'RDP', 5900: 'VNC',
                        1433: 'MSSQL', 6379: 'Redis', 27017: 'MongoDB'
                    }
                    service = service_map.get(port_num, f'Port {dst_port}')
                except (ValueError, TypeError) as e:
                    # 记录端口转换失败，使用默认服务名
                    logger.debug(f"端口转换失败: dst_port={dst_port}, 错误: {e}")
                    service = f'Port {dst_port}'
                
                brute_force_attacks.append({
                    'type': '分布式暴力破解攻击',
                    'target_port': dst_port,
                    'service': service,
                    'unique_attackers': len(attackers),
                    'attacker_ips': list(attackers)[:20],  # 显示前20个
                    'severity': 'critical',
                    'description': f'检测到 {len(attackers)} 个不同IP对 {service} (端口 {dst_port}) 进行分布式暴力破解攻击'
                })
        
        return brute_force_attacks
    
    def detect_spoofing_attacks(self) -> List[Dict]:
        """检测伪装攻击（IP欺骗、MAC欺骗等）"""
        spoofing_attacks = []
        
        # 1. IP欺骗检测
        ip_mac_relations = defaultdict(set)
        mac_ip_relations = defaultdict(set)
        
        for entry in self.log_entries:
            src_ip = entry.get('src_ip')
            mac = entry.get('mac')
            
            if src_ip and mac:
                ip_mac_relations[src_ip].add(mac)
                mac_ip_relations[mac].add(src_ip)
        
        # 检测IP欺骗（一个IP关联多个MAC）
        for ip, macs in ip_mac_relations.items():
            if len(macs) > 3:
                source_type = get_source_type_label(ip, self.network_analyzer)
                
                spoofing_attacks.append({
                    'type': 'IP地址欺骗攻击',
                    'spoofed_ip': ip,
                    'associated_macs': list(macs),
                    'mac_count': len(macs),
                    'source_type': source_type,
                    'severity': 'critical',
                    'description': f'检测到IP {ip} 关联了 {len(macs)} 个不同MAC地址，可能是IP欺骗攻击',
                    'recommendation': '建议：1) 启用IP源地址验证 2) 使用静态ARP绑定 3) 监控ARP表变化'
                })
        
        # 2. MAC欺骗检测（一个MAC关联多个IP）
        for mac, ips in mac_ip_relations.items():
            if len(ips) > 5:  # 一个MAC关联超过5个IP可能是MAC欺骗
                spoofing_attacks.append({
                    'type': 'MAC地址欺骗攻击',
                    'spoofed_mac': mac,
                    'associated_ips': list(ips)[:20],  # 显示前20个
                    'ip_count': len(ips),
                    'severity': 'high',
                    'description': f'检测到MAC {mac} 关联了 {len(ips)} 个不同IP地址，可能是MAC欺骗攻击',
                    'recommendation': '建议：1) 检查网络设备配置 2) 启用端口安全 3) 监控MAC地址表'
                })
        
        # 3. 源路由攻击检测（私有IP出现在公网流量中）
        # 注意：排除网关IP的正常NAT流量，只检测非网关的私有IP访问公网
        if self.network_analyzer:
            private_ip_as_source = []
            gateway_ip = None
            
            # 获取网关IP
            network_info = self.network_analyzer.get_network_info()
            gateway_ip = network_info.get('gateway_ip')
            
            for entry in self.log_entries:
                src_ip = entry.get('src_ip')
                dst_ip = entry.get('dst_ip')
                
                if src_ip and dst_ip:
                    src_type = self.network_analyzer.get_ip_type(src_ip)
                    dst_type = self.network_analyzer.get_ip_type(dst_ip)
                    
                    # 排除网关IP（网关访问公网是正常的NAT行为）
                    if src_ip == gateway_ip:
                        continue
                    
                    # 私有IP作为源，目标是公网IP
                    # 只检测非网关的私有IP，且目标必须是真正的公网IP（排除组播地址等）
                    if src_type in ['local', 'switch'] and dst_type == 'internet':
                        # 排除组播地址（224.0.0.0/4）和其他特殊地址
                        try:
                            dst_ip_obj = ipaddress.ip_address(dst_ip)
                            # 排除组播地址、链路本地地址等
                            if dst_ip_obj.is_multicast or dst_ip_obj.is_link_local or dst_ip_obj.is_reserved:
                                continue
                        except (ValueError, ipaddress.AddressValueError):
                            continue
                        
                        private_ip_as_source.append({
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'entry': entry
                        })
            
            # 更严格的检测条件：
            # 1. 必须有多个不同的私有IP访问公网（单个IP可能是配置错误）
            # 2. 总尝试次数要足够多
            # 3. 排除只有网关IP的情况
            if len(private_ip_as_source) > 100:
                unique_src_ips = set(e['src_ip'] for e in private_ip_as_source)
                
                # 如果只有一个私有IP，且是网关，则跳过（已在上面排除）
                # 如果只有一个非网关私有IP，可能是配置错误而非攻击
                if len(unique_src_ips) > 1:
                    # 分析目标IP分布
                    dst_ips = Counter(e['dst_ip'] for e in private_ip_as_source)
                    unique_dst_ips = len(dst_ips)
                    
                    # 如果多个私有IP访问大量不同的公网IP，更可能是攻击
                    # 如果多个私有IP访问少数几个公网IP，可能是正常的NAT或配置问题
                    spoofing_attacks.append({
                        'type': '源路由攻击（IP伪装）',
                        'unique_spoofed_ips': len(unique_src_ips),
                        'total_attempts': len(private_ip_as_source),
                        'unique_destination_ips': unique_dst_ips,
                        'sample_ips': list(unique_src_ips)[:10],
                        'severity': 'high' if len(unique_src_ips) > 10 else 'medium',
                        'description': f'检测到 {len(unique_src_ips)} 个非网关私有IP地址作为源地址访问公网，可能是源路由攻击',
                        'recommendation': '建议：1) 启用反向路径转发(RPF) 2) 过滤私有IP源地址 3) 检查路由配置 4) 确认这些IP的实际用途',
                        'diagnostic_info': {
                            'gateway_ip': gateway_ip,
                            'excluded_gateway': True,
                            'destination_ip_distribution': dict(dst_ips.most_common(10))
                        }
                    })
                elif len(unique_src_ips) == 1:
                    # 单个非网关私有IP访问公网，可能是配置错误
                    single_ip = list(unique_src_ips)[0]
                    logger.warning(f"检测到单个非网关私有IP {single_ip} 访问公网，可能是配置错误而非攻击")
        
        return spoofing_attacks
    
    def detect_all_advanced_attacks(self) -> List[Dict]:
        """检测所有高级攻击类型"""
        all_attacks = []
        
        print("  正在检测注入攻击...")
        all_attacks.extend(self.detect_injection_attacks())
        
        print("  正在检测中间人攻击...")
        all_attacks.extend(self.detect_mitm_attacks())
        
        print("  正在检测漏洞扫描...")
        all_attacks.extend(self.detect_vulnerability_scanning())
        
        print("  正在检测暴力破解攻击...")
        all_attacks.extend(self.detect_brute_force_advanced())
        
        print("  正在检测伪装攻击...")
        all_attacks.extend(self.detect_spoofing_attacks())
        
        return all_attacks


class AttackDetector:
    """
    网络攻击检测器（增强版）
    
    检测各种网络攻击模式，包括端口扫描、暴力破解、DoS攻击等。
    使用配置模块管理检测阈值和端口映射。
    """
    
    def __init__(self, log_entries: List[Dict], network_analyzer: Optional[NetworkAnalyzer] = None):
        """
        初始化攻击检测器
        
        Args:
            log_entries: UFW日志条目列表
            network_analyzer: 网络分析器实例，用于IP类型判断
        """
        self.log_entries = log_entries
        self.network_analyzer = network_analyzer
        self.device_fingerprint = DeviceFingerprint(network_analyzer)
        self.device_fingerprint.analyze_log_entries(log_entries)
        self.attacks: List[Dict[str, Any]] = []
        
        # 获取配置
        if _config_available:
            try:
                self.config = get_config()
                self.thresholds = self.config.detection_thresholds
                self.port_mappings = self.config.port_mappings
                # 从配置中获取危险端口映射（用于兼容性）
                if self.port_mappings and hasattr(self.port_mappings, 'dangerous_ports'):
                    self.DANGEROUS_PORTS = self.port_mappings.dangerous_ports
                else:
                    # 如果配置不可用，使用默认值
                    self.DANGEROUS_PORTS = {
                        22: 'SSH', 23: 'Telnet', 80: 'HTTP', 443: 'HTTPS',
                        3306: 'MySQL', 5432: 'PostgreSQL', 3389: 'RDP',
                        5900: 'VNC', 1433: 'MSSQL', 27017: 'MongoDB',
                        6379: 'Redis', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt'
                    }
            except Exception as e:
                logger.warning(f"配置加载失败，使用默认值: {e}")
                self.config = None
                self.thresholds = None
                self.port_mappings = None
                self.DANGEROUS_PORTS = {
                    22: 'SSH', 23: 'Telnet', 80: 'HTTP', 443: 'HTTPS',
                    3306: 'MySQL', 5432: 'PostgreSQL', 3389: 'RDP',
                    5900: 'VNC', 1433: 'MSSQL', 27017: 'MongoDB',
                    6379: 'Redis', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt'
                }
        else:
            # 回退到硬编码值
            self.thresholds = None
            self.port_mappings = None
            # 保留旧的危险端口映射作为回退
            self.DANGEROUS_PORTS = {
                22: 'SSH', 23: 'Telnet', 80: 'HTTP', 443: 'HTTPS',
                3306: 'MySQL', 5432: 'PostgreSQL', 3389: 'RDP',
                5900: 'VNC', 1433: 'MSSQL', 27017: 'MongoDB',
                6379: 'Redis', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt'
            }
        
        # 初始化高级攻击检测器
        self.advanced_detector = AdvancedAttackDetector(log_entries, network_analyzer)
    
    def detect_port_scan(self, threshold: Optional[int] = None) -> List['AttackResult']:
        """
        检测端口扫描攻击
        
        Args:
            threshold: 端口扫描阈值，如果为None则使用配置中的默认值
            
        Returns:
            List[Dict[str, Any]]: 检测到的端口扫描攻击列表，每个元素包含：
                - type: 攻击类型
                - source_ip: 源IP地址
                - source_type: 源IP类型（交换机/网关、本地网络、互联网）
                - ports_scanned: 扫描的端口数量
                - ports: 扫描的端口列表
                - severity: 严重程度（high/medium）
        """
        # 使用配置中的阈值或传入的阈值
        if threshold is None:
            threshold = self.thresholds.port_scan if self.thresholds else 10
        high_threshold = self.thresholds.port_scan_high if self.thresholds else 50
        
        # 统计每个源 IP 访问的不同目标端口数量
        ip_port_combinations: Dict[str, Set[str]] = defaultdict(set)
        
        for entry in self.log_entries:
            if entry.get('src_ip') and entry.get('dst_port'):
                ip_port_combinations[entry['src_ip']].add(entry['dst_port'])
        
        port_scans: List[Dict[str, Any]] = []
        for ip, ports in ip_port_combinations.items():
            if len(ports) >= threshold:
                # 判断IP类型
                source_type = get_source_type_label(ip, self.network_analyzer)
                
                port_scans.append({
                    'type': '端口扫描',
                    'source_ip': ip,
                    'source_type': source_type,
                    'ports_scanned': len(ports),
                    'ports': sorted(list(ports)),
                    'severity': 'high' if len(ports) > high_threshold else 'medium'
                })
        
        return port_scans
    
    def detect_brute_force(self, threshold: Optional[int] = None) -> List['AttackResult']:
        """
        检测暴力破解攻击（针对同一端口的多次失败尝试）
        
        Args:
            threshold: 暴力破解阈值，如果为None则使用配置中的默认值
            
        Returns:
            List[Dict[str, Any]]: 检测到的暴力破解攻击列表，每个元素包含：
                - type: 攻击类型
                - source_ip: 源IP地址
                - source_type: 源IP类型
                - target_port: 目标端口
                - service: 服务名称
                - attempts: 失败尝试次数
                - severity: 严重程度
        """
        # 使用配置中的阈值或传入的阈值
        if threshold is None:
            threshold = self.thresholds.brute_force if self.thresholds else 5
        high_threshold = self.thresholds.brute_force_high if self.thresholds else 100
        medium_threshold = self.thresholds.brute_force_medium if self.thresholds else 20
        
        # 统计每个源 IP 对同一目标端口的失败连接次数
        failed_attempts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        
        for entry in self.log_entries:
            if entry.get('action') in ['BLOCK', 'DENY']:
                src_ip = entry.get('src_ip')
                dst_port = entry.get('dst_port')
                if src_ip and dst_port:
                    failed_attempts[src_ip][dst_port] += 1
        
        brute_force_attacks: List[Dict[str, Any]] = []
        for src_ip, ports in failed_attempts.items():
            for port, count in ports.items():
                if count >= threshold:
                    # 获取服务名称
                    if self.port_mappings:
                        service = self.port_mappings.dangerous_ports.get(int(port), f'Port {port}')
                    else:
                        service = self.DANGEROUS_PORTS.get(int(port), f'Port {port}')
                    
                    # 判断IP类型
                    source_type = get_source_type_label(src_ip, self.network_analyzer)
                    
                    # 确定严重程度
                    if count > high_threshold:
                        severity = 'high'
                    elif count > medium_threshold:
                        severity = 'medium'
                    else:
                        severity = 'low'
                    
                    brute_force_attacks.append({
                        'type': '暴力破解',
                        'source_ip': src_ip,
                        'source_type': source_type,
                        'target_port': port,
                        'service': service,
                        'attempts': count,
                        'severity': severity
                    })
        
        return brute_force_attacks
    
    def detect_dos_attacks(self) -> List['AttackResult']:
        """检测拒绝服务攻击（增强版，结合IP-MAC设备指纹）"""
        dos_attacks = []
        
        # 按IP-MAC组合统计被阻止的请求
        device_requests = defaultdict(lambda: {
            'ip': None,
            'mac': None,
            'blocked_count': 0,
            'total_count': 0,
            'ports': set(),
            'target_ips': set(),
            'protocols': Counter()
        })
        
        # 按IP统计（用于对比）
        ip_only_stats = defaultdict(lambda: {
            'blocked_count': 0,
            'total_count': 0,
            'unique_macs': set()
        })
        
        for entry in self.log_entries:
            src_ip = entry.get('src_ip')
            mac = entry.get('mac')
            action = entry.get('action')
            dst_port = entry.get('dst_port')
            dst_ip = entry.get('dst_ip')
            protocol = entry.get('protocol')
            
            if src_ip:
                # IP统计
                ip_only_stats[src_ip]['total_count'] += 1
                if mac:
                    ip_only_stats[src_ip]['unique_macs'].add(mac)
                if action in ['BLOCK', 'DENY']:
                    ip_only_stats[src_ip]['blocked_count'] += 1
                
                # 设备指纹统计（IP-MAC组合）
                device_key = f"{src_ip}_{mac}" if mac else src_ip
                device = device_requests[device_key]
                device['ip'] = src_ip
                device['mac'] = mac
                device['total_count'] += 1
                
                if action in ['BLOCK', 'DENY']:
                    device['blocked_count'] += 1
                
                if dst_port:
                    device['ports'].add(dst_port)
                if dst_ip:
                    device['target_ips'].add(dst_ip)
                if protocol:
                    device['protocols'][protocol] += 1
        
        # 分析DoS特征
        for device_key, device in device_requests.items():
            blocked_count = device['blocked_count']
            total_count = device['total_count']
            blocked_ratio = blocked_count / total_count if total_count > 0 else 0
            
            # DoS攻击特征：
            # 1. 大量被阻止的请求（>500）
            # 2. 高阻止率（>80%）且请求数>100
            # 3. 针对多个目标IP和端口（分布式攻击特征）
            # 4. 短时间内大量请求
            
            is_dos = False
            dos_type = None
            severity = 'medium'
            
            if blocked_count > 1000:
                is_dos = True
                dos_type = '大规模DoS攻击'
                severity = 'critical'
            elif blocked_count > 500:
                is_dos = True
                dos_type = 'DoS攻击'
                severity = 'high'
            elif blocked_count > 200 and blocked_ratio > 0.8:
                is_dos = True
                dos_type = '可能的DoS攻击'
                severity = 'high'
            elif blocked_count > 100 and len(device['target_ips']) > 10:
                is_dos = True
                dos_type = '分布式DoS攻击'
                severity = 'high'
            
            if is_dos:
                src_ip = device['ip']
                mac = device['mac']
                
                # 获取设备指纹信息
                device_fingerprint = None
                device_type = '未知设备'
                if mac:
                    device_fingerprint = self.device_fingerprint.get_device_fingerprint(src_ip, mac)
                    device_type = device_fingerprint.get('device_type', '未知设备')
                elif src_ip:
                    device_fingerprint = self.device_fingerprint.get_device_fingerprint(src_ip)
                    device_type = device_fingerprint.get('device_type', '未知设备')
                
                # 获取IP类型
                source_type = get_source_type_label(src_ip, self.network_analyzer)
                
                # 检查是否为IP欺骗（同一IP关联多个MAC）
                ip_stats = ip_only_stats.get(src_ip, {})
                unique_macs = len(ip_stats.get('unique_macs', set()))
                is_spoofing = unique_macs > 3  # 一个IP关联超过3个MAC可能是IP欺骗
                
                attack_info = {
                    'type': dos_type,
                    'source_ip': src_ip,
                    'source_mac': mac,
                    'source_type': source_type,
                    'device_type': device_type,
                    'blocked_attempts': blocked_count,
                    'total_attempts': total_count,
                    'blocked_ratio': round(blocked_ratio * 100, 2),
                    'target_ports_count': len(device['ports']),
                    'target_ips_count': len(device['target_ips']),
                    'top_ports': sorted(list(device['ports']))[:10],
                    'top_protocols': dict(device['protocols'].most_common(5)),
                    'severity': severity,
                    'is_ip_spoofing': is_spoofing,
                    'unique_macs_for_ip': unique_macs
                }
                
                if is_spoofing:
                    attack_info['warning'] = f'检测到IP欺骗：{src_ip} 关联了 {unique_macs} 个不同的MAC地址'
                
                dos_attacks.append(attack_info)
        
        # 检测环路风暴（Loop Storm）
        # 环路风暴特征：
        # 1. 相同的数据包（相同源IP、目标IP、端口、协议、数据包长度）在短时间内大量重复
        # 2. 时间间隔非常短且规律
        # 3. 可能涉及广播/组播地址
        # 4. 数据包长度相同或非常相似
        loop_storm_attacks = self._detect_loop_storm()
        dos_attacks.extend(loop_storm_attacks)
        
        return dos_attacks
    
    def _detect_loop_storm(self) -> List['AttackResult']:
        """检测环路风暴（Loop Storm）"""
        loop_storm_attacks = []
        
        # 按数据包特征分组（源IP、目标IP、端口、协议、数据包长度）
        packet_signatures = defaultdict(lambda: {
            'count': 0,
            'timestamps': [],
            'macs': set(),
            'actions': Counter(),
            'entries': []
        })
        
        # 广播/组播地址
        broadcast_ips = ['255.255.255.255', '0.0.0.0']
        multicast_range = ipaddress.ip_network('224.0.0.0/4')
        
        for entry in self.log_entries:
            src_ip = entry.get('src_ip')
            dst_ip = entry.get('dst_ip')
            dst_port = entry.get('dst_port', '')
            protocol = entry.get('protocol', 'UNKNOWN')
            length = entry.get('length', '0')
            mac = entry.get('mac', '')
            timestamp = entry.get('timestamp', '')
            action = entry.get('action', 'UNKNOWN')
            
            if not src_ip or not dst_ip:
                continue
            
            # 创建数据包签名（用于识别相同的数据包）
            packet_signature = f"{src_ip}:{dst_ip}:{dst_port}:{protocol}:{length}"
            
            packet_data = packet_signatures[packet_signature]
            packet_data['count'] += 1
            packet_data['timestamps'].append(timestamp)
            if mac:
                packet_data['macs'].add(mac)
            packet_data['actions'][action] += 1
            packet_data['entries'].append(entry)
        
        # 分析环路风暴特征
        for signature, packet_data in packet_signatures.items():
            count = packet_data['count']
            
            # 环路风暴阈值：相同数据包出现超过50次
            if count < 50:
                continue
            
            # 解析签名
            parts = signature.split(':')
            if len(parts) < 5:
                continue
            
            src_ip = parts[0]
            dst_ip = parts[1]
            dst_port = parts[2]
            protocol = parts[3]
            length = parts[4]
            
            # 检查是否为广播/组播地址
            is_broadcast = dst_ip in broadcast_ips
            is_multicast = False
            try:
                dst_ip_obj = ipaddress.ip_address(dst_ip)
                is_multicast = dst_ip_obj in multicast_range
            except (ValueError, ipaddress.AddressValueError):
                pass
            
            # 计算时间间隔（如果时间戳可用）
            time_intervals = []
            timestamps = sorted([t for t in packet_data['timestamps'] if t])
            
            if len(timestamps) > 1:
                # 简化处理：计算时间戳数量，如果时间戳非常密集，可能是环路风暴
                # 实际应该解析时间戳计算真实间隔
                timestamp_density = len(timestamps) / max(len(timestamps), 1)
            else:
                timestamp_density = 0
            
            # 排除正常流量：
            # 1. 网关到主机的正常通信（可能是正常的网络流量）
            # 2. 正常的组播流量（如IGMP 224.0.0.1, 224.0.0.2等）
            # 3. 正常的广播流量（如DHCP等）
            
            # 获取网络信息
            gateway_ip = None
            host_ip = None
            if self.network_analyzer:
                network_info = self.network_analyzer.get_network_info()
                gateway_ip = network_info.get('gateway_ip')
                host_ip = network_info.get('host_ip')
            
            # 检查是否为正常流量
            is_normal_traffic = False
            
            # 1. 网关到主机的正常通信
            if src_ip == gateway_ip and dst_ip == host_ip:
                is_normal_traffic = True
            # 2. 主机到网关的正常通信
            elif src_ip == host_ip and dst_ip == gateway_ip:
                is_normal_traffic = True
            # 3. 正常的IGMP组播流量（224.0.0.1, 224.0.0.2等）
            elif is_multicast and dst_ip in ['224.0.0.1', '224.0.0.2', '224.0.0.22']:
                # IGMP组播流量，如果重复次数不是特别高，可能是正常的
                if count < 2000:  # 正常IGMP流量通常不会超过2000次
                    is_normal_traffic = True
            # 4. 正常的DHCP广播流量
            elif is_broadcast and dst_port in ['67', '68']:
                is_normal_traffic = True
            
            # 如果判断为正常流量，跳过
            if is_normal_traffic:
                continue
            
            # 环路风暴判断条件：
            # 1. 相同数据包出现次数 > 阈值
            # 2. 时间戳密度高（短时间内大量重复）
            # 3. 涉及广播/组播地址（常见于环路风暴）
            # 4. 数据包长度相同（相同数据包特征）
            # 5. 多个MAC地址（可能表示数据包在网络中循环）
            # 6. 高阻止率（如果是被阻止的流量，更可能是攻击）
            
            # 计算阻止率
            blocked_count = packet_data['actions'].get('BLOCK', 0) + packet_data['actions'].get('DENY', 0)
            blocked_ratio = blocked_count / count if count > 0 else 0
            
            is_loop_storm = False
            severity = 'medium'
            loop_storm_type = None
            
            # 高置信度环路风暴：
            # 1. 涉及广播/组播 + 大量重复 + 高阻止率
            if (is_broadcast or is_multicast) and count > 500 and blocked_ratio > 0.8:
                is_loop_storm = True
                loop_storm_type = '广播/组播环路风暴'
                severity = 'critical'
            # 2. 大量相同数据包 + 多个MAC地址 + 高阻止率
            elif count > 1000 and len(packet_data['macs']) > 2 and blocked_ratio > 0.7:
                is_loop_storm = True
                loop_storm_type = '环路风暴（多MAC地址）'
                severity = 'critical'
            # 中等置信度：大量相同数据包 + 高阻止率
            elif count > 500 and blocked_ratio > 0.8:
                is_loop_storm = True
                loop_storm_type = '可能的环路风暴'
                severity = 'high'
            # 低置信度：大量相同数据包（但阻止率较低，可能是正常流量）
            elif count > 2000:
                is_loop_storm = True
                loop_storm_type = '疑似环路风暴（需进一步确认）'
                severity = 'medium'
            
            if is_loop_storm:
                # 获取源IP类型
                source_type = get_source_type_label(src_ip, self.network_analyzer)
                
                # 分析目标IP类型
                dst_type = 'unknown'
                if self.network_analyzer:
                    dst_type = self.network_analyzer.get_ip_type(dst_ip)
                
                attack_info = {
                    'type': loop_storm_type,
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'destination_port': dst_port if dst_port else 'N/A',
                    'protocol': protocol,
                    'packet_length': length,
                    'source_type': source_type,
                    'destination_type': dst_type,
                    'repetition_count': count,
                    'blocked_count': blocked_count,
                    'blocked_ratio': round(blocked_ratio * 100, 2),
                    'unique_macs': len(packet_data['macs']),
                    'is_broadcast': is_broadcast,
                    'is_multicast': is_multicast,
                    'timestamp_density': timestamp_density,
                    'actions': dict(packet_data['actions']),
                    'severity': severity,
                    'description': f'检测到相同数据包重复 {count} 次（阻止率 {blocked_ratio*100:.1f}%），可能是环路风暴',
                    'recommendation': '建议：1) 检查网络拓扑，查找环路 2) 检查交换机配置，启用STP/RSTP 3) 检查网络设备状态 4) 隔离受影响网段 5) 检查是否有网络设备故障'
                }
                
                # 添加详细信息
                if is_broadcast:
                    attack_info['warning'] = '涉及广播地址，典型的环路风暴特征'
                elif is_multicast:
                    attack_info['warning'] = '涉及组播地址，可能是组播环路'
                
                if len(packet_data['macs']) > 3:
                    attack_info['warning'] = (attack_info.get('warning', '') + 
                                            f' 检测到 {len(packet_data["macs"])} 个不同MAC地址，表明数据包在网络中循环').strip()
                
                loop_storm_attacks.append(attack_info)
        
        return loop_storm_attacks
    
    def detect_suspicious_activity(self) -> List['AttackResult']:
        """检测可疑活动（增强版，结合设备指纹）"""
        suspicious = []
        
        # 检测对危险端口的访问尝试
        dangerous_port_attempts = defaultdict(lambda: {
            'count': 0,
            'mac': None,
            'device_type': None
        })
        
        for entry in self.log_entries:
            if entry.get('action') in ['BLOCK', 'DENY']:
                dst_port = entry.get('dst_port')
                src_ip = entry.get('src_ip')
                mac = entry.get('mac')
                
                if dst_port and src_ip:
                    try:
                        if int(dst_port) in self.DANGEROUS_PORTS:
                            key = src_ip
                            dangerous_port_attempts[key]['count'] += 1
                            dangerous_port_attempts[key]['mac'] = mac
                            
                            # 获取设备类型
                            if mac:
                                device_fp = self.device_fingerprint.get_device_fingerprint(src_ip, mac)
                                dangerous_port_attempts[key]['device_type'] = device_fp.get('device_type', '未知')
                    except (ValueError, TypeError):
                        pass
        
        for ip, info in dangerous_port_attempts.items():
            if info['count'] >= 3:
                source_type = get_source_type_label(ip, self.network_analyzer)
                
                suspicious.append({
                    'type': '可疑端口访问',
                    'source_ip': ip,
                    'source_mac': info['mac'],
                    'source_type': source_type,
                    'device_type': info['device_type'],
                    'attempts': info['count'],
                    'severity': 'medium'
                })
        
        # 检测异常流量模式（结合设备指纹）
        ip_activity = defaultdict(lambda: {
            'blocked_count': 0,
            'macs': set(),
            'device_types': set()
        })
        
        for entry in self.log_entries:
            if entry.get('action') in ['BLOCK', 'DENY']:
                src_ip = entry.get('src_ip')
                mac = entry.get('mac')
                if src_ip:
                    ip_activity[src_ip]['blocked_count'] += 1
                    if mac:
                        ip_activity[src_ip]['macs'].add(mac)
                        device_fp = self.device_fingerprint.get_device_fingerprint(src_ip, mac)
                        device_type = device_fp.get('device_type', '未知')
                        ip_activity[src_ip]['device_types'].add(device_type)
        
        for ip, info in ip_activity.items():
            if info['blocked_count'] > 100:
                source_type = get_source_type_label(ip, self.network_analyzer)
                
                suspicious.append({
                    'type': '异常流量',
                    'source_ip': ip,
                    'source_type': source_type,
                    'blocked_attempts': info['blocked_count'],
                    'unique_macs': len(info['macs']),
                    'device_types': list(info['device_types']),
                    'severity': 'high',
                    'warning': f'检测到来自 {ip} 的大量被阻止请求，关联了 {len(info["macs"])} 个MAC地址' if len(info['macs']) > 1 else None
                })
        
        return suspicious
    
    def detect_all_attacks(self) -> List[Dict]:
        """检测所有类型的攻击（增强版，包含DoS检测和高级数据挖掘）"""
        all_attacks = []
        
        # 基础攻击检测
        all_attacks.extend(self.detect_port_scan())
        all_attacks.extend(self.detect_brute_force())
        all_attacks.extend(self.detect_dos_attacks())
        all_attacks.extend(self.detect_suspicious_activity())
        
        # 高级攻击检测（数据挖掘）
        advanced_attacks = self.advanced_detector.detect_all_advanced_attacks()
        all_attacks.extend(advanced_attacks)
        
        self.attacks = all_attacks
        return all_attacks

