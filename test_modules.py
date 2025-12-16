#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块功能测试脚本
对各个模块和单元功能进行全面测试
"""

import sys
import os
from datetime import datetime
from typing import List, Dict, Any

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """测试所有模块导入"""
    print("=" * 60)
    print("测试 1: 模块导入")
    print("=" * 60)
    
    try:
        from ufw_analyzer import (
            NetworkAnalyzer, UFWLogParser, UFWStatistics,
            AttackDetector, AdvancedAttackDetector, VulnerabilityScanner,
            ProxyAnalyzer, DeviceFingerprint, UFWAnalyzer,
            get_source_type_label, setup_logging
        )
        from type_definitions import (
            LogEntry, StatisticsSummary, AttackResult,
            VulnerabilityResult, ProxyAnalysisResult
        )
        print("✓ 所有模块导入成功")
        return True
    except Exception as e:
        print(f"✗ 导入失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_network_analyzer():
    """测试网络分析器"""
    print("\n" + "=" * 60)
    print("测试 2: NetworkAnalyzer")
    print("=" * 60)
    
    try:
        from ufw_analyzer import NetworkAnalyzer
        
        na = NetworkAnalyzer()
        print("✓ NetworkAnalyzer 初始化成功")
        
        # 测试获取本地接口
        interfaces = na.get_local_interfaces()
        print(f"✓ 获取本地接口: {len(interfaces)} 个接口")
        
        # 测试IP类型判断
        test_ips = ['192.168.1.1', '8.8.8.8', '127.0.0.1', '10.0.0.1']
        for ip in test_ips:
            ip_type = na.get_ip_type(ip)
            print(f"  - {ip}: {ip_type}")
        
        # 测试网络信息
        network_info = na.get_network_info()
        print(f"✓ 获取网络信息: {len(network_info.get('interfaces', []))} 个接口")
        
        return True
    except Exception as e:
        print(f"✗ NetworkAnalyzer 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_log_parser():
    """测试日志解析器"""
    print("\n" + "=" * 60)
    print("测试 3: UFWLogParser")
    print("=" * 60)
    
    try:
        from ufw_analyzer import UFWLogParser
        
        parser = UFWLogParser(log_path="/var/log/ufw.log", read_archived=False)
        print("✓ UFWLogParser 初始化成功")
        
        # 测试解析单行日志
        test_line = "Jan  1 12:00:00 hostname kernel: [UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff SRC=192.168.1.100 DST=192.168.1.1 LEN=60 PROTO=TCP SPT=12345 DPT=80"
        entry = parser.parse_log_line(test_line)
        
        if entry:
            print("✓ 日志解析成功")
            print(f"  - Action: {entry.get('action')}")
            print(f"  - SRC: {entry.get('src_ip')}")
            print(f"  - DST: {entry.get('dst_ip')}")
            print(f"  - Protocol: {entry.get('protocol')}")
            print(f"  - DPT: {entry.get('dst_port')}")
        else:
            print("⚠ 日志解析返回 None（可能是日志格式不匹配）")
        
        return True
    except Exception as e:
        print(f"✗ UFWLogParser 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_statistics():
    """测试统计模块"""
    print("\n" + "=" * 60)
    print("测试 4: UFWStatistics")
    print("=" * 60)
    
    try:
        from ufw_analyzer import UFWStatistics, NetworkAnalyzer
        
        # 创建测试数据
        test_entries = [
            {
                'action': 'ALLOW',
                'protocol': 'TCP',
                'src_ip': '192.168.1.100',
                'dst_ip': '192.168.1.1',
                'dst_port': '80',
                'interface_in': 'eth0',
                'service_type': 'HTTP'
            },
            {
                'action': 'BLOCK',
                'protocol': 'TCP',
                'src_ip': '8.8.8.8',
                'dst_ip': '192.168.1.1',
                'dst_port': '22',
                'interface_in': 'eth0'
            },
            {
                'action': 'ALLOW',
                'protocol': 'UDP',
                'src_ip': '192.168.1.100',
                'dst_ip': '8.8.8.8',
                'dst_port': '53',
                'interface_out': 'eth0',
                'dns_type': 'DNS'
            }
        ]
        
        na = NetworkAnalyzer()
        stats = UFWStatistics(test_entries, na)
        print("✓ UFWStatistics 初始化成功")
        
        # 测试获取摘要
        summary = stats.get_summary()
        print(f"✓ 获取统计摘要: {summary.get('total_entries')} 条记录")
        print(f"  - Actions: {summary.get('actions')}")
        print(f"  - Protocols: {summary.get('protocols')}")
        
        # 测试流量方向统计
        traffic = stats.get_traffic_by_direction()
        print(f"✓ 获取流量方向统计")
        print(f"  - Inbound: {traffic.get('inbound', {})}")
        print(f"  - Outbound: {traffic.get('outbound', {})}")
        
        return True
    except Exception as e:
        print(f"✗ UFWStatistics 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_attack_detector():
    """测试攻击检测器"""
    print("\n" + "=" * 60)
    print("测试 5: AttackDetector")
    print("=" * 60)
    
    try:
        from ufw_analyzer import AttackDetector, NetworkAnalyzer
        
        # 创建测试数据（模拟端口扫描）
        test_entries = []
        for port in range(20, 35):  # 扫描多个端口
            test_entries.append({
                'action': 'BLOCK',
                'protocol': 'TCP',
                'src_ip': '192.168.1.200',
                'dst_ip': '192.168.1.1',
                'dst_port': str(port),
                'interface_in': 'eth0'
            })
        
        na = NetworkAnalyzer()
        detector = AttackDetector(test_entries, na)
        print("✓ AttackDetector 初始化成功")
        
        # 测试端口扫描检测
        port_scan_attacks = detector.detect_port_scan()
        print(f"✓ 端口扫描检测: {len(port_scan_attacks)} 个攻击")
        if port_scan_attacks:
            print(f"  - 检测到攻击: {port_scan_attacks[0].get('type')}")
        
        # 测试暴力破解检测
        brute_force_attacks = detector.detect_brute_force()
        print(f"✓ 暴力破解检测: {len(brute_force_attacks)} 个攻击")
        
        # 测试所有攻击检测
        all_attacks = detector.detect_all_attacks()
        print(f"✓ 所有攻击检测: {len(all_attacks)} 个攻击")
        
        return True
    except Exception as e:
        print(f"✗ AttackDetector 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_advanced_attack_detector():
    """测试高级攻击检测器"""
    print("\n" + "=" * 60)
    print("测试 6: AdvancedAttackDetector")
    print("=" * 60)
    
    try:
        from ufw_analyzer import AdvancedAttackDetector, NetworkAnalyzer
        
        # 创建测试数据（模拟SQL注入）
        test_entries = [
            {
                'action': 'BLOCK',
                'protocol': 'TCP',
                'src_ip': '192.168.1.200',
                'dst_ip': '192.168.1.1',
                'dst_port': '80',
                'raw_line': "[UFW BLOCK] SRC=192.168.1.200 DST=192.168.1.1 DPT=80 PROTO=TCP ' OR 1=1--"
            },
            {
                'action': 'BLOCK',
                'protocol': 'TCP',
                'src_ip': '192.168.1.200',
                'dst_ip': '192.168.1.1',
                'dst_port': '80',
                'raw_line': "[UFW BLOCK] SRC=192.168.1.200 DST=192.168.1.1 DPT=80 PROTO=TCP UNION SELECT * FROM users"
            }
        ]
        
        na = NetworkAnalyzer()
        detector = AdvancedAttackDetector(test_entries, na)
        print("✓ AdvancedAttackDetector 初始化成功")
        
        # 测试注入攻击检测
        injection_attacks = detector.detect_injection_attacks()
        print(f"✓ 注入攻击检测: {len(injection_attacks)} 个攻击")
        if injection_attacks:
            print(f"  - 检测到攻击类型: {injection_attacks[0].get('type')}")
        
        # 测试所有高级攻击检测
        all_advanced_attacks = detector.detect_all_advanced_attacks()
        print(f"✓ 所有高级攻击检测: {len(all_advanced_attacks)} 个攻击")
        
        return True
    except Exception as e:
        print(f"✗ AdvancedAttackDetector 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_proxy_analyzer():
    """测试代理分析器"""
    print("\n" + "=" * 60)
    print("测试 7: ProxyAnalyzer")
    print("=" * 60)
    
    try:
        from ufw_analyzer import ProxyAnalyzer
        
        # 创建测试数据（模拟代理流量）
        test_entries = [
            {
                'action': 'ALLOW',
                'protocol': 'TCP',
                'src_ip': '198.18.0.1',
                'dst_ip': '198.18.0.2',
                'dst_port': '10000',
                'interface_in': 'eth0'
            },
            {
                'action': 'ALLOW',
                'protocol': 'TCP',
                'src_ip': '198.18.0.1',
                'dst_ip': '198.18.0.2',
                'dst_port': '10001',
                'interface_in': 'eth0'
            }
        ]
        
        analyzer = ProxyAnalyzer()
        print("✓ ProxyAnalyzer 初始化成功")
        
        # 测试代理流量分析
        proxy_analysis = analyzer.analyze_proxy_traffic(test_entries)
        print(f"✓ 代理流量分析: {proxy_analysis.get('total_proxy_entries')} 条代理记录")
        print(f"  - 代理类型: {list(proxy_analysis.get('proxy_types', {}).keys())}")
        
        # 测试代理攻击检测
        proxy_attacks = analyzer.detect_proxy_attacks(analyzer.proxy_entries)
        print(f"✓ 代理攻击检测: {len(proxy_attacks)} 个攻击")
        
        return True
    except Exception as e:
        print(f"✗ ProxyAnalyzer 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_device_fingerprint():
    """测试设备指纹"""
    print("\n" + "=" * 60)
    print("测试 8: DeviceFingerprint")
    print("=" * 60)
    
    try:
        from ufw_analyzer import DeviceFingerprint, NetworkAnalyzer
        
        # 创建测试数据
        test_entries = [
            {
                'src_ip': '192.168.1.100',
                'mac': 'aa:bb:cc:dd:ee:ff'
            },
            {
                'src_ip': '192.168.1.100',
                'mac': 'aa:bb:cc:dd:ee:ff'
            },
            {
                'src_ip': '192.168.1.101',
                'mac': '11:22:33:44:55:66'
            }
        ]
        
        na = NetworkAnalyzer()
        df = DeviceFingerprint(na)
        print("✓ DeviceFingerprint 初始化成功")
        
        # 测试分析日志条目
        df.analyze_log_entries(test_entries)
        print("✓ 分析日志条目成功")
        
        # 测试获取设备指纹
        fingerprint = df.get_device_fingerprint('192.168.1.100', 'aa:bb:cc:dd:ee:ff')
        print(f"✓ 获取设备指纹: IP={fingerprint.get('ip')}, MAC={fingerprint.get('mac')}")
        print(f"  - 设备类型: {fingerprint.get('device_type')}")
        print(f"  - IP类型: {fingerprint.get('ip_type')}")
        
        # 测试设备摘要
        summary = df.get_device_summary()
        print(f"✓ 获取设备摘要: {summary.get('total_devices')} 个设备")
        
        return True
    except Exception as e:
        print(f"✗ DeviceFingerprint 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_vulnerability_scanner():
    """测试漏洞扫描器"""
    print("\n" + "=" * 60)
    print("测试 9: VulnerabilityScanner")
    print("=" * 60)
    
    try:
        from ufw_analyzer import VulnerabilityScanner, NetworkAnalyzer
        
        # 创建测试数据（模拟开放的危险端口）
        test_entries = [
            {
                'action': 'ALLOW',
                'protocol': 'TCP',
                'src_ip': '0.0.0.0',
                'dst_ip': '192.168.1.1',
                'dst_port': '22',
                'interface_in': 'eth0'
            },
            {
                'action': 'ALLOW',
                'protocol': 'TCP',
                'src_ip': '0.0.0.0',
                'dst_ip': '192.168.1.1',
                'dst_port': '3306',
                'interface_in': 'eth0'
            }
        ]
        
        na = NetworkAnalyzer()
        scanner = VulnerabilityScanner(test_entries, na, enable_online_db=False)
        print("✓ VulnerabilityScanner 初始化成功")
        
        # 测试扫描开放端口
        open_ports = scanner.scan_open_ports()
        print(f"✓ 扫描开放端口: {len(open_ports)} 个漏洞")
        
        # 测试扫描所有漏洞
        all_vulns = scanner.scan_all_vulnerabilities()
        print(f"✓ 扫描所有漏洞: {len(all_vulns)} 个漏洞")
        
        return True
    except Exception as e:
        print(f"✗ VulnerabilityScanner 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_utility_functions():
    """测试工具函数"""
    print("\n" + "=" * 60)
    print("测试 10: 工具函数")
    print("=" * 60)
    
    try:
        from ufw_analyzer import get_source_type_label, NetworkAnalyzer
        
        na = NetworkAnalyzer()
        print("✓ 工具函数导入成功")
        
        # 测试 get_source_type_label
        test_cases = [
            ('192.168.1.1', na),
            ('8.8.8.8', na),
            (None, na),
            ('192.168.1.1', None)
        ]
        
        for ip, network_analyzer in test_cases:
            label = get_source_type_label(ip, network_analyzer)
            print(f"  - {ip}: {label}")
        
        print("✓ get_source_type_label 测试通过")
        
        return True
    except Exception as e:
        print(f"✗ 工具函数测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_type_definitions():
    """测试类型定义"""
    print("\n" + "=" * 60)
    print("测试 11: 类型定义")
    print("=" * 60)
    
    try:
        from type_definitions import (
            LogEntry, StatisticsSummary, TrafficByDirection,
            AttackResult, VulnerabilityResult, ProxyAnalysisResult,
            DeviceFingerprintResult, NetworkInfo
        )
        print("✓ 所有类型定义导入成功")
        
        # 测试类型定义是否可用
        test_log_entry: LogEntry = {
            'action': 'ALLOW',
            'protocol': 'TCP',
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.1',
            'dst_port': '80',
            'raw_line': 'test'
        }
        print(f"✓ LogEntry 类型测试: {test_log_entry.get('action')}")
        
        return True
    except Exception as e:
        print(f"✗ 类型定义测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """运行所有测试"""
    print("\n" + "=" * 60)
    print("UFW 分析程序 - 模块功能测试")
    print("=" * 60)
    print(f"测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    results = []
    
    # 运行所有测试
    results.append(("模块导入", test_imports()))
    results.append(("网络分析器", test_network_analyzer()))
    results.append(("日志解析器", test_log_parser()))
    results.append(("统计模块", test_statistics()))
    results.append(("攻击检测器", test_attack_detector()))
    results.append(("高级攻击检测器", test_advanced_attack_detector()))
    results.append(("代理分析器", test_proxy_analyzer()))
    results.append(("设备指纹", test_device_fingerprint()))
    results.append(("漏洞扫描器", test_vulnerability_scanner()))
    results.append(("工具函数", test_utility_functions()))
    results.append(("类型定义", test_type_definitions()))
    
    # 输出测试结果摘要
    print("\n" + "=" * 60)
    print("测试结果摘要")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✓ 通过" if result else "✗ 失败"
        print(f"{status}: {name}")
    
    print("\n" + "=" * 60)
    print(f"总计: {passed}/{total} 个测试通过 ({passed*100//total}%)")
    print("=" * 60)
    
    if passed == total:
        print("\n✓ 所有测试通过！")
        return 0
    else:
        print(f"\n⚠ {total - passed} 个测试失败")
        return 1


if __name__ == '__main__':
    sys.exit(main())

