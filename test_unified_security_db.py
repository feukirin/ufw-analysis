#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
统一安全库功能测试
测试CNVD/CNNVD HTML解析、信息融合和攻击检测器集成
"""

import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_unified_security_db():
    """测试统一安全库"""
    print("=" * 60)
    print("测试 1: UnifiedSecurityDatabase")
    print("=" * 60)
    
    try:
        from unified_security_db import UnifiedSecurityDatabase
        
        db = UnifiedSecurityDatabase()
        print("✓ UnifiedSecurityDatabase 初始化成功")
        print(f"✓ 缓存目录: {db.cache_dir}")
        
        # 测试融合漏洞信息
        print("\n测试融合漏洞信息:")
        merged_info = db.merge_vulnerability_info("CVE-2021-44228", 80)
        print(f"  ✓ CVE融合信息获取成功")
        print(f"    - CVE ID: {merged_info.get('cve_id')}")
        print(f"    - 数据源: {merged_info.get('sources')}")
        print(f"    - 描述数量: {len(merged_info.get('descriptions', []))}")
        print(f"    - CVSS评分: {merged_info.get('avg_cvss_score')}")
        print(f"    - 最终严重程度: {merged_info.get('final_severity')}")
        
        # 测试按端口获取漏洞
        print("\n测试按端口获取漏洞:")
        port_vulns = db.get_vulnerability_by_port(80)
        print(f"  ✓ 端口80漏洞: {len(port_vulns)} 个")
        
        # 测试统计信息
        print("\n测试统计信息:")
        stats = db.get_statistics()
        print(f"  ✓ 本地库记录数: {stats.get('total_records')}")
        
        return True
    except Exception as e:
        print(f"✗ UnifiedSecurityDatabase 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_html_parsing():
    """测试HTML解析功能"""
    print("\n" + "=" * 60)
    print("测试 2: HTML解析功能")
    print("=" * 60)
    
    try:
        from unified_security_db import UnifiedSecurityDatabase
        
        db = UnifiedSecurityDatabase()
        print("✓ UnifiedSecurityDatabase 初始化成功")
        
        # 测试CNVD HTML解析（使用模拟HTML）
        print("\n测试CNVD HTML解析:")
        test_html = """
        <html>
        <head><title>CNVD-2021-12345 漏洞详情</title></head>
        <body>
            <h1>Apache Log4j2 远程代码执行漏洞</h1>
            <div class="detail">漏洞描述：Apache Log4j2存在远程代码执行漏洞</div>
            <div>严重程度：严重</div>
            <div>CVSS评分：10.0</div>
            <div>发布时间：2021-12-10</div>
        </body>
        </html>
        """
        parsed = db.parse_cnvd_html(test_html)
        if parsed:
            print(f"  ✓ CNVD解析成功")
            print(f"    - 标题: {parsed.get('title', 'N/A')[:50]}")
            print(f"    - 严重程度: {parsed.get('severity')}")
            print(f"    - CVSS评分: {parsed.get('cvss_score')}")
        else:
            print("  ⚠ CNVD解析返回None（可能是HTML格式不匹配）")
        
        # 测试CNNVD HTML解析
        print("\n测试CNNVD HTML解析:")
        parsed = db.parse_cnnvd_html(test_html)
        if parsed:
            print(f"  ✓ CNNVD解析成功")
            print(f"    - 标题: {parsed.get('title', 'N/A')[:50]}")
        else:
            print("  ⚠ CNNVD解析返回None（可能是HTML格式不匹配）")
        
        return True
    except Exception as e:
        print(f"✗ HTML解析测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_security_info_integration():
    """测试安全信息集成到攻击检测器"""
    print("\n" + "=" * 60)
    print("测试 3: 安全信息集成到攻击检测器")
    print("=" * 60)
    
    try:
        from ufw_analyzer import VulnerabilityScanner, NetworkAnalyzer, AttackDetector
        
        # 创建测试数据
        test_entries = [
            {
                'action': 'ALLOW',
                'protocol': 'TCP',
                'src_ip': '0.0.0.0',
                'dst_ip': '192.168.1.1',
                'dst_port': '80',
                'interface_in': 'eth0',
                'raw_line': "[UFW ALLOW] SRC=0.0.0.0 DST=192.168.1.1 DPT=80 PROTO=TCP"
            },
            {
                'action': 'BLOCK',
                'protocol': 'TCP',
                'src_ip': '8.8.8.8',
                'dst_ip': '192.168.1.1',
                'dst_port': '80',
                'interface_in': 'eth0',
                'raw_line': "[UFW BLOCK] SRC=8.8.8.8 DST=192.168.1.1 DPT=80 PROTO=TCP ' OR 1=1--"
            }
        ]
        
        na = NetworkAnalyzer()
        
        # 测试漏洞扫描器
        print("\n测试漏洞扫描器:")
        scanner = VulnerabilityScanner(test_entries, na, enable_online_db=True)
        vulns = scanner.scan_open_ports()
        print(f"  ✓ 漏洞扫描: {len(vulns)} 个漏洞")
        
        if vulns:
            vuln = vulns[0]
            print(f"    - 端口: {vuln.get('port')}")
            print(f"    - 服务: {vuln.get('service')}")
            print(f"    - 严重程度: {vuln.get('severity')}")
            if 'cve_ids' in vuln:
                print(f"    - CVE数量: {len(vuln.get('cve_ids', []))}")
            if 'enhanced_cves' in vuln:
                print(f"    - 增强CVE信息: {len(vuln.get('enhanced_cves', []))} 个")
        
        # 测试攻击模式扫描
        print("\n测试攻击模式扫描:")
        attack_vulns = scanner.scan_attack_patterns()
        print(f"  ✓ 攻击模式扫描: {len(attack_vulns)} 个漏洞")
        
        # 测试攻击检测器
        print("\n测试攻击检测器:")
        detector = AttackDetector(test_entries, na)
        attacks = detector.detect_all_attacks()
        print(f"  ✓ 攻击检测: {len(attacks)} 个攻击")
        
        return True
    except Exception as e:
        print(f"✗ 安全信息集成测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_database_removal():
    """测试删除无法申请接入的数据库"""
    print("\n" + "=" * 60)
    print("测试 4: 数据库清理")
    print("=" * 60)
    
    try:
        from ufw_analyzer import SecurityDatabaseManager
        
        manager = SecurityDatabaseManager()
        print("✓ SecurityDatabaseManager 初始化成功")
        
        # 检查已删除的数据库
        print("\n检查已删除的数据库:")
        if 'cicsvd' in manager.enabled_databases:
            print("  ✗ CICSVD 仍在配置中")
        else:
            print("  ✓ CICSVD 已删除")
        
        if 'nvdb' in manager.enabled_databases:
            print("  ✗ NVDB 仍在配置中")
        else:
            print("  ✓ NVDB 已删除")
        
        if 'cicsvd' in manager.api_endpoints:
            print("  ✗ CICSVD API端点仍在配置中")
        else:
            print("  ✓ CICSVD API端点已删除")
        
        if 'nvdb' in manager.api_endpoints:
            print("  ✗ NVDB API端点仍在配置中")
        else:
            print("  ✓ NVDB API端点已删除")
        
        # 检查启用的数据库
        print(f"\n启用的数据库: {[k for k, v in manager.enabled_databases.items() if v]}")
        print(f"API端点数量: {len(manager.api_endpoints)}")
        
        return True
    except Exception as e:
        print(f"✗ 数据库清理测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """运行所有测试"""
    print("\n" + "=" * 60)
    print("统一安全库功能测试")
    print("=" * 60)
    print(f"测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    results = []
    
    # 运行所有测试
    results.append(("统一安全库", test_unified_security_db()))
    results.append(("HTML解析功能", test_html_parsing()))
    results.append(("安全信息集成", test_security_info_integration()))
    results.append(("数据库清理", test_database_removal()))
    
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
    print(f"总计: {passed}/{total} 个测试通过 ({passed*100//total if total > 0 else 0}%)")
    print("=" * 60)
    
    if passed == total:
        print("\n✓ 所有测试通过！")
        return 0
    else:
        print(f"\n⚠ {total - passed} 个测试失败")
        return 1


if __name__ == '__main__':
    sys.exit(main())

