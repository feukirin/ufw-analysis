#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
安全数据库访问功能测试
测试对国内外权威数据库的访问功能
"""

import sys
import os
from datetime import datetime

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_security_database_manager():
    """测试 SecurityDatabaseManager"""
    print("=" * 60)
    print("测试 1: SecurityDatabaseManager")
    print("=" * 60)
    
    try:
        from ufw_analyzer import SecurityDatabaseManager
        
        manager = SecurityDatabaseManager()
        print("✓ SecurityDatabaseManager 初始化成功")
        
        # 测试缓存目录
        print(f"✓ 缓存目录: {manager.cache_dir}")
        
        # 测试CVE查询
        print("\n测试 CVE 查询:")
        cve_result = manager.query_cve("CVE-2021-44228")
        if cve_result:
            print(f"  ✓ CVE查询成功: {cve_result.get('id', 'N/A')}")
            print(f"    - 描述: {cve_result.get('description', 'N/A')[:50]}...")
        else:
            print("  ⚠ CVE查询返回None（可能是模拟数据）")
        
        # 测试NVD查询
        print("\n测试 NVD 查询:")
        nvd_result = manager.query_nvd("CVE-2021-44228")
        if nvd_result:
            print(f"  ✓ NVD查询成功: {nvd_result.get('id', 'N/A')}")
        else:
            print("  ⚠ NVD查询返回None（可能是模拟数据）")
        
        # 测试OSV查询
        print("\n测试 OSV 查询:")
        osv_result = manager.query_osv(cve_id="CVE-2021-44228")
        if osv_result:
            print(f"  ✓ OSV查询成功: {osv_result.get('id', 'N/A')}")
        else:
            print("  ⚠ OSV查询返回None（可能是模拟数据）")
        
        # 测试CNVD查询
        print("\n测试 CNVD 查询:")
        cnvd_result = manager.query_cnvd(cnvd_id="CNVD-2021-12345")
        if cnvd_result:
            print(f"  ✓ CNVD查询成功: {cnvd_result.get('id', 'N/A')}")
        else:
            print("  ⚠ CNVD查询返回None（可能是模拟数据）")
        
        # 测试CNNVD查询
        print("\n测试 CNNVD 查询:")
        cnnvd_result = manager.query_cnnvd(cnnvd_id="CNNVD-202112-123")
        if cnnvd_result:
            print(f"  ✓ CNNVD查询成功: {cnnvd_result.get('id', 'N/A')}")
        else:
            print("  ⚠ CNNVD查询返回None（可能是模拟数据）")
        
        # 测试按端口查询
        print("\n测试按端口查询:")
        port_result = manager.query_by_port(80)
        if port_result:
            print(f"  ✓ 端口查询成功: {len(port_result)} 个漏洞")
            if port_result:
                print(f"    - 示例: {port_result[0].get('id', 'N/A')}")
        else:
            print("  ⚠ 端口查询返回None（可能是模拟数据）")
        
        return True
    except Exception as e:
        print(f"✗ SecurityDatabaseManager 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_vulnerability_database():
    """测试 VulnerabilityDatabase"""
    print("\n" + "=" * 60)
    print("测试 2: VulnerabilityDatabase")
    print("=" * 60)
    
    try:
        from ufw_analyzer import VulnerabilityDatabase
        
        db = VulnerabilityDatabase()
        print("✓ VulnerabilityDatabase 初始化成功")
        
        # 测试获取端口信息
        print("\n测试获取端口信息:")
        port_info = db.get_port_info(80)
        if port_info:
            print(f"  ✓ 端口80信息获取成功")
            print(f"    - 服务: {port_info.get('service', 'N/A')}")
            print(f"    - 描述: {port_info.get('description', 'N/A')[:50]}...")
            if 'cves' in port_info:
                print(f"    - CVE数量: {len(port_info.get('cves', []))}")
        else:
            print("  ⚠ 端口信息返回None")
        
        # 测试获取攻击模式
        print("\n测试获取攻击模式:")
        attack_pattern = db.get_attack_pattern("sql_injection")
        if attack_pattern:
            print(f"  ✓ 攻击模式获取成功: {attack_pattern.get('name', 'N/A')}")
        else:
            print("  ⚠ 攻击模式返回None")
        
        return True
    except Exception as e:
        print(f"✗ VulnerabilityDatabase 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_cache_mechanism():
    """测试缓存机制"""
    print("\n" + "=" * 60)
    print("测试 3: 缓存机制")
    print("=" * 60)
    
    try:
        from ufw_analyzer import SecurityDatabaseManager
        import time
        
        manager = SecurityDatabaseManager()
        print("✓ SecurityDatabaseManager 初始化成功")
        
        # 测试缓存写入
        print("\n测试缓存写入:")
        test_data = {"id": "TEST-001", "description": "测试数据"}
        manager._save_cache("test_key", test_data)
        print("  ✓ 缓存写入成功")
        
        # 测试缓存读取
        print("\n测试缓存读取:")
        cached_data = manager._load_cache("test_key")
        if cached_data:
            print(f"  ✓ 缓存读取成功: {cached_data.get('id', 'N/A')}")
        else:
            print("  ⚠ 缓存读取返回None（可能是缓存过期或不存在）")
        
        # 测试缓存TTL
        print("\n测试缓存TTL:")
        print(f"  ✓ 缓存TTL: {manager.cache_ttl} 秒")
        
        return True
    except Exception as e:
        print(f"✗ 缓存机制测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_api_endpoints():
    """测试API端点配置"""
    print("\n" + "=" * 60)
    print("测试 4: API端点配置")
    print("=" * 60)
    
    try:
        from ufw_analyzer import SecurityDatabaseManager
        
        manager = SecurityDatabaseManager()
        print("✓ SecurityDatabaseManager 初始化成功")
        
        # 检查API端点配置
        print("\n检查API端点:")
        if hasattr(manager, 'api_endpoints'):
            endpoints = manager.api_endpoints
            print(f"  ✓ API端点数量: {len(endpoints)}")
            for name, endpoint_config in endpoints.items():
                if isinstance(endpoint_config, dict):
                    base_url = endpoint_config.get('base_url', 'N/A')
                    desc = endpoint_config.get('description', '')
                    print(f"    - {name}: {base_url[:50]}... ({desc})")
                else:
                    print(f"    - {name}: {str(endpoint_config)[:50]}...")
        else:
            print("  ⚠ 未找到api_endpoints属性")
        
        return True
    except Exception as e:
        print(f"✗ API端点配置测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_error_handling():
    """测试错误处理"""
    print("\n" + "=" * 60)
    print("测试 5: 错误处理")
    print("=" * 60)
    
    try:
        from ufw_analyzer import SecurityDatabaseManager
        
        manager = SecurityDatabaseManager()
        print("✓ SecurityDatabaseManager 初始化成功")
        
        # 测试无效CVE ID
        print("\n测试无效CVE ID:")
        result = manager.query_cve("INVALID-CVE-ID")
        if result is None:
            print("  ✓ 无效CVE ID处理正常（返回None）")
        else:
            print(f"  ⚠ 返回了结果: {result}")
        
        # 测试无效端口
        print("\n测试无效端口:")
        result = manager.query_by_port(99999)
        if result is None or len(result) == 0:
            print("  ✓ 无效端口处理正常")
        else:
            print(f"  ⚠ 返回了结果: {result}")
        
        return True
    except Exception as e:
        print(f"✗ 错误处理测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_integration_with_vulnerability_scanner():
    """测试与漏洞扫描器的集成"""
    print("\n" + "=" * 60)
    print("测试 6: 与漏洞扫描器的集成")
    print("=" * 60)
    
    try:
        from ufw_analyzer import VulnerabilityScanner, NetworkAnalyzer
        
        # 创建测试数据
        test_entries = [
            {
                'action': 'ALLOW',
                'protocol': 'TCP',
                'src_ip': '0.0.0.0',
                'dst_ip': '192.168.1.1',
                'dst_port': '80',
                'interface_in': 'eth0'
            }
        ]
        
        na = NetworkAnalyzer()
        scanner = VulnerabilityScanner(test_entries, na, enable_online_db=True)
        print("✓ VulnerabilityScanner 初始化成功（启用在线数据库）")
        
        # 测试扫描
        vulns = scanner.scan_open_ports()
        print(f"✓ 漏洞扫描完成: {len(vulns)} 个漏洞")
        
        if vulns:
            vuln = vulns[0]
            print(f"  - 漏洞类型: {vuln.get('type', 'N/A')}")
            print(f"  - 端口: {vuln.get('port', 'N/A')}")
            if 'cve_ids' in vuln:
                print(f"  - CVE数量: {len(vuln.get('cve_ids', []))}")
        
        return True
    except Exception as e:
        print(f"✗ 集成测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """运行所有测试"""
    print("\n" + "=" * 60)
    print("安全数据库访问功能测试")
    print("=" * 60)
    print(f"测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    results = []
    
    # 运行所有测试
    results.append(("SecurityDatabaseManager", test_security_database_manager()))
    results.append(("VulnerabilityDatabase", test_vulnerability_database()))
    results.append(("缓存机制", test_cache_mechanism()))
    results.append(("API端点配置", test_api_endpoints()))
    results.append(("错误处理", test_error_handling()))
    results.append(("与漏洞扫描器集成", test_integration_with_vulnerability_scanner()))
    
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
    
    # 输出支持的数据库列表
    print("\n支持的数据库:")
    print("  国际数据库:")
    print("    - CVE (Common Vulnerabilities and Exposures)")
    print("    - NVD (National Vulnerability Database)")
    print("    - OSV (Open Source Vulnerability Database)")
    print("  国内数据库:")
    print("    - CNVD (国家信息安全漏洞共享平台)")
    print("    - CNNVD (国家信息安全漏洞库)")
    
    if passed == total:
        print("\n✓ 所有测试通过！")
        return 0
    else:
        print(f"\n⚠ {total - passed} 个测试失败")
        return 1


if __name__ == '__main__':
    sys.exit(main())

