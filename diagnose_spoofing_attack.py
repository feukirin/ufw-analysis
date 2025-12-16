#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
源路由攻击（IP伪装）诊断工具

用于详细分析源路由攻击检测结果，判断是否为误报
"""

import sys
import os
from collections import defaultdict, Counter
from typing import Dict, List, Any
import ipaddress

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ufw_analyzer.core.network import NetworkAnalyzer
from ufw_analyzer.core.parser import UFWLogParser


class SpoofingAttackDiagnostic:
    """源路由攻击诊断器"""
    
    def __init__(self, log_path: str = "/var/log/ufw.log"):
        self.log_path = log_path
        self.network_analyzer = NetworkAnalyzer()
        self.parser = UFWLogParser(log_path, read_archived=False)
        self.log_entries = []
    
    def load_logs(self):
        """加载日志"""
        print("正在加载日志文件...")
        self.log_entries = self.parser.read_logs()
        print(f"已加载 {len(self.log_entries)} 条日志记录")
    
    def diagnose(self, target_ip: str = "192.168.50.1"):
        """诊断源路由攻击"""
        print("=" * 80)
        print(f"源路由攻击诊断 - 目标IP: {target_ip}")
        print("=" * 80)
        
        # 1. 分析目标IP的基本信息
        print("\n[1] IP地址基本信息分析")
        print("-" * 80)
        self._analyze_ip_info(target_ip)
        
        # 2. 分析该IP的流量模式
        print("\n[2] 流量模式分析")
        print("-" * 80)
        self._analyze_traffic_pattern(target_ip)
        
        # 3. 分析目标IP地址
        print("\n[3] 目标地址分析")
        print("-" * 80)
        self._analyze_destination_ips(target_ip)
        
        # 4. 分析是否为正常NAT行为
        print("\n[4] NAT行为分析")
        print("-" * 80)
        self._analyze_nat_behavior(target_ip)
        
        # 5. 判断是否为误报
        print("\n[5] 综合判断")
        print("-" * 80)
        self._make_judgment(target_ip)
    
    def _analyze_ip_info(self, ip: str):
        """分析IP基本信息"""
        ip_type = self.network_analyzer.get_ip_type(ip)
        is_switch = self.network_analyzer.is_switch_ip(ip)
        is_local = self.network_analyzer.is_local_ip(ip)
        is_internet = self.network_analyzer.is_internet_ip(ip)
        
        network_info = self.network_analyzer.get_network_info()
        gateway_ip = network_info.get('gateway_ip')
        host_ip = network_info.get('host_ip')
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            is_private = ip_obj.is_private
        except:
            is_private = False
        
        print(f"IP地址: {ip}")
        print(f"  类型: {ip_type}")
        print(f"  是否为网关/交换机IP: {is_switch}")
        print(f"  是否为本地网络IP: {is_local}")
        print(f"  是否为互联网IP: {is_internet}")
        print(f"  是否为私有IP: {is_private}")
        print(f"\n网络环境:")
        print(f"  网关IP: {gateway_ip}")
        print(f"  主机IP: {host_ip}")
        
        if ip == gateway_ip:
            print(f"\n  ⚠️  该IP是网关地址！")
            print(f"  ⚠️  网关作为源地址访问公网是正常的NAT行为，不应被视为攻击")
    
    def _analyze_traffic_pattern(self, src_ip: str):
        """分析流量模式"""
        # 筛选该IP作为源地址的日志
        src_entries = [e for e in self.log_entries if e.get('src_ip') == src_ip]
        
        if not src_entries:
            print(f"未找到 {src_ip} 作为源地址的日志记录")
            return
        
        print(f"总记录数: {len(src_entries)}")
        
        # 动作统计
        actions = Counter(e.get('action', 'UNKNOWN') for e in src_entries)
        print(f"\n动作统计:")
        for action, count in actions.items():
            print(f"  {action}: {count} ({count/len(src_entries)*100:.1f}%)")
        
        # 协议统计
        protocols = Counter(e.get('protocol', 'UNKNOWN') for e in src_entries)
        print(f"\n协议统计:")
        for protocol, count in protocols.most_common(10):
            print(f"  {protocol}: {count}")
        
        # 目标IP类型统计
        dst_types = Counter()
        internet_dst_count = 0
        local_dst_count = 0
        
        for entry in src_entries:
            dst_ip = entry.get('dst_ip')
            if dst_ip:
                dst_type = self.network_analyzer.get_ip_type(dst_ip)
                dst_types[dst_type] += 1
                if dst_type == 'internet':
                    internet_dst_count += 1
                elif dst_type in ['local', 'switch']:
                    local_dst_count += 1
        
        print(f"\n目标IP类型统计:")
        for dst_type, count in dst_types.items():
            print(f"  {dst_type}: {count} ({count/len(src_entries)*100:.1f}%)")
        
        print(f"\n关键指标:")
        print(f"  访问公网IP的记录数: {internet_dst_count}")
        print(f"  访问本地IP的记录数: {local_dst_count}")
        print(f"  公网访问占比: {internet_dst_count/len(src_entries)*100:.1f}%")
    
    def _analyze_destination_ips(self, src_ip: str):
        """分析目标IP地址"""
        src_entries = [e for e in self.log_entries if e.get('src_ip') == src_ip]
        
        # 筛选访问公网IP的记录
        internet_entries = []
        for entry in src_entries:
            dst_ip = entry.get('dst_ip')
            if dst_ip:
                dst_type = self.network_analyzer.get_ip_type(dst_ip)
                if dst_type == 'internet':
                    internet_entries.append(entry)
        
        if not internet_entries:
            print("未发现访问公网IP的记录")
            return
        
        print(f"访问公网IP的记录数: {len(internet_entries)}")
        
        # 目标IP统计
        dst_ips = Counter(e.get('dst_ip') for e in internet_entries if e.get('dst_ip'))
        print(f"\nTop 10 目标IP地址:")
        for dst_ip, count in dst_ips.most_common(10):
            try:
                ip_obj = ipaddress.ip_address(dst_ip)
                is_private = ip_obj.is_private
                print(f"  {dst_ip}: {count} 次 {'(私有IP，可能是误判)' if is_private else ''}")
            except:
                print(f"  {dst_ip}: {count} 次")
        
        # 目标端口统计
        dst_ports = Counter(e.get('dst_port') for e in internet_entries if e.get('dst_port'))
        print(f"\nTop 10 目标端口:")
        for port, count in dst_ports.most_common(10):
            print(f"  {port}: {count} 次")
        
        # 检查是否有异常的目标IP
        suspicious_dsts = []
        for dst_ip, count in dst_ips.items():
            if count > 100:  # 单个目标IP访问超过100次
                suspicious_dsts.append((dst_ip, count))
        
        if suspicious_dsts:
            print(f"\n⚠️  发现异常目标IP（访问次数>100）:")
            for dst_ip, count in suspicious_dsts[:5]:
                print(f"  {dst_ip}: {count} 次")
    
    def _analyze_nat_behavior(self, src_ip: str):
        """分析NAT行为"""
        network_info = self.network_analyzer.get_network_info()
        gateway_ip = network_info.get('gateway_ip')
        
        if src_ip != gateway_ip:
            print(f"该IP不是网关地址，跳过NAT行为分析")
            return
        
        print(f"该IP是网关地址 ({gateway_ip})")
        print(f"\nNAT行为特征分析:")
        
        src_entries = [e for e in self.log_entries if e.get('src_ip') == src_ip]
        internet_entries = [e for e in src_entries 
                           if e.get('dst_ip') and 
                           self.network_analyzer.get_ip_type(e.get('dst_ip')) == 'internet']
        
        print(f"  网关作为源地址访问公网的记录数: {len(internet_entries)}")
        print(f"  这是正常的NAT（网络地址转换）行为")
        print(f"  网关会将内网设备的请求转发到公网，源IP显示为网关IP是正常的")
        
        # 检查是否有内网设备也在访问相同的公网IP
        # 这可以进一步确认是NAT行为
        if internet_entries:
            # 获取网关访问的公网IP列表
            gateway_dst_ips = set(e.get('dst_ip') for e in internet_entries if e.get('dst_ip'))
            
            # 检查内网其他设备是否也访问这些IP
            local_entries = [e for e in self.log_entries 
                           if e.get('src_ip') != src_ip and
                           self.network_analyzer.is_local_ip(e.get('src_ip'))]
            
            local_dst_ips = set(e.get('dst_ip') for e in local_entries if e.get('dst_ip'))
            
            common_dsts = gateway_dst_ips & local_dst_ips
            
            if common_dsts:
                print(f"\n  ✅ 发现内网其他设备也访问了相同的公网IP ({len(common_dsts)} 个)")
                print(f"  这进一步确认了这是正常的NAT行为")
                print(f"  示例公网IP: {list(common_dsts)[:5]}")
            else:
                print(f"\n  ⚠️  未发现内网其他设备访问相同的公网IP")
                print(f"  这可能表示：")
                print(f"    1. 网关本身在访问公网（正常）")
                print(f"    2. 内网设备的访问被NAT转换，源IP显示为网关（正常）")
    
    def _make_judgment(self, src_ip: str):
        """综合判断"""
        network_info = self.network_analyzer.get_network_info()
        gateway_ip = network_info.get('gateway_ip')
        is_switch = self.network_analyzer.is_switch_ip(src_ip)
        
        src_entries = [e for e in self.log_entries if e.get('src_ip') == src_ip]
        internet_entries = [e for e in src_entries 
                           if e.get('dst_ip') and 
                           self.network_analyzer.get_ip_type(e.get('dst_ip')) == 'internet']
        
        print(f"判断结果:")
        print(f"  目标IP: {src_ip}")
        print(f"  是否为网关: {src_ip == gateway_ip}")
        print(f"  是否为交换机/网关IP: {is_switch}")
        print(f"  访问公网记录数: {len(internet_entries)}")
        
        # 判断逻辑
        if src_ip == gateway_ip:
            print(f"\n  ✅ 结论: 这是误报（False Positive）")
            print(f"\n  原因:")
            print(f"    1. {src_ip} 是网关地址")
            print(f"    2. 网关作为源地址访问公网是正常的NAT行为")
            print(f"    3. 这不是源路由攻击，而是正常的网络地址转换")
            print(f"\n  建议:")
            print(f"    1. 修改攻击检测逻辑，排除网关IP的正常NAT流量")
            print(f"    2. 如果确实需要检测源路由攻击，应该关注：")
            print(f"       - 非网关IP的私有地址访问公网")
            print(f"       - 异常的源IP和目标IP组合")
            print(f"       - 大量不同的私有IP访问相同的公网目标")
        elif is_switch:
            print(f"\n  ⚠️  结论: 可能是误报")
            print(f"\n  原因:")
            print(f"    1. {src_ip} 被识别为交换机/网关IP")
            print(f"    2. 交换机/网关访问公网通常是正常的")
            print(f"\n  建议:")
            print(f"    1. 确认该IP的实际用途")
            print(f"    2. 如果是网关，应排除在源路由攻击检测之外")
        else:
            print(f"\n  ⚠️  结论: 需要进一步分析")
            print(f"\n  原因:")
            print(f"    1. {src_ip} 是私有IP地址")
            print(f"    2. 私有IP作为源地址访问公网可能是：")
            print(f"       - 正常的NAT行为（如果该IP是网关）")
            print(f"       - 配置错误（路由配置问题）")
            print(f"       - 真正的源路由攻击（较少见）")
            print(f"\n  建议:")
            print(f"    1. 检查网络配置，确认该IP的实际用途")
            print(f"    2. 检查路由表，确认是否有异常路由")
            print(f"    3. 如果确认是攻击，采取以下措施：")
            print(f"       - 启用反向路径转发(RPF)")
            print(f"       - 过滤私有IP源地址")
            print(f"       - 检查路由配置")


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='源路由攻击诊断工具')
    parser.add_argument('-l', '--log', default='/var/log/ufw.log',
                       help='UFW日志文件路径')
    parser.add_argument('-i', '--ip', default='192.168.50.1',
                       help='要诊断的IP地址')
    
    args = parser.parse_args()
    
    diagnostic = SpoofingAttackDiagnostic(args.log)
    diagnostic.load_logs()
    diagnostic.diagnose(args.ip)


if __name__ == '__main__':
    main()

