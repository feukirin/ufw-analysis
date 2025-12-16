#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
代理连接问题诊断和修复工具
用于诊断和修复 Clash/Mihomo 等代理软件的 UFW 防火墙阻止问题
"""

import subprocess
import sys
import ipaddress
from typing import List, Dict, Optional

class ProxyFixHelper:
    """代理连接修复助手"""
    
    PROXY_NETWORK = ipaddress.IPv4Network('198.18.0.0/15')
    CLASH_PORTS = list(range(10000, 10020))  # Clash/Mihomo 常用端口范围
    
    def __init__(self):
        self.ufw_rules = []
        self.blocked_rules = []
        self.allowed_rules = []
    
    def check_ufw_status(self) -> bool:
        """检查 UFW 是否启用"""
        try:
            result = subprocess.run(['ufw', 'status'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                output = result.stdout
                if 'Status: active' in output:
                    print("✓ UFW 防火墙已启用")
                    return True
                else:
                    print("✗ UFW 防火墙未启用")
                    return False
            return False
        except (FileNotFoundError, subprocess.SubprocessError) as e:
            print(f"✗ 无法检查 UFW 状态: {e}")
            return False
    
    def get_ufw_rules(self) -> List[str]:
        """获取当前 UFW 规则"""
        try:
            result = subprocess.run(['ufw', 'status', 'numbered'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return result.stdout.split('\n')
            return []
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            print(f"✗ 无法获取 UFW 规则: {e}")
            return []
    
    def analyze_rules(self):
        """分析 UFW 规则，查找可能阻止代理的规则"""
        rules = self.get_ufw_rules()
        self.ufw_rules = rules
        
        print("\n正在分析 UFW 规则...")
        
        # 检查是否有阻止 198.18.0.0/15 的规则
        for rule in rules:
            if '198.18' in rule or '198.19' in rule:
                if 'DENY' in rule or 'REJECT' in rule or 'BLOCK' in rule:
                    self.blocked_rules.append(rule)
                    print(f"⚠ 发现阻止代理网络的规则: {rule.strip()}")
                elif 'ALLOW' in rule:
                    self.allowed_rules.append(rule)
                    print(f"✓ 发现允许代理网络的规则: {rule.strip()}")
        
        # 检查默认策略
        for rule in rules:
            if 'Default:' in rule:
                if 'deny' in rule.lower() or 'reject' in rule.lower():
                    print(f"⚠ 默认策略可能阻止连接: {rule.strip()}")
    
    def diagnose_proxy_blocking(self, client_ip: str = '198.18.0.1', 
                                proxy_ip: str = '198.18.0.2',
                                ports: List[int] = None) -> Dict:
        """诊断代理连接被阻止的原因"""
        if ports is None:
            ports = self.CLASH_PORTS
        
        print("\n" + "=" * 60)
        print("代理连接问题诊断")
        print("=" * 60)
        print(f"客户端 IP: {client_ip}")
        print(f"代理 IP: {proxy_ip}")
        print(f"使用端口: {', '.join(map(str, ports[:10]))}...")
        
        diagnosis = {
            'ufw_enabled': self.check_ufw_status(),
            'blocked_rules': [],
            'missing_allows': [],
            'recommendations': []
        }
        
        if not diagnosis['ufw_enabled']:
            diagnosis['recommendations'].append("UFW 未启用，可能不是防火墙问题")
            return diagnosis
        
        self.analyze_rules()
        
        # 检查是否有允许规则
        has_allow_rule = False
        for rule in self.allowed_rules:
            if proxy_ip in rule or client_ip in rule:
                has_allow_rule = True
                break
        
        if not has_allow_rule:
            diagnosis['missing_allows'].append(
                f"缺少允许 {client_ip} 到 {proxy_ip} 的规则"
            )
            diagnosis['recommendations'].append(
                f"需要添加允许规则: ufw allow from {client_ip} to {proxy_ip}"
            )
        
        # 检查端口
        for port in ports[:10]:  # 只检查前10个端口
            port_allowed = False
            for rule in self.allowed_rules:
                if str(port) in rule:
                    port_allowed = True
                    break
            
            if not port_allowed:
                diagnosis['missing_allows'].append(
                    f"缺少允许端口 {port} 的规则"
                )
        
        if diagnosis['missing_allows']:
            diagnosis['recommendations'].append(
                f"需要添加端口范围规则: ufw allow from {client_ip} to {proxy_ip} port {ports[0]}:{ports[-1]}"
            )
        
        return diagnosis
    
    def generate_fix_commands(self, client_ip: str = '198.18.0.1',
                             proxy_ip: str = '198.18.0.2',
                             ports: List[int] = None) -> List[str]:
        """生成修复命令"""
        if ports is None:
            ports = self.CLASH_PORTS
        
        commands = []
        
        print("\n" + "=" * 60)
        print("修复建议")
        print("=" * 60)
        
        # 方案1: 允许整个代理网络段
        print("\n方案1: 允许整个代理网络段 (198.18.0.0/15)")
        commands.append(f"sudo ufw allow from 198.18.0.0/15 to 198.18.0.0/15")
        print(f"  命令: {commands[-1]}")
        print("  说明: 允许代理网络内部的所有通信")
        
        # 方案2: 允许特定客户端到代理的通信
        print("\n方案2: 允许特定客户端到代理的通信")
        commands.append(f"sudo ufw allow from {client_ip} to {proxy_ip}")
        print(f"  命令: {commands[-1]}")
        print("  说明: 只允许指定的客户端IP访问代理IP")
        
        # 方案3: 允许端口范围
        print("\n方案3: 允许端口范围")
        commands.append(f"sudo ufw allow from {client_ip} to {proxy_ip} port {ports[0]}:{ports[-1]}")
        print(f"  命令: {commands[-1]}")
        print(f"  说明: 允许客户端访问代理的端口范围 {ports[0]}-{ports[-1]}")
        
        # 方案4: 允许所有本地代理流量（最宽松）
        print("\n方案4: 允许所有本地代理流量（最宽松，推荐用于本地代理）")
        commands.append(f"sudo ufw allow from 127.0.0.1,{client_ip} to {proxy_ip} port {ports[0]}:{ports[-1]}/tcp")
        commands.append(f"sudo ufw allow from 127.0.0.1,{client_ip} to {proxy_ip} port {ports[0]}:{ports[-1]}/udp")
        print(f"  命令: {commands[-2]}")
        print(f"  命令: {commands[-1]}")
        print("  说明: 允许本地和客户端访问代理的TCP和UDP流量")
        
        print("\n" + "=" * 60)
        print("执行建议:")
        print("=" * 60)
        print("1. 如果是本地代理（Clash/Mihomo），推荐使用方案4")
        print("2. 执行命令后，检查代理连接是否正常")
        print("3. 如果仍有问题，检查是否有其他防火墙规则阻止")
        print("4. 可以使用 'sudo ufw status numbered' 查看所有规则")
        print("5. 可以使用 'sudo ufw delete <规则编号>' 删除不需要的规则")
        
        return commands
    
    def print_diagnosis_report(self, diagnosis: Dict):
        """打印诊断报告"""
        print("\n" + "=" * 60)
        print("诊断报告")
        print("=" * 60)
        
        print(f"\nUFW 状态: {'✓ 已启用' if diagnosis['ufw_enabled'] else '✗ 未启用'}")
        
        if diagnosis['blocked_rules']:
            print(f"\n⚠ 发现 {len(diagnosis['blocked_rules'])} 条可能阻止代理的规则:")
            for rule in diagnosis['blocked_rules']:
                print(f"  - {rule.strip()}")
        
        if diagnosis['missing_allows']:
            print(f"\n✗ 缺少 {len(diagnosis['missing_allows'])} 条允许规则:")
            for missing in diagnosis['missing_allows'][:5]:  # 只显示前5条
                print(f"  - {missing}")
            if len(diagnosis['missing_allows']) > 5:
                print(f"  ... 还有 {len(diagnosis['missing_allows']) - 5} 条")
        
        if diagnosis['recommendations']:
            print(f"\n💡 修复建议:")
            for i, rec in enumerate(diagnosis['recommendations'], 1):
                print(f"  {i}. {rec}")


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='代理连接问题诊断和修复工具')
    parser.add_argument('--client-ip', default='198.18.0.1',
                       help='客户端IP地址 (默认: 198.18.0.1)')
    parser.add_argument('--proxy-ip', default='198.18.0.2',
                       help='代理IP地址 (默认: 198.18.0.2)')
    parser.add_argument('--ports', nargs='+', type=int,
                       default=list(range(10000, 10010)),
                       help='使用的端口列表 (默认: 10000-10009)')
    parser.add_argument('--fix', action='store_true',
                       help='显示修复命令（不执行）')
    
    args = parser.parse_args()
    
    helper = ProxyFixHelper()
    
    # 诊断
    diagnosis = helper.diagnose_proxy_blocking(
        client_ip=args.client_ip,
        proxy_ip=args.proxy_ip,
        ports=args.ports
    )
    
    helper.print_diagnosis_report(diagnosis)
    
    # 生成修复命令
    if args.fix:
        commands = helper.generate_fix_commands(
            client_ip=args.client_ip,
            proxy_ip=args.proxy_ip,
            ports=args.ports
        )
        
        print("\n" + "=" * 60)
        print("所有修复命令:")
        print("=" * 60)
        for i, cmd in enumerate(commands, 1):
            print(f"{i}. {cmd}")


if __name__ == '__main__':
    main()

