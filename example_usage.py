#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UFW 分析器使用示例
"""

from ufw_analyzer import UFWAnalyzer

def main():
    # 创建分析器实例
    # 如果日志文件不在默认位置，可以指定路径
    analyzer = UFWAnalyzer('/var/log/ufw.log')
    
    # 执行完整分析
    analyzer.analyze()
    
    # 导出 JSON 结果
    analyzer.export_json('ufw_analysis_result.json')
    
    print("\n提示: 分析结果已保存到 ufw_analysis_result.json")

if __name__ == '__main__':
    main()

