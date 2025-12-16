#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UFW 防火墙日志分析程序 - 主入口

这是程序的主入口点，负责：
1. 解析命令行参数
2. 初始化分析器
3. 执行分析
4. 输出结果

使用方法:
    python3 main.py                    # 使用默认日志路径
    python3 main.py -l /path/to/log    # 指定日志路径
    python3 main.py -o output.json     # 导出JSON结果
    python3 main.py -j                 # 仅导出JSON，不显示详细输出
    sudo python3 main.py               # 需要读取 /var/log/ufw.log 时使用
"""

import sys
import argparse
from typing import Optional

# 导入主分析器
from ufw_analyzer import UFWAnalyzer


def main():
    """
    主函数 - 程序入口点
    
    解析命令行参数，初始化分析器，执行分析并输出结果。
    """
    parser = argparse.ArgumentParser(
        description='UFW 防火墙日志分析程序',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s                              # 使用默认日志路径分析
  %(prog)s -l /var/log/ufw.log          # 指定日志文件路径
  %(prog)s -o result.json                # 导出JSON结果
  %(prog)s -j -o result.json             # 仅导出JSON，不显示详细输出
  sudo %(prog)s                          # 需要读取系统日志时使用
        """
    )
    
    parser.add_argument(
        '-l', '--log',
        default='/var/log/ufw.log',
        help='UFW 日志文件路径 (默认: /var/log/ufw.log)'
    )
    
    parser.add_argument(
        '-o', '--output',
        default=None,
        help='导出 JSON 结果到指定文件'
    )
    
    parser.add_argument(
        '-j', '--json-only',
        action='store_true',
        help='仅导出 JSON，不显示详细输出'
    )
    
    parser.add_argument(
        '--no-network-analysis',
        action='store_true',
        help='禁用本地网络结构分析'
    )
    
    parser.add_argument(
        '--no-archived',
        action='store_true',
        help='不读取压缩的历史日志文件，仅读取当前日志'
    )
    
    parser.add_argument(
        '--no-online-db',
        action='store_true',
        help='禁用在线漏洞数据库查询（仅使用本地数据库）'
    )
    
    args = parser.parse_args()
    
    # 创建分析器实例
    try:
        analyzer = UFWAnalyzer(
            log_path=args.log,
            enable_network_analysis=not args.no_network_analysis,
            read_archived=not args.no_archived,
            enable_online_db=not args.no_online_db
        )
    except Exception as e:
        print(f"错误: 初始化分析器失败: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1
    
    # 执行分析
    try:
        if args.json_only:
            # 仅导出JSON模式
            analyzer.analyze()
            output_file = args.output or "ufw_analysis.json"
            analyzer.export_json(output_file)
        else:
            # 正常模式：显示详细输出
            analyzer.analyze()
            # 如果指定了输出文件，也导出JSON
            if args.output:
                analyzer.export_json(args.output)
    except KeyboardInterrupt:
        print("\n\n用户中断程序", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"错误: 分析过程中出错: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())

