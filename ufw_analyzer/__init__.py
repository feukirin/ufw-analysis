#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UFW 分析器包

这是 UFW 防火墙日志分析程序的主要包。
"""

# 从主文件导入 UFWAnalyzer（向后兼容）
# 注意：主文件 ufw_analyzer.py 包含 UFWAnalyzer 类
# 推荐使用 main.py 作为程序入口

__version__ = '2.0.0'
__author__ = 'UFW Analyzer Team'

# 尝试从主文件导入 UFWAnalyzer
try:
    import sys
    import importlib.util
    
    # 动态导入主文件中的 UFWAnalyzer
    spec = importlib.util.spec_from_file_location("ufw_analyzer_main", "ufw_analyzer.py")
    if spec and spec.loader:
        ufw_analyzer_main = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ufw_analyzer_main)
        UFWAnalyzer = getattr(ufw_analyzer_main, 'UFWAnalyzer', None)
    else:
        UFWAnalyzer = None
except Exception:
    UFWAnalyzer = None

__all__ = ['UFWAnalyzer'] if UFWAnalyzer else []

