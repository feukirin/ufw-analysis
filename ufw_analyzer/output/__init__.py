#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
输出格式化模块
提供多种输出格式支持（控制台、JSON等）
"""

from .base import BaseFormatter

# 延迟导入，避免循环依赖
try:
    from .console import ConsoleFormatter
    __all__ = ['ConsoleFormatter', 'BaseFormatter']
except ImportError:
    __all__ = ['BaseFormatter']

