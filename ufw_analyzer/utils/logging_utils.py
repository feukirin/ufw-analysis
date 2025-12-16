#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
日志工具函数
"""

import sys
import logging
from typing import Optional


def setup_logging(level=logging.INFO, log_file: Optional[str] = None):
    """
    设置日志系统
    
    Args:
        level: 日志级别，默认为 INFO
        log_file: 日志文件路径，如果为 None 则只输出到控制台
    
    Returns:
        logging.Logger: 配置好的日志记录器
    """
    # 创建格式化器
    formatter = logging.Formatter(
        fmt='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # 配置根日志记录器
    logger = logging.getLogger('ufw_analyzer')
    logger.setLevel(level)
    
    # 清除已有的处理器
    logger.handlers.clear()
    
    # 控制台处理器
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # 文件处理器（如果指定了日志文件）
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except (IOError, OSError) as e:
            logger.warning(f"无法创建日志文件 {log_file}: {e}，将只输出到控制台")
    
    return logger

