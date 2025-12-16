#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
统一安全库管理器
融合多个安全数据库的信息，形成本地统一的安全库
"""

import re
import json
import os
import time
import hashlib
import urllib.request
import urllib.error
import urllib.parse
import socket
from typing import Dict, List, Optional, Set, Any
from collections import defaultdict
import logging

logger = logging.getLogger('ufw_analyzer')

# BeautifulSoup用于HTML解析（可选依赖）
try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False
    logger.warning("BeautifulSoup4未安装，HTML解析功能将受限，将使用正则表达式解析")


class UnifiedSecurityDatabase:
    """统一安全库管理器"""
    
    def __init__(self, cache_dir: str = ".security_cache", cache_ttl: int = 86400 * 7):
        """
        初始化统一安全库
        
        Args:
            cache_dir: 缓存目录
            cache_ttl: 缓存有效期（秒），默认7天
        """
        self.cache_dir = cache_dir
        self.cache_ttl = cache_ttl
        
        # 确保缓存目录存在
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
            # 测试写权限
            test_file = os.path.join(self.cache_dir, '.test_write')
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
        except (OSError, PermissionError) as e:
            logger.warning(f"缓存目录创建或权限检查失败: {self.cache_dir}, 错误: {e}")
            import tempfile
            self.cache_dir = os.path.join(tempfile.gettempdir(), 'ufw_security_cache')
            os.makedirs(self.cache_dir, exist_ok=True)
            logger.info(f"使用临时缓存目录: {self.cache_dir}")
        
        # 本地统一安全库（内存缓存）
        self.local_db: Dict[str, Dict] = {}
        
        # 加载本地数据库
        self._load_local_db()
    
    def _get_cache_path(self, key: str) -> str:
        """获取缓存文件路径"""
        cache_key = hashlib.md5(key.encode()).hexdigest()
        return os.path.join(self.cache_dir, f"{cache_key}.json")
    
    def _load_cache(self, key: str) -> Optional[Dict]:
        """从缓存加载数据"""
        cache_path = self._get_cache_path(key)
        if not os.path.exists(cache_path):
            return None
        
        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)
            
            # 检查缓存是否过期
            cache_time = cache_data.get('timestamp', 0)
            if time.time() - cache_time > self.cache_ttl:
                return None
            
            return cache_data.get('data')
        except (json.JSONDecodeError, IOError, OSError) as e:
            logger.debug(f"缓存文件读取失败: {cache_path}, 错误: {e}")
            return None
    
    def _save_cache(self, key: str, data: Dict):
        """保存数据到缓存"""
        cache_path = self._get_cache_path(key)
        cache_data = {
            'timestamp': time.time(),
            'data': data
        }
        
        try:
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, ensure_ascii=False, indent=2)
        except (IOError, OSError) as e:
            logger.warning(f"缓存文件写入失败: {cache_path}, 错误: {e}")
    
    def _load_local_db(self):
        """加载本地统一安全库"""
        db_file = os.path.join(self.cache_dir, 'unified_security_db.json')
        if os.path.exists(db_file):
            try:
                with open(db_file, 'r', encoding='utf-8') as f:
                    self.local_db = json.load(f)
                logger.info(f"加载本地安全库: {len(self.local_db)} 条记录")
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"加载本地安全库失败: {e}")
                self.local_db = {}
        else:
            self.local_db = {}
    
    def _save_local_db(self):
        """保存本地统一安全库"""
        db_file = os.path.join(self.cache_dir, 'unified_security_db.json')
        try:
            with open(db_file, 'w', encoding='utf-8') as f:
                json.dump(self.local_db, f, ensure_ascii=False, indent=2)
            logger.info(f"保存本地安全库: {len(self.local_db)} 条记录")
        except (IOError, OSError) as e:
            logger.warning(f"保存本地安全库失败: {e}")
    
    def parse_cnvd_html(self, html_content: str) -> Optional[Dict]:
        """
        解析CNVD HTML页面
        
        Args:
            html_content: HTML内容
            
        Returns:
            Dict: 解析后的漏洞信息
        """
        if not HAS_BS4:
            # 如果没有BeautifulSoup，使用正则表达式简单解析
            return self._parse_cnvd_html_regex(html_content)
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            result = {
                'source': 'CNVD',
                'title': '',
                'description': '',
                'severity': '',
                'cvss_score': None,
                'affected_products': [],
                'published_date': '',
                'updated_date': '',
                'references': []
            }
            
            # 提取标题
            title_elem = soup.find('h1') or soup.find('title')
            if title_elem:
                result['title'] = title_elem.get_text(strip=True)
            
            # 提取描述（通常在class包含"detail"或"description"的元素中）
            desc_elem = soup.find(class_=re.compile(r'detail|description|content', re.I))
            if desc_elem:
                result['description'] = desc_elem.get_text(strip=True)
            
            # 提取严重程度（查找包含"严重"、"高危"等关键词）
            severity_pattern = re.compile(r'(严重|高危|中危|低危|critical|high|medium|low)', re.I)
            for elem in soup.find_all(text=severity_pattern):
                text = elem.strip()
                if severity_pattern.search(text):
                    result['severity'] = text
                    break
            
            # 提取CVSS评分
            cvss_pattern = re.compile(r'CVSS[:\s]*([\d.]+)', re.I)
            for elem in soup.find_all(text=cvss_pattern):
                match = cvss_pattern.search(elem)
                if match:
                    try:
                        result['cvss_score'] = float(match.group(1))
                    except (ValueError, TypeError):
                        pass
                    break
            
            # 提取受影响产品
            product_pattern = re.compile(r'(受影响|影响|产品|Product)', re.I)
            for elem in soup.find_all(text=product_pattern):
                parent = elem.parent
                if parent:
                    text = parent.get_text(strip=True)
                    # 提取产品名称（简化版）
                    products = re.findall(r'[\w\s]+', text)
                    result['affected_products'].extend(products[:5])  # 最多5个
            
            # 提取日期
            date_pattern = re.compile(r'(\d{4}[-/]\d{1,2}[-/]\d{1,2})')
            dates = date_pattern.findall(html_content)
            if dates:
                result['published_date'] = dates[0]
                if len(dates) > 1:
                    result['updated_date'] = dates[1]
            
            # 提取参考链接
            for link in soup.find_all('a', href=True):
                href = link.get('href', '')
                if href.startswith('http'):
                    result['references'].append(href)
            
            return result if result.get('title') or result.get('description') else None
            
        except Exception as e:
            logger.debug(f"CNVD HTML解析失败: {e}")
            return None
    
    def parse_cnnvd_html(self, html_content: str) -> Optional[Dict]:
        """
        解析CNNVD HTML页面
        
        Args:
            html_content: HTML内容
            
        Returns:
            Dict: 解析后的漏洞信息
        """
        if not HAS_BS4:
            # 如果没有BeautifulSoup，使用正则表达式简单解析
            return self._parse_cnnvd_html_regex(html_content)
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            result = {
                'source': 'CNNVD',
                'title': '',
                'description': '',
                'severity': '',
                'cvss_score': None,
                'affected_products': [],
                'published_date': '',
                'updated_date': '',
                'references': []
            }
            
            # 提取标题
            title_elem = soup.find('h1') or soup.find('title')
            if title_elem:
                result['title'] = title_elem.get_text(strip=True)
            
            # 提取描述
            desc_elem = soup.find(class_=re.compile(r'detail|description|content|vuln', re.I))
            if desc_elem:
                result['description'] = desc_elem.get_text(strip=True)
            
            # 提取严重程度
            severity_pattern = re.compile(r'(严重|高危|中危|低危|critical|high|medium|low)', re.I)
            for elem in soup.find_all(text=severity_pattern):
                text = elem.strip()
                if severity_pattern.search(text):
                    result['severity'] = text
                    break
            
            # 提取CVSS评分
            cvss_pattern = re.compile(r'CVSS[:\s]*([\d.]+)', re.I)
            for elem in soup.find_all(text=cvss_pattern):
                match = cvss_pattern.search(elem)
                if match:
                    try:
                        result['cvss_score'] = float(match.group(1))
                    except (ValueError, TypeError):
                        pass
                    break
            
            # 提取受影响产品
            product_pattern = re.compile(r'(受影响|影响|产品|Product)', re.I)
            for elem in soup.find_all(text=product_pattern):
                parent = elem.parent
                if parent:
                    text = parent.get_text(strip=True)
                    products = re.findall(r'[\w\s]+', text)
                    result['affected_products'].extend(products[:5])
            
            # 提取日期
            date_pattern = re.compile(r'(\d{4}[-/]\d{1,2}[-/]\d{1,2})')
            dates = date_pattern.findall(html_content)
            if dates:
                result['published_date'] = dates[0]
                if len(dates) > 1:
                    result['updated_date'] = dates[1]
            
            # 提取参考链接
            for link in soup.find_all('a', href=True):
                href = link.get('href', '')
                if href.startswith('http'):
                    result['references'].append(href)
            
            return result if result.get('title') or result.get('description') else None
            
        except Exception as e:
            logger.debug(f"CNNVD HTML解析失败: {e}")
            return None
    
    def _parse_cnnvd_html_regex(self, html_content: str) -> Optional[Dict]:
        """使用正则表达式解析CNNVD HTML（备用方法）"""
        try:
            result = {
                'source': 'CNNVD',
                'title': '',
                'description': '',
                'severity': '',
                'cvss_score': None,
                'affected_products': [],
                'published_date': '',
                'updated_date': '',
                'references': []
            }
            
            # 提取标题
            title_match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
            if title_match:
                result['title'] = re.sub(r'<[^>]+>', '', title_match.group(1)).strip()
            
            # 提取描述
            desc_pattern = re.compile(r'(漏洞描述|漏洞详情|描述)[：:]\s*([^<]+)', re.IGNORECASE)
            desc_match = desc_pattern.search(html_content)
            if desc_match:
                result['description'] = desc_match.group(2).strip()
            
            # 提取严重程度
            severity_pattern = re.compile(r'(严重程度|危险等级)[：:]\s*(严重|高危|中危|低危|critical|high|medium|low)', re.IGNORECASE)
            severity_match = severity_pattern.search(html_content)
            if severity_match:
                result['severity'] = severity_match.group(2)
            
            # 提取CVSS评分
            cvss_pattern = re.compile(r'CVSS[:\s]*([\d.]+)', re.IGNORECASE)
            cvss_match = cvss_pattern.search(html_content)
            if cvss_match:
                try:
                    result['cvss_score'] = float(cvss_match.group(1))
                except (ValueError, TypeError):
                    pass
            
            # 提取日期
            date_pattern = re.compile(r'(\d{4}[-/]\d{1,2}[-/]\d{1,2})')
            dates = date_pattern.findall(html_content)
            if dates:
                result['published_date'] = dates[0]
                if len(dates) > 1:
                    result['updated_date'] = dates[1]
            
            # 提取链接
            url_pattern = re.compile(r'href=["\'](https?://[^"\']+)["\']', re.IGNORECASE)
            urls = url_pattern.findall(html_content)
            result['references'] = list(set(urls[:10]))  # 最多10个链接
            
            return result if result.get('title') or result.get('description') else None
            
        except Exception as e:
            logger.debug(f"CNNVD正则解析失败: {e}")
            return None
    
    def fetch_cnvd_info(self, cnvd_id: str = None, keyword: str = None) -> Optional[Dict]:
        """
        获取CNVD信息（带HTML解析）
        
        Args:
            cnvd_id: CNVD编号
            keyword: 关键词
            
        Returns:
            Dict: CNVD漏洞信息
        """
        cache_key = f"cnvd_{cnvd_id}_{keyword}"
        cached = self._load_cache(cache_key)
        if cached:
            return cached
        
        try:
            # 构建URL
            if cnvd_id:
                url = f"https://www.cnvd.org.cn/flaw/show/{cnvd_id}"
            else:
                # 搜索页面
                url = f"https://www.cnvd.org.cn/flaw/list?q={urllib.parse.quote(keyword)}"
            
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            
            with urllib.request.urlopen(req, timeout=15) as response:
                html_content = response.read().decode('utf-8', errors='ignore')
            
            # 解析HTML
            parsed_data = self.parse_cnvd_html(html_content)
            
            if parsed_data:
                parsed_data['cnvd_id'] = cnvd_id
                parsed_data['keyword'] = keyword
                parsed_data['url'] = url
                parsed_data['status'] = 'fetched'
                
                self._save_cache(cache_key, parsed_data)
                return parsed_data
            else:
                # 如果解析失败，返回基础信息
                base_data = {
                    'source': 'CNVD',
                    'cnvd_id': cnvd_id,
                    'keyword': keyword,
                    'url': url,
                    'status': 'cached',
                    'description': f'CNVD漏洞信息: {cnvd_id or keyword}',
                    'note': 'HTML解析失败，返回基础信息'
                }
                self._save_cache(cache_key, base_data)
                return base_data
                
        except (urllib.error.URLError, socket.timeout, Exception) as e:
            logger.debug(f"CNVD信息获取失败: {e}")
            return None
    
    def fetch_cnnvd_info(self, cnnvd_id: str = None, keyword: str = None) -> Optional[Dict]:
        """
        获取CNNVD信息（带HTML解析）
        
        Args:
            cnnvd_id: CNNVD编号
            keyword: 关键词
            
        Returns:
            Dict: CNNVD漏洞信息
        """
        cache_key = f"cnnvd_{cnnvd_id}_{keyword}"
        cached = self._load_cache(cache_key)
        if cached:
            return cached
        
        try:
            # 构建URL
            if cnnvd_id:
                url = f"https://www.cnnvd.org.cn/web/vulnerability/querylist.tag?CNNVD={cnnvd_id}"
            else:
                url = f"https://www.cnnvd.org.cn/web/vulnerability/querylist.tag?q={urllib.parse.quote(keyword)}"
            
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            
            with urllib.request.urlopen(req, timeout=15) as response:
                html_content = response.read().decode('utf-8', errors='ignore')
            
            # 解析HTML
            parsed_data = self.parse_cnnvd_html(html_content)
            
            if parsed_data:
                parsed_data['cnnvd_id'] = cnnvd_id
                parsed_data['keyword'] = keyword
                parsed_data['url'] = url
                parsed_data['status'] = 'fetched'
                
                self._save_cache(cache_key, parsed_data)
                return parsed_data
            else:
                # 如果解析失败，返回基础信息
                base_data = {
                    'source': 'CNNVD',
                    'cnnvd_id': cnnvd_id,
                    'keyword': keyword,
                    'url': url,
                    'status': 'cached',
                    'description': f'CNNVD漏洞信息: {cnnvd_id or keyword}',
                    'note': 'HTML解析失败，返回基础信息'
                }
                self._save_cache(cache_key, base_data)
                return base_data
                
        except (urllib.error.URLError, socket.timeout, Exception) as e:
            logger.debug(f"CNNVD信息获取失败: {e}")
            return None
    
    def merge_vulnerability_info(self, cve_id: str, port: int = None) -> Dict:
        """
        融合多个数据库的漏洞信息
        
        Args:
            cve_id: CVE编号
            port: 端口号（可选）
            
        Returns:
            Dict: 融合后的漏洞信息
        """
        # 检查本地库
        if cve_id in self.local_db:
            return self.local_db[cve_id]
        
        merged_info = {
            'cve_id': cve_id,
            'port': port,
            'sources': [],
            'descriptions': [],
            'cvss_scores': [],
            'severities': [],
            'affected_products': [],
            'references': [],
            'urls': [],
            'published_dates': [],
            'updated_dates': []
        }
        
        # 从NVD获取（主要来源）
        try:
            from ufw_analyzer import SecurityDatabaseManager
            db_manager = SecurityDatabaseManager()
            
            nvd_data = db_manager.query_nvd(cve_id)
            if nvd_data:
                merged_info['sources'].append('NVD')
                if nvd_data.get('description'):
                    merged_info['descriptions'].append(nvd_data['description'])
                if nvd_data.get('cvss_score'):
                    merged_info['cvss_scores'].append(nvd_data['cvss_score'])
                if nvd_data.get('severity'):
                    merged_info['severities'].append(nvd_data['severity'])
                if nvd_data.get('references'):
                    merged_info['references'].extend(nvd_data['references'])
                if nvd_data.get('url'):
                    merged_info['urls'].append(nvd_data['url'])
                if nvd_data.get('published_date'):
                    merged_info['published_dates'].append(nvd_data['published_date'])
        except Exception as e:
            logger.debug(f"NVD查询失败: {e}")
        
        # 从CNVD获取（HTML解析）
        cnvd_data = self.fetch_cnvd_info(keyword=cve_id)
        if cnvd_data and cnvd_data.get('status') == 'fetched':
            merged_info['sources'].append('CNVD')
            if cnvd_data.get('description'):
                merged_info['descriptions'].append(cnvd_data['description'])
            if cnvd_data.get('cvss_score'):
                merged_info['cvss_scores'].append(cnvd_data['cvss_score'])
            if cnvd_data.get('severity'):
                merged_info['severities'].append(cnvd_data['severity'])
            if cnvd_data.get('affected_products'):
                merged_info['affected_products'].extend(cnvd_data['affected_products'])
            if cnvd_data.get('url'):
                merged_info['urls'].append(cnvd_data['url'])
            if cnvd_data.get('published_date'):
                merged_info['published_dates'].append(cnvd_data['published_date'])
        
        # 从CNNVD获取（HTML解析）
        cnnvd_data = self.fetch_cnnvd_info(keyword=cve_id)
        if cnnvd_data and cnnvd_data.get('status') == 'fetched':
            merged_info['sources'].append('CNNVD')
            if cnnvd_data.get('description'):
                merged_info['descriptions'].append(cnnvd_data['description'])
            if cnnvd_data.get('cvss_score'):
                merged_info['cvss_scores'].append(cnvd_data['cvss_score'])
            if cnnvd_data.get('severity'):
                merged_info['severities'].append(cnnvd_data['severity'])
            if cnnvd_data.get('affected_products'):
                merged_info['affected_products'].extend(cnnvd_data['affected_products'])
            if cnnvd_data.get('url'):
                merged_info['urls'].append(cnnvd_data['url'])
            if cnnvd_data.get('published_date'):
                merged_info['published_dates'].append(cnnvd_data['published_date'])
        
        # 去重和整理
        merged_info['sources'] = list(set(merged_info['sources']))
        merged_info['descriptions'] = list(set(merged_info['descriptions']))
        merged_info['references'] = list(set(merged_info['references']))
        merged_info['urls'] = list(set(merged_info['urls']))
        merged_info['affected_products'] = list(set(merged_info['affected_products']))
        
        # 计算综合严重程度（取最高）
        if merged_info['severities']:
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, '严重': 0, '高危': 1, '中危': 2, '低危': 3}
            merged_info['final_severity'] = min(merged_info['severities'], 
                                                key=lambda x: severity_order.get(x.upper(), 99))
        else:
            merged_info['final_severity'] = 'UNKNOWN'
        
        # 计算平均CVSS评分
        if merged_info['cvss_scores']:
            merged_info['avg_cvss_score'] = sum(merged_info['cvss_scores']) / len(merged_info['cvss_scores'])
        else:
            merged_info['avg_cvss_score'] = None
        
        # 保存到本地库
        self.local_db[cve_id] = merged_info
        self._save_local_db()
        
        return merged_info
    
    def get_vulnerability_by_port(self, port: int) -> List[Dict]:
        """
        根据端口获取漏洞信息
        
        Args:
            port: 端口号
            
        Returns:
            List[Dict]: 漏洞信息列表
        """
        from ufw_analyzer import VulnerabilityDatabase
        
        vuln_db = VulnerabilityDatabase()
        port_info = vuln_db.get_port_info(port)
        
        if not port_info:
            return []
        
        vulnerabilities = []
        cves = port_info.get('common_cves', [])
        
        for cve_id in cves:
            merged_info = self.merge_vulnerability_info(cve_id, port)
            vulnerabilities.append(merged_info)
        
        return vulnerabilities
    
    def get_statistics(self) -> Dict:
        """获取安全库统计信息"""
        return {
            'total_records': len(self.local_db),
            'sources': list(set([info.get('sources', []) for info in self.local_db.values()])),
            'ports_covered': len(set([info.get('port') for info in self.local_db.values() if info.get('port')]))
        }

