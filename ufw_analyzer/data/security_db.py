#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
安全数据库管理器
集成国内外权威漏洞数据库（CVE, NVD, OSV, CNVD, CNNVD等）
"""

import os
import time
import hashlib
import json
import logging
import urllib.request
import urllib.error
from typing import Dict, List, Optional

# 获取日志记录器
logger = logging.getLogger('ufw_analyzer')

class SecurityDatabaseManager:
    """安全数据库管理器（集成国内外权威漏洞数据库）"""
    
    def __init__(self, cache_dir: str = ".vuln_cache", cache_ttl: int = 86400):
        """
        初始化安全数据库管理器
        cache_dir: 缓存目录
        cache_ttl: 缓存有效期（秒），默认24小时
        """
        self.cache_dir = cache_dir
        self.cache_ttl = cache_ttl
        
        # 确保缓存目录存在且有写权限
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
            # 测试写权限
            test_file = os.path.join(self.cache_dir, '.test_write')
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
        except (OSError, PermissionError) as e:
            logger.warning(f"缓存目录创建或权限检查失败: {self.cache_dir}, 错误: {e}")
            # 尝试使用用户主目录下的缓存目录
            import tempfile
            self.cache_dir = os.path.join(tempfile.gettempdir(), 'ufw_analyzer_cache')
            os.makedirs(self.cache_dir, exist_ok=True)
            logger.info(f"使用临时缓存目录: {self.cache_dir}")
        self.enabled_databases = {
            'cve': True,
            'nvd': True,
            'exploitdb': True,
            'osv': True,
            'cnvd': True,
            'cnnvd': True
        }
        
        # 创建缓存目录
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # 数据库API端点配置
        self.api_endpoints = {
            'cve': {
                'base_url': 'https://cve.mitre.org/api/cve/',
                'search_url': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=',
                'description': 'CVE (Common Vulnerabilities and Exposures)'
            },
            'nvd': {
                'base_url': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
                'description': 'NVD (National Vulnerability Database) - 无需API密钥'
            },
            'exploitdb': {
                'base_url': 'https://www.exploit-db.com/search',
                'api_url': 'https://gitlab.com/api/v4/projects/38868127/repository/files/',
                'description': 'Exploit Database (EDB)'
            },
            'osv': {
                'base_url': 'https://osv.dev/api/v1/query',
                'description': 'OSV (Open Source Vulnerability Database)'
            },
            'cnvd': {
                'base_url': 'https://www.cnvd.org.cn/flaw/list',
                'search_url': 'https://www.cnvd.org.cn/flaw/show/',
                'description': '国家信息安全漏洞共享平台 (CNVD)'
            },
            'cnnvd': {
                'base_url': 'https://www.cnnvd.org.cn/web/vulnerability/querylist.tag',
                'description': '国家信息安全漏洞库 (CNNVD)'
            }
        }
    
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
            # 记录缓存文件读取失败或格式错误，返回None
            logger.debug(f"缓存文件读取失败: cache_path={cache_path}, 错误类型: {type(e).__name__}, 错误: {e}")
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
            # 记录缓存文件写入失败，但不中断处理
            logger.warning(f"缓存文件写入失败: cache_path={cache_path}, 错误类型: {type(e).__name__}, 错误: {e}")
            pass
    
    def query_cve(self, cve_id: str) -> Optional[Dict]:
        """查询CVE信息"""
        if not self.enabled_databases.get('cve', False):
            return None
        
        cache_key = f"cve_{cve_id}"
        cached = self._load_cache(cache_key)
        if cached:
            return cached
        
        # CVE API访问（简化版，实际需要更复杂的解析）
        try:
            # 尝试从NVD获取（更详细的信息）
            if self.enabled_databases.get('nvd', False):
                nvd_data = self.query_nvd(cve_id)
                if nvd_data:
                    self._save_cache(cache_key, nvd_data)
                    return nvd_data
            
            # 基础CVE信息
            cve_data = {
                'cve_id': cve_id,
                'source': 'CVE',
                'url': f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
                'description': f'CVE漏洞编号: {cve_id}',
                'status': 'cached'
            }
            
            self._save_cache(cache_key, cve_data)
            return cve_data
        except Exception as e:
            return None
    
    def query_nvd(self, cve_id: str) -> Optional[Dict]:
        """查询NVD数据库"""
        if not self.enabled_databases.get('nvd', False):
            return None
        
        cache_key = f"nvd_{cve_id}"
        cached = self._load_cache(cache_key)
        if cached:
            return cached
        
        try:
            # NVD API v2.0 (需要API密钥，但也可以不使用)
            url = f"{self.api_endpoints['nvd']['base_url']}?cveId={cve_id}"
            
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'UFW-Analyzer/1.0')
            
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())
                
                if data.get('vulnerabilities'):
                    vuln = data['vulnerabilities'][0]['cve']
                    nvd_data = {
                        'cve_id': cve_id,
                        'source': 'NVD',
                        'description': vuln.get('descriptions', [{}])[0].get('value', ''),
                        'cvss_score': self._extract_cvss_score(vuln),
                        'severity': self._extract_severity(vuln),
                        'published_date': vuln.get('published', ''),
                        'modified_date': vuln.get('lastModified', ''),
                        'references': [ref.get('url', '') for ref in vuln.get('references', [])],
                        'url': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        'status': 'fetched'
                    }
                    
                    self._save_cache(cache_key, nvd_data)
                    return nvd_data
        except Exception as e:
            pass
        
        return None
    
    def query_osv(self, package_name: str = None, cve_id: str = None) -> Optional[Dict]:
        """查询OSV数据库"""
        if not self.enabled_databases.get('osv', False):
            return None
        
        cache_key = f"osv_{package_name}_{cve_id}"
        cached = self._load_cache(cache_key)
        if cached:
            return cached
        
        try:
            query_data = {}
            if cve_id:
                query_data['cve'] = cve_id
            if package_name:
                query_data['package'] = {'name': package_name}
            
            if not query_data:
                return None
            
            url = self.api_endpoints['osv']['base_url']
            data = json.dumps(query_data).encode()
            
            req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
            req.add_header('User-Agent', 'UFW-Analyzer/1.0')
            
            with urllib.request.urlopen(req, timeout=10) as response:
                result = json.loads(response.read().decode())
                
                if result.get('vulns'):
                    vuln = result['vulns'][0]
                    osv_data = {
                        'source': 'OSV',
                        'id': vuln.get('id', ''),
                        'summary': vuln.get('summary', ''),
                        'details': vuln.get('details', ''),
                        'severity': vuln.get('severity', []),
                        'references': vuln.get('references', []),
                        'url': f"https://osv.dev/vulnerability/{vuln.get('id', '')}",
                        'status': 'fetched'
                    }
                    
                    self._save_cache(cache_key, osv_data)
                    return osv_data
        except Exception as e:
            pass
        
        return None
    
    def query_cnvd(self, cnvd_id: str = None, keyword: str = None) -> Optional[Dict]:
        """查询CNVD数据库（国家信息安全漏洞共享平台，使用HTML解析）"""
        if not self.enabled_databases.get('cnvd', False):
            return None
        
        cache_key = f"cnvd_{cnvd_id}_{keyword}"
        cached = self._load_cache(cache_key)
        if cached:
            return cached
        
        try:
            # 使用统一安全库的HTML解析功能
            from unified_security_db import UnifiedSecurityDatabase
            unified_db = UnifiedSecurityDatabase()
            cnvd_data = unified_db.fetch_cnvd_info(cnvd_id, keyword)
            
            if cnvd_data:
                self._save_cache(cache_key, cnvd_data)
                return cnvd_data
            else:
                # 如果解析失败，返回基础信息
                base_data = {
                    'source': 'CNVD',
                    'cnvd_id': cnvd_id,
                    'keyword': keyword,
                    'url': f"https://www.cnvd.org.cn/flaw/show/{cnvd_id}" if cnvd_id else self.api_endpoints['cnvd']['base_url'],
                    'description': f'CNVD漏洞信息: {cnvd_id or keyword}',
                    'status': 'cached',
                    'note': 'HTML解析失败，返回基础信息'
                }
                self._save_cache(cache_key, base_data)
                return base_data
        except ImportError:
            # 如果unified_security_db不可用，返回基础信息
            logger.warning("统一安全库不可用，返回CNVD基础信息")
            base_data = {
                'source': 'CNVD',
                'cnvd_id': cnvd_id,
                'keyword': keyword,
                'url': f"https://www.cnvd.org.cn/flaw/show/{cnvd_id}" if cnvd_id else self.api_endpoints['cnvd']['base_url'],
                'description': f'CNVD漏洞信息: {cnvd_id or keyword}',
                'status': 'cached',
                'note': '统一安全库不可用'
            }
            return base_data
        except Exception as e:
            logger.debug(f"CNVD查询失败: {e}")
            return None
    
    def query_cnnvd(self, cnnvd_id: str = None, keyword: str = None) -> Optional[Dict]:
        """查询CNNVD数据库（国家信息安全漏洞库，使用HTML解析）"""
        if not self.enabled_databases.get('cnnvd', False):
            return None
        
        cache_key = f"cnnvd_{cnnvd_id}_{keyword}"
        cached = self._load_cache(cache_key)
        if cached:
            return cached
        
        try:
            # 使用统一安全库的HTML解析功能
            from unified_security_db import UnifiedSecurityDatabase
            unified_db = UnifiedSecurityDatabase()
            cnnvd_data = unified_db.fetch_cnnvd_info(cnnvd_id, keyword)
            
            if cnnvd_data:
                self._save_cache(cache_key, cnnvd_data)
                return cnnvd_data
            else:
                # 如果解析失败，返回基础信息
                base_data = {
                    'source': 'CNNVD',
                    'cnnvd_id': cnnvd_id,
                    'keyword': keyword,
                    'url': self.api_endpoints['cnnvd']['base_url'],
                    'description': f'CNNVD漏洞信息: {cnnvd_id or keyword}',
                    'status': 'cached',
                    'note': 'HTML解析失败，返回基础信息'
                }
                self._save_cache(cache_key, base_data)
                return base_data
        except ImportError:
            # 如果unified_security_db不可用，返回基础信息
            logger.warning("统一安全库不可用，返回CNNVD基础信息")
            base_data = {
                'source': 'CNNVD',
                'cnnvd_id': cnnvd_id,
                'keyword': keyword,
                'url': self.api_endpoints['cnnvd']['base_url'],
                'description': f'CNNVD漏洞信息: {cnnvd_id or keyword}',
                'status': 'cached',
                'note': '统一安全库不可用'
            }
            return base_data
        except Exception as e:
            logger.debug(f"CNNVD查询失败: {e}")
            return None
    
    def query_by_port(self, port: int) -> List[Dict]:
        """根据端口查询相关漏洞"""
        vulnerabilities = []
        
        # 从本地数据库获取端口相关的CVE
        port_cves = self._get_cves_by_port(port)
        
        for cve_id in port_cves:
            # 尝试从多个数据库查询
            cve_data = self.query_cve(cve_id)
            if cve_data:
                vulnerabilities.append(cve_data)
            
            nvd_data = self.query_nvd(cve_id)
            if nvd_data and nvd_data not in vulnerabilities:
                vulnerabilities.append(nvd_data)
        
        return vulnerabilities
    
    def _get_cves_by_port(self, port: int) -> List[str]:
        """根据端口获取相关CVE列表（从本地数据库）"""
        # 端口到CVE的映射（简化版，实际应该从更完整的数据库获取）
        port_cve_map = {
            22: ['CVE-2018-15473', 'CVE-2016-0777', 'CVE-2016-0778'],
            23: ['CVE-2020-10173'],
            80: ['CVE-2021-44228', 'CVE-2021-45046', 'CVE-2017-5638'],
            443: ['CVE-2014-0160', 'CVE-2014-0224'],
            3306: ['CVE-2021-27928', 'CVE-2020-14882'],
            3389: ['CVE-2019-0708', 'CVE-2020-0609', 'CVE-2021-34527'],
            6379: ['CVE-2019-10192', 'CVE-2015-4335'],
            27017: ['CVE-2019-2392', 'CVE-2016-6494'],
            1433: ['CVE-2019-1069', 'CVE-2018-8273'],
            5432: ['CVE-2019-9193', 'CVE-2018-1058'],
            445: ['CVE-2017-0144', 'CVE-2019-0708', 'CVE-2020-0796'],
            21: ['CVE-2020-1938', 'CVE-2019-12815'],
            1521: ['CVE-2020-14750', 'CVE-2019-2729']
        }
        
        return port_cve_map.get(port, [])
    
    def _extract_cvss_score(self, vuln: Dict) -> Optional[float]:
        """从NVD数据中提取CVSS分数"""
        try:
            metrics = vuln.get('metrics', {})
            if 'cvssMetricV31' in metrics:
                return float(metrics['cvssMetricV31'][0]['cvssData']['baseScore'])
            elif 'cvssMetricV30' in metrics:
                return float(metrics['cvssMetricV30'][0]['cvssData']['baseScore'])
            elif 'cvssMetricV2' in metrics:
                return float(metrics['cvssMetricV2'][0]['cvssData']['baseScore'])
        except (KeyError, TypeError, ValueError, IndexError) as e:
            # 记录CVSS分数提取错误，但不中断处理
            logger.debug(f"CVSS分数提取错误: vuln={vuln.get('id', 'unknown')}, 错误类型: {type(e).__name__}, 错误: {e}")
            pass
        return None
    
    def _extract_severity(self, vuln: Dict) -> str:
        """从NVD数据中提取严重程度"""
        try:
            metrics = vuln.get('metrics', {})
            if 'cvssMetricV31' in metrics:
                severity = metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseSeverity', '')
            elif 'cvssMetricV30' in metrics:
                severity = metrics['cvssMetricV30'][0].get('cvssData', {}).get('baseSeverity', '')
            elif 'cvssMetricV2' in metrics:
                score = float(metrics['cvssMetricV2'][0]['cvssData']['baseScore'])
                if score >= 9.0:
                    severity = 'CRITICAL'
                elif score >= 7.0:
                    severity = 'HIGH'
                elif score >= 4.0:
                    severity = 'MEDIUM'
                else:
                    severity = 'LOW'
            
            return severity.upper() if severity else 'UNKNOWN'
        except (KeyError, TypeError, ValueError, IndexError) as e:
            # 记录严重程度提取错误，返回UNKNOWN
            logger.debug(f"严重程度提取错误: vuln={vuln.get('id', 'unknown')}, 错误类型: {type(e).__name__}, 错误: {e}")
            return 'UNKNOWN'
    
    def get_enhanced_vulnerability_info(self, cve_id: str, port: int = None) -> Dict:
        """获取增强的漏洞信息（从多个数据库聚合，使用统一安全库）"""
        # 优先使用统一安全库
        try:
            from unified_security_db import UnifiedSecurityDatabase
            unified_db = UnifiedSecurityDatabase()
            merged_info = unified_db.merge_vulnerability_info(cve_id, port)
            
            # 转换为兼容格式
            enhanced_info = {
                'cve_id': cve_id,
                'sources': merged_info.get('sources', []),
                'descriptions': merged_info.get('descriptions', []),
                'cvss_scores': merged_info.get('cvss_scores', []),
                'severities': merged_info.get('severities', []),
                'references': merged_info.get('references', []),
                'urls': merged_info.get('urls', []),
                'final_severity': merged_info.get('final_severity', 'UNKNOWN'),
                'avg_cvss_score': merged_info.get('avg_cvss_score'),
                'affected_products': merged_info.get('affected_products', [])
            }
            
            return enhanced_info
        except ImportError:
            # 如果统一安全库不可用，使用原有方法
            logger.warning("统一安全库不可用，使用原有聚合方法")
            enhanced_info = {
                'cve_id': cve_id,
                'sources': [],
                'descriptions': [],
                'cvss_scores': [],
                'severities': [],
                'references': [],
                'urls': []
            }
            
            # 查询各个数据库
            cve_data = self.query_cve(cve_id)
            if cve_data:
                enhanced_info['sources'].append('CVE')
                if cve_data.get('description'):
                    enhanced_info['descriptions'].append(cve_data['description'])
                if cve_data.get('url'):
                    enhanced_info['urls'].append(cve_data['url'])
            
            nvd_data = self.query_nvd(cve_id)
            if nvd_data:
                enhanced_info['sources'].append('NVD')
                if nvd_data.get('description'):
                    enhanced_info['descriptions'].append(nvd_data['description'])
                if nvd_data.get('cvss_score'):
                    enhanced_info['cvss_scores'].append(nvd_data['cvss_score'])
                if nvd_data.get('severity'):
                    enhanced_info['severities'].append(nvd_data['severity'])
                if nvd_data.get('references'):
                    enhanced_info['references'].extend(nvd_data['references'])
                if nvd_data.get('url'):
                    enhanced_info['urls'].append(nvd_data['url'])
            
            osv_data = self.query_osv(cve_id=cve_id)
            if osv_data:
                enhanced_info['sources'].append('OSV')
                if osv_data.get('summary'):
                    enhanced_info['descriptions'].append(osv_data['summary'])
                if osv_data.get('references'):
                    enhanced_info['references'].extend(osv_data['references'])
                if osv_data.get('url'):
                    enhanced_info['urls'].append(osv_data['url'])
            
            cnvd_data = self.query_cnvd(keyword=cve_id)
            if cnvd_data:
                enhanced_info['sources'].append('CNVD')
                if cnvd_data.get('description'):
                    enhanced_info['descriptions'].append(cnvd_data['description'])
                if cnvd_data.get('url'):
                    enhanced_info['urls'].append(cnvd_data['url'])
            
            cnnvd_data = self.query_cnnvd(keyword=cve_id)
            if cnnvd_data:
                enhanced_info['sources'].append('CNNVD')
                if cnnvd_data.get('description'):
                    enhanced_info['descriptions'].append(cnnvd_data['description'])
                if cnnvd_data.get('url'):
                    enhanced_info['urls'].append(cnnvd_data['url'])
            
            # 去重
            enhanced_info['sources'] = list(set(enhanced_info['sources']))
            enhanced_info['descriptions'] = list(set(enhanced_info['descriptions']))
            enhanced_info['references'] = list(set(enhanced_info['references']))
            enhanced_info['urls'] = list(set(enhanced_info['urls']))
            
            return enhanced_info


