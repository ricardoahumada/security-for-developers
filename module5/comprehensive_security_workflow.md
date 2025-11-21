# Comprehensive Security Testing Workflow Integration

This document demonstrates how to integrate SAST, DAST, and WAF tools into a unified security testing pipeline for healthcare applications.

## Unified Security Pipeline Orchestration

```python
#!/usr/bin/env python3
"""
Comprehensive Security Testing Pipeline
Integrates SAST (SonarQube), DAST (OWASP ZAP), and WAF (AWS CloudFront) testing
"""

import os
import json
import time
import logging
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import subprocess
import tempfile

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SecurityPipelineOrchestrator:
    """Main orchestrator for comprehensive security testing pipeline"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.sast_scanner = SonarQubeScanner(config.get('sonarqube', {}))
        self.dast_scanner = DASTScanner(config.get('zap', {}))
        self.waf_monitor = WAFMonitor(config.get('waf', {}))
        self.results = {
            'pipeline_start': datetime.now().isoformat(),
            'sast_results': None,
            'dast_results': None,
            'waf_analysis': None,
            'overall_status': 'UNKNOWN',
            'compliance_status': {},
            'recommendations': []
        }
    
    def run_comprehensive_security_scan(self) -> Dict:
        """Execute complete security testing pipeline"""
        logger.info("Starting comprehensive security testing pipeline")
        
        try:
            # Phase 1: SAST (Static Application Security Testing)
            logger.info("Phase 1: Executing SAST analysis...")
            self.results['sast_results'] = self.sast_scanner.run_analysis()
            self.sast_scanner.wait_for_completion()
            self.results['sast_results'] = self.sast_scanner.get_results()
            
            # Phase 2: DAST (Dynamic Application Security Testing)
            logger.info("Phase 2: Executing DAST analysis...")
            self.results['dast_results'] = self.dast_scanner.run_scan(
                self.config['target_url'],
                scan_depth='comprehensive'
            )
            
            # Phase 3: WAF Analysis and Configuration Review
            logger.info("Phase 3: Analyzing WAF configuration...")
            self.results['waf_analysis'] = self.waf_monitor.analyze_configuration()
            
            # Phase 4: Compliance Assessment
            logger.info("Phase 4: Assessing compliance status...")
            self.results['compliance_status'] = self.assess_compliance()
            
            # Phase 5: Risk Assessment and Recommendations
            logger.info("Phase 5: Generating recommendations...")
            self.results['recommendations'] = self.generate_recommendations()
            
            # Phase 6: Overall Status Determination
            self.results['overall_status'] = self.determine_overall_status()
            self.results['pipeline_end'] = datetime.now().isoformat()
            
            # Generate final report
            self.generate_security_report()
            
            return self.results
            
        except Exception as e:
            logger.error(f"Security pipeline failed: {e}")
            self.results['overall_status'] = 'FAILED'
            self.results['error'] = str(e)
            return self.results
    
    def assess_compliance(self) -> Dict:
        """Assess compliance with healthcare security standards"""
        compliance_results = {
            'hipaa': self._assess_hipaa_compliance(),
            'soc2': self._assess_soc2_compliance(),
            'nist': self._assess_nist_compliance()
        }
        
        overall_compliant = all(
            result['compliant'] for result in compliance_results.values()
        )
        
        return {
            'overall_compliant': overall_compliant,
            'standards': compliance_results,
            'assessment_date': datetime.now().isoformat()
        }
    
    def _assess_hipaa_compliance(self) -> Dict:
        """Assess HIPAA compliance based on security test results"""
        # Analyze SAST findings for PHI protection
        sast_findings = self.results.get('sast_results', {}).get('findings', [])
        phi_protection_score = self._calculate_phi_protection_score(sast_findings)
        
        # Analyze DAST findings for data exposure
        dast_findings = self.results.get('dast_results', {}).get('alerts', [])
        data_exposure_score = self._calculate_data_exposure_score(dast_findings)
        
        # Analyze WAF configuration for access controls
        waf_protection_score = self.results.get('waf_analysis', {}).get('protection_score', 0)
        
        hipaa_score = (phi_protection_score + data_exposure_score + waf_protection_score) / 3
        
        return {
            'compliant': hipaa_score >= 85,
            'score': hipaa_score,
            'requirements': {
                'access_control': waf_protection_score >= 90,
                'audit_logging': self._check_audit_logging(),
                'data_protection': phi_protection_score >= 80,
                'transmission_security': self._check_transmission_security()
            }
        }
    
    def generate_recommendations(self) -> List[Dict]:
        """Generate actionable security recommendations"""
        recommendations = []
        
        # SAST-based recommendations
        if self.results.get('sast_results'):
            sast_issues = self.results['sast_results'].get('security_issues', [])
            for issue in sast_issues:
                if issue['severity'] in ['HIGH', 'CRITICAL']:
                    recommendations.append({
                        'category': 'SAST',
                        'priority': 'HIGH',
                        'title': f'Fix {issue["type"]} vulnerability',
                        'description': issue['description'],
                        'component': issue['component'],
                        'remediation': issue['remediation']
                    })
        
        # DAST-based recommendations
        if self.results.get('dast_results'):
            dast_alerts = self.results['dast_results'].get('critical_alerts', [])
            for alert in dast_alerts:
                recommendations.append({
                    'category': 'DAST',
                    'priority': alert.get('risk', 'MEDIUM').upper(),
                    'title': f'Mitigate {alert["name"]}',
                    'description': alert['description'],
                    'url': alert.get('url', 'N/A'),
                    'remediation': alert.get('solution', 'Implement security controls')
                })
        
        # WAF-based recommendations
        if self.results.get('waf_analysis'):
            waf_gaps = self.results['waf_analysis'].get('protection_gaps', [])
            for gap in waf_gaps:
                recommendations.append({
                    'category': 'WAF',
                    'priority': gap['severity'].upper(),
                    'title': f'Enhance {gap["protection_type"]} protection',
                    'description': gap['description'],
                    'current_score': gap['current_score'],
                    'remediation': gap['recommendation']
                })
        
        return sorted(recommendations, key=lambda x: x['priority'] != 'HIGH', reverse=True)
    
    def determine_overall_status(self) -> str:
        """Determine overall security pipeline status"""
        if not all([
            self.results.get('sast_results'),
            self.results.get('dast_results'),
            self.results.get('waf_analysis')
        ]):
            return 'INCOMPLETE'
        
        # Count critical issues
        critical_count = 0
        
        # SAST critical issues
        sast_critical = len([
            f for f in self.results['sast_results'].get('security_issues', [])
            if f['severity'] == 'CRITICAL'
        ])
        critical_count += sast_critical
        
        # DAST high-risk issues
        dast_high = len([
            a for a in self.results['dast_results'].get('alerts', [])
            if a.get('risk', '').lower() in ['high', 'critical']
        ])
        critical_count += dast_high
        
        # WAF protection gaps
        waf_gaps = len([
            g for g in self.results['waf_analysis'].get('protection_gaps', [])
            if g['severity'] == 'CRITICAL'
        ])
        critical_count += waf_gaps
        
        # Determine status
        if critical_count == 0:
            return 'SECURE'
        elif critical_count <= 3:
            return 'ACCEPTABLE'
        elif critical_count <= 10:
            return 'VULNERABLE'
        else:
            return 'CRITICAL'

class SonarQubeScanner:
    """SAST scanner using SonarQube"""
    
    def __init__(self, config: Dict):
        self.base_url = config.get('base_url', 'https://sonarqube.example.com')
        self.token = config.get('token')
        self.project_key = config.get('project_key')
        self.headers = {'Authorization': f'Bearer {self.token}'}
        self.scan_id = None
    
    def run_analysis(self) -> Dict:
        """Initiate SonarQube analysis"""
        analysis_config = {
            'projectKey': self.project_key,
            'sources': 'src/main/java',
            'tests': 'src/test/java',
            'java.binaries': 'target/classes',
            'java.coveragePlugin': 'jacoco'
        }
        
        # Trigger analysis via Jenkins or CI/CD
        response = requests.post(
            f"{self.base_url}/api/qualitygates/project_status",
            headers=self.headers,
            json=analysis_config
        )
        
        if response.status_code == 200:
            self.scan_id = response.json().get('taskId')
            return {'status': 'started', 'scan_id': self.scan_id}
        else:
            raise Exception(f"Failed to start SAST analysis: {response.text}")
    
    def wait_for_completion(self, timeout_minutes: int = 30):
        """Wait for SAST analysis to complete"""
        timeout = timeout_minutes * 60
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            status_response = requests.get(
                f"{self.base_url}/api/ce/task?id={self.scan_id}",
                headers=self.headers
            )
            
            if status_response.status_code == 200:
                task_status = status_response.json().get('task', {}).get('status')
                
                if task_status == 'SUCCESS':
                    logger.info("SAST analysis completed successfully")
                    return True
                elif task_status == 'FAILED':
                    raise Exception("SAST analysis failed")
                elif task_status in ['PENDING', 'IN_PROGRESS']:
                    time.sleep(30)
                    continue
            
            raise Exception(f"Failed to check SAST analysis status")
        
        raise Exception("SAST analysis timed out")
    
    def get_results(self) -> Dict:
        """Retrieve SAST analysis results"""
        # Get security hotspots
        hotspots_response = requests.get(
            f"{self.base_url}/api/hotspots/search?projectKey={self.project_key}",
            headers=self.headers
        )
        
        # Get vulnerabilities
        vulnerabilities_response = requests.get(
            f"{self.base_url}/api/issues/search?componentKeys={self.project_key}&types=VULNERABILITY",
            headers=self.headers
        )
        
        # Get code smells
        codesmells_response = requests.get(
            f"{self.base_url}/api/issues/search?componentKeys={self.project_key}&types=CODE_SMELL",
            headers=self.headers
        )
        
        return {
            'security_hotspots': hotspots_response.json() if hotspots_response.status_code == 200 else {},
            'vulnerabilities': vulnerabilities_response.json() if vulnerabilities_response.status_code == 200 else {},
            'code_smells': codesmells_response.json() if codesmells_response.status_code == 200 else {},
            'security_issues': self._extract_security_issues(vulnerabilities_response.json() if vulnerabilities_response.status_code == 200 else {}),
            'quality_gate_status': self._get_quality_gate_status()
        }
    
    def _extract_security_issues(self, vulnerabilities_data: Dict) -> List[Dict]:
        """Extract and categorize security issues"""
        issues = []
        
        for issue in vulnerabilities_data.get('issues', []):
            issues.append({
                'id': issue.get('key'),
                'type': issue.get('type'),
                'severity': issue.get('severity'),
                'component': issue.get('component'),
                'description': issue.get('message'),
                'remediation': self._get_remediation_guidance(issue.get('type', ''))
            })
        
        return issues
    
    def _get_remediation_guidance(self, issue_type: str) -> str:
        """Get remediation guidance for specific issue types"""
        guidance_map = {
            'SQL_INJECTION': 'Use parameterized queries and input validation',
            'XSS': 'Implement output encoding and Content Security Policy',
            'HARDCODED_CREDENTIALS': 'Remove hardcoded credentials and use environment variables',
            'PATH_TRAVERSAL': 'Validate file paths and use allowlists'
        }
        return guidance_map.get(issue_type, 'Review OWASP guidelines for remediation')
    
    def _get_quality_gate_status(self) -> Dict:
        """Get quality gate project status"""
        response = requests.get(
            f"{self.base_url}/api/qualitygates/project_status?projectKey={self.project_key}",
            headers=self.headers
        )
        
        if response.status_code == 200:
            return response.json().get('projectStatus', {})
        return {}

class DASTScanner:
    """DAST scanner using OWASP ZAP"""
    
    def __init__(self, config: Dict):
        self.base_url = config.get('base_url', 'http://localhost:8080')
        self.api_key = config.get('api_key')
        self.headers = {'X-ZAP-API-Key': self.api_key}
    
    def run_scan(self, target_url: str, scan_depth: str = 'standard') -> Dict:
        """Execute DAST scan using OWASP ZAP"""
        
        # Phase 1: Spider scan for URL discovery
        spider_id = self._start_spider_scan(target_url)
        self._wait_for_spider_completion(spider_id)
        
        # Phase 2: Active scan for vulnerability detection
        active_scan_id = self._start_active_scan(target_url)
        self._wait_for_active_scan_completion(active_scan_id)
        
        # Phase 3: Generate comprehensive report
        return self._get_scan_results(target_url)
    
    def _start_spider_scan(self, target_url: str) -> str:
        """Start spider scan for URL discovery"""
        response = requests.get(
            f"{self.base_url}/JSON/spider/action/scan/",
            headers=self.headers,
            params={'url': target_url, 'maxDepth': 3}
        )
        
        if response.status_code == 200:
            return response.json().get('scan')
        raise Exception("Failed to start spider scan")
    
    def _wait_for_spider_completion(self, scan_id: str):
        """Wait for spider scan to complete"""
        while True:
            status_response = requests.get(
                f"{self.base_url}/JSON/spider/view/status/",
                headers=self.headers,
                params={'scanId': scan_id}
            )
            
            if status_response.status_code == 200:
                status = int(status_response.json().get('status', '0'))
                
                if status >= 100:
                    logger.info("Spider scan completed")
                    return True
                
                time.sleep(10)
            
            raise Exception("Failed to check spider scan status")
    
    def _start_active_scan(self, target_url: str) -> str:
        """Start active vulnerability scan"""
        response = requests.get(
            f"{self.base_url}/JSON/ascan/action/scan/",
            headers=self.headers,
            params={'url': target_url, 'recurse': 'true'}
        )
        
        if response.status_code == 200:
            return response.json().get('scan')
        raise Exception("Failed to start active scan")
    
    def _wait_for_active_scan_completion(self, scan_id: str):
        """Wait for active scan to complete"""
        while True:
            status_response = requests.get(
                f"{self.base_url}/JSON/ascan/view/status/",
                headers=self.headers,
                params={'scanId': scan_id}
            )
            
            if status_response.status_code == 200:
                status = int(status_response.json().get('status', '0'))
                
                if status >= 100:
                    logger.info("Active scan completed")
                    return True
                
                time.sleep(15)
            
            raise Exception("Failed to check active scan status")
    
    def _get_scan_results(self, target_url: str) -> Dict:
        """Retrieve and analyze DAST scan results"""
        # Get alerts
        alerts_response = requests.get(
            f"{self.base_url}/JSON/alert/view/alerts/",
            headers=self.headers,
            params={'baseurl': target_url}
        )
        
        alerts = alerts_response.json().get('alerts', []) if alerts_response.status_code == 200 else []
        
        # Categorize alerts
        critical_alerts = [alert for alert in alerts 
                          if alert.get('risk', '').lower() in ['high', 'critical']]
        medium_alerts = [alert for alert in alerts 
                        if alert.get('risk', '').lower() == 'medium']
        low_alerts = [alert for alert in alerts 
                     if alert.get('risk', '').lower() in ['low', 'informational']]
        
        return {
            'total_alerts': len(alerts),
            'critical_alerts': critical_alerts,
            'medium_alerts': medium_alerts,
            'low_alerts': low_alerts,
            'alerts': alerts,
            'scan_summary': {
                'sql_injection_attempts': len([a for a in alerts if 'sql' in a.get('name', '').lower()]),
                'xss_attempts': len([a for a in alerts if 'xss' in a.get('name', '').lower()]),
                'authentication_bypass': len([a for a in alerts if 'auth' in a.get('name', '').lower()]),
                'data_exposure': len([a for a in alerts if 'exposure' in a.get('name', '').lower()])
            }
        }

class WAFMonitor:
    """WAF configuration analyzer"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.cloudfront_dist_id = config.get('cloudfront_distribution_id')
        self.waf_web_acl_id = config.get('waf_web_acl_id')
    
    def analyze_configuration(self) -> Dict:
        """Analyze WAF configuration and protection coverage"""
        
        # Check SQL injection protection
        sql_protection_score = self._check_sql_injection_protection()
        
        # Check XSS protection
        xss_protection_score = self._check_xss_protection()
        
        # Check rate limiting
        rate_limiting_score = self._check_rate_limiting()
        
        # Check geo-blocking
        geo_blocking_score = self._check_geo_blocking()
        
        # Check bot protection
        bot_protection_score = self._check_bot_protection()
        
        # Calculate overall protection score
        protection_score = (
            sql_protection_score + 
            xss_protection_score + 
            rate_limiting_score + 
            geo_blocking_score + 
            bot_protection_score
        ) / 5
        
        # Identify protection gaps
        protection_gaps = self._identify_protection_gaps(
            sql_protection_score, xss_protection_score, 
            rate_limiting_score, geo_blocking_score, bot_protection_score
        )
        
        return {
            'protection_score': protection_score,
            'protection_breakdown': {
                'sql_injection': sql_protection_score,
                'xss_protection': xss_protection_score,
                'rate_limiting': rate_limiting_score,
                'geo_blocking': geo_blocking_score,
                'bot_protection': bot_protection_score
            },
            'protection_gaps': protection_gaps,
            'recommended_improvements': self._generate_waf_recommendations(protection_gaps)
        }
    
    def _check_sql_injection_protection(self) -> int:
        """Check SQL injection protection coverage"""
        # Simulated WAF rule analysis
        sql_rules = [
            'union.*select',
            'drop.*table',
            'insert.*into',
            'script.*select'
        ]
        
        coverage = len(sql_rules) * 20  # Each rule adds 20% coverage
        return min(coverage, 100)
    
    def _check_xss_protection(self) -> int:
        """Check XSS protection coverage"""
        # Simulated XSS rule analysis
        xss_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'onerror\s*=',
            r'onload\s*='
        ]
        
        coverage = len(xss_patterns) * 25  # Each pattern adds 25% coverage
        return min(coverage, 100)
    
    def _check_rate_limiting(self) -> int:
        """Check rate limiting configuration"""
        # Simulated rate limiting analysis
        if self.config.get('rate_limit_rules', 0) >= 3:
            return 100
        elif self.config.get('rate_limit_rules', 0) >= 1:
            return 70
        else:
            return 20
    
    def _check_geo_blocking(self) -> int:
        """Check geo-blocking configuration"""
        allowed_countries = self.config.get('allowed_countries', [])
        
        if len(allowed_countries) == 0:
            return 0
        elif len(allowed_countries) <= 10:
            return 80
        else:
            return 90
    
    def _check_bot_protection(self) -> int:
        """Check bot protection configuration"""
        if self.config.get('bot_protection_enabled', False):
            return 95
        else:
            return 30
    
    def _identify_protection_gaps(self, sql_score: int, xss_score: int, 
                                 rate_score: int, geo_score: int, bot_score: int) -> List[Dict]:
        """Identify specific protection gaps"""
        gaps = []
        
        if sql_score < 80:
            gaps.append({
                'protection_type': 'SQL Injection',
                'current_score': sql_score,
                'severity': 'HIGH' if sql_score < 60 else 'MEDIUM',
                'description': 'Insufficient SQL injection protection rules',
                'recommendation': 'Add comprehensive SQL injection detection rules'
            })
        
        if xss_score < 80:
            gaps.append({
                'protection_type': 'Cross-Site Scripting',
                'current_score': xss_score,
                'severity': 'HIGH' if xss_score < 60 else 'MEDIUM',
                'description': 'Insufficient XSS protection coverage',
                'recommendation': 'Implement comprehensive XSS filtering rules'
            })
        
        if rate_score < 90:
            gaps.append({
                'protection_type': 'Rate Limiting',
                'current_score': rate_score,
                'severity': 'MEDIUM',
                'description': 'Rate limiting rules may be insufficient',
                'recommendation': 'Implement multi-tier rate limiting for different endpoints'
            })
        
        if geo_score < 80:
            gaps.append({
                'protection_type': 'Geographic Restrictions',
                'current_score': geo_score,
                'severity': 'LOW',
                'description': 'Limited geographic access controls',
                'recommendation': 'Implement geo-blocking for enhanced security'
            })
        
        if bot_score < 80:
            gaps.append({
                'protection_type': 'Bot Protection',
                'current_score': bot_score,
                'severity': 'MEDIUM',
                'description': 'Bot protection may be inadequate',
                'recommendation': 'Enable advanced bot management features'
            })
        
        return gaps
    
    def _generate_waf_recommendations(self, gaps: List[Dict]) -> List[str]:
        """Generate specific WAF improvement recommendations"""
        recommendations = []
        
        for gap in gaps:
            if gap['protection_type'] == 'SQL Injection':
                recommendations.append(
                    'Implement ModSecurity Core Rule Set (CRS) for comprehensive SQL injection protection'
                )
            elif gap['protection_type'] == 'Cross-Site Scripting':
                recommendations.append(
                    'Deploy CSP headers and XSS filtering rules in WAF configuration'
                )
            elif gap['protection_type'] == 'Rate Limiting':
                recommendations.append(
                    'Configure different rate limits for different API endpoints and user roles'
                )
            elif gap['protection_type'] == 'Geographic Restrictions':
                recommendations.append(
                    'Implement country-based access controls for healthcare data protection'
                )
            elif gap['protection_type'] == 'Bot Protection':
                recommendations.append(
                    'Enable bot scoring and challenge mechanisms to prevent automated attacks'
                )
        
        return recommendations

# Utility methods for compliance assessment
class ComplianceAssessment:
    """Helper methods for compliance assessment"""
    
    @staticmethod
    def _calculate_phi_protection_score(sast_findings: List[Dict]) -> int:
        """Calculate PHI protection score based on SAST findings"""
        phi_related_issues = [
            f for f in sast_findings 
            if any(keyword in f.get('description', '').lower() 
                  for keyword in ['patient', 'medical', 'phi', 'health', 'record'])
        ]
        
        critical_issues = len([i for i in phi_related_issues if i.get('severity') == 'CRITICAL'])
        high_issues = len([i for i in phi_related_issues if i.get('severity') == 'HIGH'])
        
        # Deduct points for security issues
        deductions = (critical_issues * 30) + (high_issues * 15)
        base_score = 100 - deductions
        
        return max(base_score, 0)
    
    @staticmethod
    def _calculate_data_exposure_score(dast_findings: List[Dict]) -> int:
        """Calculate data exposure score based on DAST findings"""
        exposure_related_alerts = [
            a for a in dast_findings 
            if any(keyword in a.get('name', '').lower() 
                  for keyword in ['exposure', 'disclosure', 'information', 'directory'])
        ]
        
        high_risk_exposure = len([
            a for a in exposure_related_alerts 
            if a.get('risk', '').lower() in ['high', 'critical']
        ])
        
        # Deduct points for data exposure vulnerabilities
        deductions = high_risk_exposure * 25
        base_score = 100 - deductions
        
        return max(base_score, 0)

# Example usage and configuration
if __name__ == "__main__":
    # Configuration
    security_config = {
        'target_url': 'https://health-portal.example.com',
        'sonarqube': {
            'base_url': 'https://sonarqube.example.com',
            'token': os.getenv('SONARQUBE_TOKEN'),
            'project_key': 'health-portal-main'
        },
        'zap': {
            'base_url': 'http://localhost:8080',
            'api_key': os.getenv('ZAP_API_KEY')
        },
        'waf': {
            'cloudfront_distribution_id': 'E123ABC456',
            'waf_web_acl_id': 'arn:aws:wafv2:us-east-1:123456789012:global/webacl/health-portal-waf/abcdef12-3456-7890-abcd-ef1234567890',
            'rate_limit_rules': 3,
            'allowed_countries': ['US', 'CA', 'MX'],
            'bot_protection_enabled': True
        }
    }
    
    # Run comprehensive security pipeline
    orchestrator = SecurityPipelineOrchestrator(security_config)
    
    try:
        results = orchestrator.run_comprehensive_security_scan()
        
        # Save results
        with open('comprehensive-security-report.json', 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\nSecurity Pipeline Complete!")
        print(f"Overall Status: {results['overall_status']}")
        print(f"Compliance Status: {results['compliance_status']['overall_compliant']}")
        print(f"Total Recommendations: {len(results['recommendations'])}")
        
        # Exit with appropriate code
        exit_code = 0 if results['overall_status'] in ['SECURE', 'ACCEPTABLE'] else 1
        exit(exit_code)
        
    except Exception as e:
        logger.error(f"Security pipeline execution failed: {e}")
        exit(1)
```

This comprehensive security testing workflow demonstrates how to integrate SAST, DAST, and WAF tools into a unified pipeline that provides:

1. **Complete Security Coverage**: Tests applications at multiple layers (code, runtime, network)
2. **Compliance Assessment**: Specifically evaluates HIPAA and other healthcare compliance requirements
3. **Actionable Insights**: Provides prioritized recommendations for security improvements
4. **Automation**: Fully automated pipeline suitable for CI/CD integration
5. **Comprehensive Reporting**: Generates detailed reports for both technical and executive stakeholders

The pipeline can be easily adapted for different compliance frameworks and security requirements by modifying the configuration and assessment criteria.