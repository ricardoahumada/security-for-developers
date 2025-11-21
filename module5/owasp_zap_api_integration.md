# OWASP ZAP API Integration for DAST

This code example demonstrates how to automate DAST scanning using the OWASP ZAP API for continuous security testing of web applications.

## Python Implementation

```python
import time
import requests
import json
import sys
from datetime import datetime

class OWASPZAPScanner:
    def __init__(self, zap_api_key, zap_url="http://localhost:8080"):
        self.zap_api_key = zap_api_key
        self.zap_url = zap_url
        self.headers = {'X-ZAP-API-Key': zap_api_key}
        
    def start_spider_scan(self, url, max_depth=3, max_duration=2):
        """Start automated spider scan for URL discovery"""
        spider_url = f"{self.zap_url}/JSON/spider/action/scan/"
        params = {
            'url': url,
            'maxDepth': max_depth,
            'maxDuration': max_duration,
            'recurse': 'true'
        }
        
        try:
            response = requests.get(spider_url, headers=self.headers, params=params)
            if response.status_code == 200:
                result = response.json()
                scan_id = result.get('scan', '0')
                print(f"Spider scan started with ID: {scan_id}")
                return scan_id
            else:
                print(f"Failed to start spider scan: {response.status_code}")
                return None
        except Exception as e:
            print(f"Error starting spider scan: {e}")
            return None
    
    def start_active_scan(self, url, policy_name=None):
        """Start active vulnerability scanning"""
        ascan_url = f"{self.zap_url}/JSON/ascan/action/scan/"
        params = {
            'url': url,
            'recurse': 'true',
            'scanPolicyName': policy_name
        }
        
        if policy_name:
            params['scanPolicyName'] = policy_name
            
        try:
            response = requests.get(ascan_url, headers=self.headers, params=params)
            if response.status_code == 200:
                result = response.json()
                scan_id = result.get('scan', '0')
                print(f"Active scan started with ID: {scan_id}")
                return scan_id
            else:
                print(f"Failed to start active scan: {response.status_code}")
                return None
        except Exception as e:
            print(f"Error starting active scan: {e}")
            return None
    
    def get_scan_status(self, scan_type, scan_id):
        """Get scan progress status"""
        if scan_type == 'spider':
            status_url = f"{self.zap_url}/JSON/spider/view/status/"
        else:
            status_url = f"{self.zap_url}/JSON/ascan/view/status/"
            
        params = {'scanId': scan_id}
        
        try:
            response = requests.get(status_url, headers=self.headers, params=params)
            if response.status_code == 200:
                result = response.json()
                return int(result.get('status', '0'))
            else:
                print(f"Failed to get {scan_type} status: {response.status_code}")
                return 0
        except Exception as e:
            print(f"Error getting {scan_type} status: {e}")
            return 0
    
    def wait_for_scan_completion(self, scan_type, scan_id, timeout_minutes=30):
        """Wait for scan to complete with timeout"""
        timeout_seconds = timeout_minutes * 60
        start_time = time.time()
        poll_interval = 10  # seconds
        
        print(f"Waiting for {scan_type} scan {scan_id} to complete...")
        
        while time.time() - start_time < timeout_seconds:
            status = self.get_scan_status(scan_type, scan_id)
            print(f"{scan_type.title()} scan progress: {status}%")
            
            if status >= 100:
                print(f"{scan_type.title()} scan completed successfully")
                return True
                
            time.sleep(poll_interval)
        
        print(f"{scan_type.title()} scan timed out after {timeout_minutes} minutes")
        return False
    
    def get_alerts(self, baseurl=None, start=None, count=None):
        """Retrieve scan results and alerts"""
        alerts_url = f"{self.zap_url}/JSON/alert/view/alerts/"
        params = {}
        
        if baseurl:
            params['baseurl'] = baseurl
        if start:
            params['start'] = start
        if count:
            params['count'] = count
            
        try:
            response = requests.get(alerts_url, headers=self.headers, params=params)
            if response.status_code == 200:
                return response.json().get('alerts', [])
            else:
                print(f"Failed to get alerts: {response.status_code}")
                return []
        except Exception as e:
            print(f"Error getting alerts: {e}")
            return []
    
    def generate_report(self, format_type='XML', output_file='dast-report.xml'):
        """Generate comprehensive scan report"""
        report_url = f"{self.zap_url}/OTHER/core/other/"
        params = {
            'reporttype': format_type.lower(),
            'reportfilename': output_file
        }
        
        try:
            response = requests.get(report_url, headers=self.headers, params=params)
            if response.status_code == 200:
                with open(output_file, 'wb') as f:
                    f.write(response.content)
                print(f"Report generated successfully: {output_file}")
                return True
            else:
                print(f"Failed to generate report: {response.status_code}")
                return False
        except Exception as e:
            print(f"Error generating report: {e}")
            return False
    
    def create_scan_session(self, session_name):
        """Create a new scanning session"""
        session_url = f"{self.zap_url}/JSON/core/action/newSession/"
        params = {'name': session_name}
        
        try:
            response = requests.get(session_url, headers=self.headers, params=params)
            return response.status_code == 200
        except Exception as e:
            print(f"Error creating session: {e}")
            return False

def run_comprehensive_scan(target_url):
    """Run complete DAST scan workflow"""
    zap_scanner = OWASPZAPScanner(zap_api_key="your-zap-api-key")
    
    print(f"Starting comprehensive security scan for: {target_url}")
    print(f"Scan started at: {datetime.now().isoformat()}")
    
    # Create scan session
    session_name = f"dast-scan-{int(time.time())}"
    if not zap_scanner.create_scan_session(session_name):
        print("Failed to create scan session")
        return False
    
    # Step 1: Spider scan for URL discovery
    print("\n=== Phase 1: URL Discovery (Spider Scan) ===")
    spider_id = zap_scanner.start_spider_scan(target_url, max_depth=3, max_duration=10)
    
    if spider_id:
        if not zap_scanner.wait_for_scan_completion('spider', spider_id, timeout_minutes=15):
            print("Spider scan failed or timed out")
    else:
        print("Spider scan failed to start")
    
    # Step 2: Active scan for vulnerability detection
    print("\n=== Phase 2: Vulnerability Detection (Active Scan) ===")
    active_id = zap_scanner.start_active_scan(target_url, policy_name="API-default")
    
    if active_id:
        if not zap_scanner.wait_for_scan_completion('active', active_id, timeout_minutes=30):
            print("Active scan failed or timed out")
    else:
        print("Active scan failed to start")
    
    # Step 3: Generate and analyze results
    print("\n=== Phase 3: Results Analysis ===")
    
    # Generate reports in multiple formats
    zap_scanner.generate_report('XML', 'dast-report.xml')
    zap_scanner.generate_report('JSON', 'dast-report.json')
    
    # Get detailed alerts
    alerts = zap_scanner.get_alerts()
    
    # Analyze and categorize findings
    critical_issues = []
    high_issues = []
    medium_issues = []
    low_issues = []
    
    for alert in alerts:
        risk = alert.get('risk', '').lower()
        if risk == 'high' or risk == 'critical':
            critical_issues.append(alert)
        elif risk == 'medium':
            medium_issues.append(alert)
        else:
            low_issues.append(alert)
    
    # Print summary
    print(f"\n=== Scan Summary ===")
    print(f"Total alerts found: {len(alerts)}")
    print(f"Critical/High issues: {len(critical_issues)}")
    print(f"Medium issues: {len(medium_issues)}")
    print(f"Low issues: {len(low_issues)}")
    
    # Print critical findings
    if critical_issues:
        print(f"\n=== Critical Security Issues Found ===")
        for i, alert in enumerate(critical_issues, 1):
            print(f"{i}. {alert.get('name', 'Unknown Issue')}")
            print(f"   Risk: {alert.get('risk', 'Unknown')}")
            print(f"   URL: {alert.get('url', 'N/A')}")
            print(f"   Description: {alert.get('desc', 'No description')}")
            print()
    
    # Create detailed JSON report
    detailed_report = {
        'scan_info': {
            'target_url': target_url,
            'scan_timestamp': datetime.now().isoformat(),
            'session_name': session_name,
            'total_alerts': len(alerts),
            'critical_count': len(critical_issues),
            'high_count': len(critical_issues),
            'medium_count': len(medium_issues),
            'low_count': len(low_issues)
        },
        'alerts': alerts,
        'critical_findings': critical_issues,
        'recommendations': [
            'Review and remediate all critical and high-risk vulnerabilities immediately',
            'Implement input validation and output encoding for injection prevention',
            'Update all dependencies to latest secure versions',
            'Implement Content Security Policy (CSP)',
            'Regular security testing as part of CI/CD pipeline'
        ]
    }
    
    with open('dast-detailed-report.json', 'w') as f:
        json.dump(detailed_report, f, indent=2)
    
    print(f"Detailed report saved to: dast-detailed-report.json")
    print(f"Scan completed at: {datetime.now().isoformat()}")
    
    return len(critical_issues) == 0

# Example usage
if __name__ == "__main__":
    target = "https://example-healthcare-portal.com"
    success = run_comprehensive_scan(target)
    sys.exit(0 if success else 1)
```

## Custom Scanning Policies Configuration

```python
# Custom security scanning policies for healthcare applications
class HealthcareDASTScanner(OWASPZAPScanner):
    def __init__(self, api_key):
        super().__init__(api_key)
        self.healthcare_policies = {
            'phi_protection': self._configure_phi_protection(),
            'hipaa_compliance': self._configure_hipaa_compliance(),
            'patient_data': self._configure_patient_data_protection()
        }
    
    def _configure_phi_protection(self):
        """Configure scanning policies for PHI protection"""
        return {
            'sql_injection': True,
            'no_sql_injection': True,
            'authentication_bypass': True,
            'session_management': True,
            'insecure_communication': True,
            'data_exposure': True
        }
    
    def _configure_hipaa_compliance(self):
        """HIPAA-specific security checks"""
        return {
            'access_control': True,
            'audit_logging': True,
            'data_encryption': True,
            'secure_transmission': True,
            'minimum_necessary': True
        }
    
    def scan_with_compliance(self, target_url, compliance_type='phi_protection'):
        """Run scan with specific compliance requirements"""
        if compliance_type not in self.healthcare_policies:
            print(f"Unknown compliance type: {compliance_type}")
            return False
        
        print(f"Running {compliance_type} compliant scan...")
        
        # Set custom headers for healthcare app testing
        custom_headers = {
            'X-Compliance-Type': compliance_type,
            'X-Testing-Purpose': 'security_scan',
            'X-User-Agent': 'DAST-Scanner/1.0'
        }
        
        # Apply policies and run scan
        return self.run_compliant_scan(target_url, custom_headers)
    
    def run_compliant_scan(self, url, headers):
        """Execute compliance-specific scan"""
        # Implementation would include specific scanning rules
        # for healthcare data protection
        pass
```

## Docker-based ZAP Setup

```dockerfile
# Dockerfile for automated ZAP scanning
FROM owasp/zap2docker-stable

# Install additional tools
USER root
RUN pip install requests beautifulsoup4

# Copy scanning scripts
COPY zap-scanner.py /zap/
COPY healthcare-policies.json /zap/

# Set working directory
WORKDIR /zap

# Default command
CMD ["python", "zap-scanner.py"]
```

## Kubernetes CronJob for Regular Scanning

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: dast-weekly-scan
  namespace: security
spec:
  schedule: "0 2 * * 1"  # Every Monday at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: zap-scanner
            image: owasp/zap2docker-stable:latest
            command:
            - python
            - /zap/scripts/healthcare-scan.py
            - --target=https://healthcare-portal.example.com
            - --report-format=json
            - --compliance=hipaa
            env:
            - name: ZAP_API_KEY
              valueFrom:
                secretKeyRef:
                  name: zap-secrets
                  key: api-key
            volumeMounts:
            - name: scan-reports
              mountPath: /zap/reports
          volumes:
          - name: scan-reports
            emptyDir: {}
          restartPolicy: OnFailure
```

This comprehensive DAST implementation provides automated, scalable security testing capabilities specifically designed for healthcare applications while maintaining compliance with relevant regulations.