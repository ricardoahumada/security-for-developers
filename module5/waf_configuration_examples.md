# WAF Configuration Examples

This document provides comprehensive examples of Web Application Firewall (WAF) configurations for different platforms and use cases.

## ModSecurity Core Rule Set (CRS) Configuration

### Basic ModSecurity Configuration

```apache
# /etc/apache2/mods-enabled/mod-security.conf

# Enable ModSecurity
SecRuleEngine On

# Default action for blocking
SecDefaultAction "deny,pass"

# Log settings
SecDebugLog /var/log/apache2/modsec_debug.log
SecDebugLogLevel 1
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogType Serial
SecAuditLog /var/log/apache2/modsec_audit.log

# Upload directory
SecTmpDir /var/cache/modsecurity/
SecDataDir /tmp/

# Memory limit for inspection
SecRequestBodyMemoryLimit 13107200
SecRequestBodyInMemoryLimit 13107200
SecRequestBodyLimit 104857600
SecRequestBodyNoFilesLimit 32768

# Body processing
SecRule REQBODY_ERROR_LOG "!@eq 0" \
"id:'200003', \
phase:2,\
t:none,\
deny,\
msg:'ModSecurity internal error encountered.'"

SecRule MULTIPART_STRICT_ERROR "@eq 1" \
"id:'200002', \
phase:2,\
t:none,\
deny,\
msg:'Multipart request body failed strict validation. \
PE \[REASON BODY=1\] [COMPLIANCE TARGET=ALL] \[REASON CONTENT TYPE=1\] \
[COMPLIANCE REASON=1]'"

SecRule MULTIPART_UNMATCHED_PARAMS "@eq 2" \
"id:'200003', \
phase:2,\
t:none,\
deny,\
msg:'Multipart request body failed strict validation. \
PE \[REASON BODY=2\] [COMPLIANCE TARGET=ALL] \[REASON CONTENT TYPE=1\] \
[COMPLIANCE REASON=2]'"

SecRule BODY_PROTOCOLS "@rx ^http/" \
"id:'200004', \
phase:2,\
t:none,\
deny,\
msg:'Invalid HTTP request body protocol.'"

SecRule BODY_PROTOCOL_ERROR "@eq 1" \
"id:'200005', \
phase:2,\
t:none,\
deny,\
msg:'Invalid HTTP request body protocol.'"

SecRule BODY_LENGTH_LIMIT "@gt 100000000" \
"id:'200006', \
phase:2,\
t:none,\
deny,\
msg:'Request body length limit exceeded.'"

SecRule BODY_LENGTH_MAX "@gt 2147483647" \
"id:'200007', \
phase:2,\
t:none,\
deny,\
msg:'Request body length exceeds maximum allowed.'"

SecAction \
"id:'900200', \
phase:5,\
pass,\
t:none,\
setvar:tx.inbound_anomaly_score_threshold=5"
```

### Healthcare Application Specific Rules

```apache
# /etc/apache2/modsecurity.d/healthcare-specific.conf
# HIPAA-compliant WAF rules for healthcare applications

# Rule to detect potential PHI exposure
SecRule REQUEST_URI "@rx /(patient|medical|health|record|diagnosis|prescription)" \
"id:'2001',\
phase:2,\
t:none,\
pass,\
setvar:tx.healthcare_flag=1,\
msg:'Healthcare Application Endpoint Detected'"

# Detect common healthcare identifiers
SecRule ARGS "@rx \b(\d{3}[-\s]?\d{2}[-\s]?\d{4})\b" \
"id:'2002',\
phase:2,\
t:none,\
pass,\
chain\
setvar:tx.ssn_detected=1"
  SecRule &tx.healthcare_flag "@eq 1"

# Medical record number validation
SecRule ARGS "@rx \b(MRN|PatientID|RecordID):?\s*(\d{6,12})\b" \
"id:'2003',\
phase:2,\
t:none,\
block,\
msg:'Potential Medical Record Number Exposure'"

# Prescription drug detection
SecRule ARGS "@rx \b(Acetaminophen|Ibuprofen|Lisinopril|Omeprazole|Metformin)\b" \
"id:'2004',\
phase:2,\
t:none,\
pass,\
setvar:tx.rx_detected=1,\
msg:'Prescription Drug Information Detected'"

# HIPAA compliance check - ensure HTTPS for PHI
SecRule SERVER_PORT "@rx ^80$" \
"id:'2005',\
phase:1,\
t:none,\
deny,\
chain"
  SecRule &tx.healthcare_flag "@eq 1"

# Audit logging for healthcare access
SecRule REQUEST_URI "@rx /(patient|medical|record)" \
"id:'2006',\
phase:2,\
t:none,\
pass,\
log,\
logdata:'Healthcare Access - User: %{REMOTE_USER} - URI: %{REQUEST_URI} - Method: %{REQUEST_METHOD}'"
```

### SQL Injection Prevention Rules

```apache
# /etc/apache2/modsecurity.d/sql-injection.conf

# Generic SQL injection patterns
SecRule ARGS "@rx (\%27)|(\')|(\-\-)|(\%23)|(#)" \
"id:'1000',\
phase:2,\
t:none,\
block,\
msg:'Generic SQL Injection Pattern Detected'"

# Specific SQL injection techniques
SecRule ARGS "@rx \b(union|select|insert|update|delete|drop|create|alter)\b" \
"id:'1001',\
phase:2,\
t:none,\
block,\
msg:'SQL Command Injection Attempt'"

# Time-based blind SQL injection
SecRule ARGS "@rx \b(sleep|benchmark|pg_sleep|waitfor delay)\b" \
"id:'1002',\
phase:2,\
t:none,\
block,\
msg:'Time-based Blind SQL Injection Attempt'"

# Error-based SQL injection
SecRule ARGS "@rx \b(mysql_fetch_array|mysql_fetch_assoc|ORA-\d{4,5})\b" \
"id:'1003',\
phase:2,\
t:none,\
block,\
msg:'Error-based SQL Injection Attempt'"

# Advanced SQL injection techniques
SecRule ARGS "@rx \b(char\s*\(|substring\s*\(|ascii\s*\(|hex\s*\(|ascii_str)\b" \
"id:'1004',\
phase:2,\
t:none,\
block,\
msg:'Advanced SQL Injection Technique Detected'"
```

### Cross-Site Scripting (XSS) Prevention

```apache
# /etc/apache2/modsecurity.d/xss.conf

# Reflected XSS detection
SecRule ARGS "@rx <script\b[^<]*(?:(?!</script>)<[^<]*)*</script>" \
"id:'2000',\
phase:2,\
t:none,\
block,\
msg:'Reflected XSS Attack Detected'"

# DOM-based XSS patterns
SecRule ARGS "@rx javascript:|vbscript:|onload=|onerror=|onclick=" \
"id:'2001',\
phase:2,\
t:none,\
block,\
msg:'DOM-based XSS Attempt'"

# HTML injection prevention
SecRule ARGS "@rx <[^>]+on\w+\s*=" \
"id:'2002',\
phase:2,\
t:none,\
block,\
msg:'HTML Injection with Event Handler'"

# iframe and embed tag injection
SecRule ARGS "@rx <\s*(iframe|embed|object)\b[^>]*>" \
"id:'2003',\
phase:2,\
t:none,\
block,\
msg:'Embedded Content Injection Attempt'"
```

## AWS WAF Configuration

### CloudFormation Template for Healthcare WAF

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Healthcare Application WAF Configuration'

Parameters:
  HealthCareDomainName:
    Type: String
    Description: Domain name of healthcare application
    Default: health-portal.example.com

Resources:
  # WAF Web ACL
  HealthCareWAF:
    Type: AWS::WAFv2::WebACL
    Properties:
      Name: !Sub '${AWS::StackName}-HealthCare-WAF'
      Scope: CLOUDFRONT
      DefaultAction:
        Allow: {}
      Rules:
        - Name: 'AWS-AWSManagedRulesCommonRuleSet'
          Priority: 1
          Statement:
            ManagedRuleGroupStatement:
              VendorName: AWS
              Name: AWSManagedRulesCommonRuleSet
              ExcludedRules: []
          OverrideAction:
            None: {}
          VisibilityConfig:
            CloudWatchMetricsEnabled: true
            MetricName: 'CommonRuleSet'
            SampledRequestsEnabled: true
        
        - Name: 'AWS-AWSManagedRulesLinuxRuleSet'
          Priority: 2
          Statement:
            ManagedRuleGroupStatement:
              VendorName: AWS
              Name: AWSManagedRulesLinuxRuleSet
          OverrideAction:
            None: {}
          VisibilityConfig:
            CloudWatchMetricsEnabled: true
            MetricName: 'LinuxRuleSet'
            SampledRequestsEnabled: true
        
        - Name: 'AWS-AWSManagedRulesUnixRuleSet'
          Priority: 3
          Statement:
            ManagedRuleGroupStatement:
              VendorName: AWS
              Name: AWSManagedRulesUnixRuleSet
          OverrideAction:
            None: {}
          VisibilityConfig:
            CloudWatchMetricsEnabled: true
            MetricName: 'UnixRuleSet'
            SampledRequestsEnabled: true
        
        - Name: 'AWS-AWSManagedRulesKnownBadInputsRuleSet'
          Priority: 4
          Statement:
            ManagedRuleGroupStatement:
              VendorName: AWS
              Name: AWSManagedRulesKnownBadInputsRuleSet
          OverrideAction:
            None: {}
          VisibilityConfig:
            CloudWatchMetricsEnabled: true
            MetricName: 'KnownBadInputs'
            SampledRequestsEnabled: true
        
        # Custom healthcare-specific rules
        - Name: 'HealthcarePHIRule'
          Priority: 5
          Statement:
            AndStatement:
              Statements:
                - GeoMatchStatement:
                    CountryCodes:
                      - US
                      - CA
                - ByteMatchStatement:
                    SearchString: '/api/patient'
                    PositionalConstraint: CONTAINS
                    TextTransformations:
                      - Priority: 0
                        Type: NONE
          Action:
            Block:
              CustomResponse:
                ResponseCode: 403
                ResponseBody:
                  Message: 'Unauthorized access to protected health information'
          VisibilityConfig:
            CloudWatchMetricsEnabled: true
            MetricName: 'PHIAccess'
            SampledRequestsEnabled: true
        
        # Rate limiting rule
        - Name: 'RateLimitRule'
          Priority: 6
          Statement:
            RateBasedStatement:
              Limit: 2000
              AggregateKeyType: IP
          Action:
            Block:
              CustomResponse:
                ResponseCode: 429
                ResponseBody:
                  Message: 'Rate limit exceeded'
          VisibilityConfig:
            CloudWatchMetricsEnabled: true
            MetricName: 'RateLimit'
            SampledRequestsEnabled: true
        
        # SQL injection protection
        - Name: 'SQLInjectionRule'
          Priority: 7
          Statement:
            SqliMatchStatement:
              TextTransformations:
                - Priority: 0
                  Type: URL_DECODE
                - Priority: 1
                  Type: HTML_ENTITY_DECODE
              FieldToMatch:
                Body:
                  OversizeHandling: MATCH
          Action:
            Block:
              CustomResponse:
                ResponseCode: 403
                ResponseBody:
                  Message: 'SQL injection attempt blocked'
          VisibilityConfig:
            CloudWatchMetricsEnabled: true
            MetricName: 'SQLInjection'
            SampledRequestsEnabled: true
      
      VisibilityConfig:
        CloudWatchMetricsEnabled: true
        MetricName: 'HealthcareWAF'
        SampledRequestsEnabled: true
      
      Tags:
        - Key: Environment
          Value: Production
        - Key: Compliance
          Value: HIPAA
        - Key: Application
          Value: HealthPortal

  # Association with CloudFront distribution
  WAFAssociation:
    Type: AWS::WAFv2::WebACLAssociation
    Properties:
      ResourceArn: !ImportValue HealthPortal-CloudFrontArn
      WebACLArn: !GetAtt HealthCareWAF.Arn

  # WAF logging configuration
  WAFLoggingConfiguration:
    Type: AWS::WAFv2::LoggingConfiguration
    Properties:
      LogDestinationConfigs:
        - !GetAtt WAFLogGroup.Arn
      RedactedFields:
        HeaderMethods:
          - GET
          - POST
          - HEAD
        HeaderNames:
          - USER-AGENT
          - AUTHORIZATION
      ResourceArn: !GetAtt HealthCareWAF.Arn

  # CloudWatch Log Group for WAF logs
  WAFLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Sub '/aws/wafv2/${AWS::StackName}'
      RetentionInDays: 30

Outputs:
  WAFWebACLArn:
    Description: WAF Web ACL ARN
    Value: !GetAtt HealthCareWAF.Arn
    Export:
      Name: !Sub '${AWS::StackName}-WAF-ARN'
```

### AWS WAF CLI Configuration

```bash
#!/bin/bash
# AWS WAF CLI configuration script for healthcare applications

STACK_NAME="health-portal-waf"
REGION="us-east-1"
CLOUDFRONT_ARN="arn:aws:cloudfront::123456789012:distribution/ABC123DEF456"

# Create WAF Web ACL
aws wafv2 create-web-acl \
    --scope CLOUDFRONT \
    --default-action Allow={} \
    --name "${STACK_NAME}-WebACL" \
    --description "Healthcare Portal WAF Configuration" \
    --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=HealthPortalWAF \
    --rules file://waf-rules.json \
    --region $REGION

# Associate WAF with CloudFront distribution
aws wafv2 associate-web-acl \
    --web-acl-arn "arn:aws:wafv2:us-east-1:123456789012:global/webacl/${STACK_NAME}-WebACL/abcdef12-3456-7890-abcd-ef1234567890" \
    --resource-arn $CLOUDFRONT_ARN \
    --region $REGION

# Configure logging
aws wafv2 put-logging-configuration \
    --logging-configuration ResourceARN=arn:aws:wafv2:us-east-1:123456789012:global/webacl/${STACK_NAME}-WebACL/abcdef12-3456-7890-abcd-ef1234567890,LogDestinationConfigs=arn:aws:logs:us-east-1:123456789012:log-group:/aws/wafv2/health-portal,RedactedFields=[{HeaderNames=[\"AUTHORIZATION\", \"COOKIE\"],HeaderMethods=[\"POST\", \"GET\", \"PUT\", \"DELETE\"]}] \
    --region $REGION
```

## Cloudflare WAF Configuration

### Cloudflare Terraform Configuration

```hcl
terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 3.0"
    }
  }
}

# Cloudflare WAF configuration for healthcare portal
variable "cloudflare_zone_id" {
  description = "Cloudflare Zone ID"
  type        = string
}

resource "cloudflare_ruleset" "healthcare_waf" {
  zone_id = var.cloudflare_zone_id
  name    = "Healthcare Portal Security Rules"
  kind    = "zone"
  phase   = "http_request_firewall_custom"

  rules {
    action = "execute"
    action_id = "execute_cloudflare_ruleset"
    expression = "(cf.threat_score >= 14 and cf.threat_score lt 20)"
    description = "Challenge medium threat score requests"
  }

  rules {
    action = "execute"
    action_id = "execute_cloudflare_ruleset"
    expression = "(cf.threat_score >= 20)"
    description = "Block high threat score requests"
  }

  rules {
    action = "block"
    expression = "(http.request.uri.path contains \"/api/patient\" and not cf.threat_score eq 0)"
    description = "Block patient API access for unknown reputation"
  }

  rules {
    action = "challenge"
    expression = "(http.request.uri.path matches \"/patient/.*\" and http.request.method ne \"GET\")"
    description = "Challenge write operations on patient endpoints"
  }

  rules {
    action = "block"
    expression = "(lower(http.request.uri.path) contains \"select\" and lower(http.request.uri.path) contains \"from\")"
    description = "Block SQL injection attempts"
  }

  rules {
    action = "block"
    expression = "(http.request.uri contains \"<script\" or http.request.uri contains \"javascript:\")"
    description = "Block XSS attempts"
  }
}

# Rate limiting rules
resource "cloudflare_rate_limit" "healthcare_api_limit" {
  zone_id = var.cloudflare_zone_id
  threshold = 10
  period    = 60
  action {
    mode    = "challenge"
    timeout = 300
  }
  match {
    request {
      schemes = ["HTTP", "HTTPS"]
      methods = ["POST", "PUT", "DELETE"]
      url     = "health-portal.example.com/api/patient/*"
    }
  }
  description = "Rate limit patient API operations"
}

# Custom rules for HIPAA compliance
resource "cloudflare_ruleset" "hipaa_compliance" {
  zone_id = var.cloudflare_zone_id
  name    = "HIPAA Compliance Rules"
  kind    = "zone"
  phase   = "http_request_firewall_security"

  rules {
    action = "block"
    expression = "(not ssl and http.request.uri.path contains \"/api/patient\")"
    description = "Require SSL for patient data access"
  }

  rules {
    action = "allow"
    expression = "(ip.geoip.country in {\"US\" \"CA\" \"MX\"})"
    description = "Allow requests from North America only"
  }

  rules {
    action = "block"
    expression = "(http.request.uri.path contains \"admin\" and not cf.bot_management.score ge 99)"
    description = "Restrict admin access to verified users only"
  }
}

# Bot management configuration
resource "cloudflare_ruleset" "bot_management" {
  zone_id = var.cloudflare_zone_id
  name    = "Bot Management"
  kind    = "zone"
  phase   = "http_request_firewall_custom"

  rules {
    action = "execute"
    action_id = "execute_cloudflare_bot_management"
    expression = "(true)"
    description = "Enable bot management for all requests"
  }
}
```

## Rate Limiting and DDoS Protection

### Advanced Rate Limiting Configuration

```apache
# ModSecurity rate limiting for healthcare APIs
SecAction \
  "id:9001,\
   phase:1,\
   t:none,\
   setvar:tx.rate_limit_api=/api/patient,\
   setvar:tx.rate_limit_window=300,\
   setvar:tx.rate_limit_requests=20"

# Rate limiting rule
SecRule TX:rate_limit_api "@streq %{REQUEST_URI}" \
  "id:9002,\
   phase:1,\
   t:none,\
   pass,\
   nolog,\
   chain"
  SecRule &IP:rate_limit "@eq 0" \
    "setvar:IP.rate_limit=0"

SecRule TX:rate_limit_api "@streq %{REQUEST_URI}" \
  "id:9003,\
   phase:1,\
   t:none,\
   pass,\
   nolog,\
   chain"
  SecRule TX:rate_limit "@lt %{TX.rate_limit_requests}" \
    "setvar:IP.rate_limit=+1"

SecRule TX:rate_limit_api "@streq %{REQUEST_URI}" \
  "id:9004,\
   phase:1,\
   t:none,\
   deny,\
   msg:'Rate limit exceeded for patient API'"
```

## Monitoring and Alerting Configuration

### CloudWatch Alerts for WAF Metrics

```yaml
# CloudWatch alarms for WAF monitoring
Resources:
  WAFBlockRateAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: !Sub '${AWS::StackName}-WAF-Block-Rate'
      AlarmDescription: 'High block rate indicating potential attack'
      MetricName: 'AllowedRequests'
      Namespace: 'AWS/WAFV2'
      Statistic: 'Sum'
      Period: '300'
      EvaluationPeriods: '2'
      Threshold: '100'
      ComparisonOperator: 'GreaterThanThreshold'
      Dimensions:
        - Name: WebACL
          Value: !GetAtt HealthCareWAF.Name
        - Name: Region
          Value: !Ref 'AWS::Region'
        - Name: Resource
          Value: !Ref HealthCareWAF

  WAFSQLInjectionAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: !Sub '${AWS::StackName}-SQL-Injection-Attempts'
      AlarmDescription: 'SQL injection attempts detected'
      MetricName: 'AllowedRequests'
      Namespace: 'AWS/WAFV2'
      Statistic: 'Sum'
      Period: '300'
      EvaluationPeriods: '1'
      Threshold: '5'
      ComparisonOperator: 'GreaterThanThreshold'
      Dimensions:
        - Name: WebACL
          Value: !GetAtt HealthCareWAF.Name
        - Name: Region
          Value: !Ref 'AWS::Region'
        - Name: Resource
          Value: !Ref HealthCareWAF
```

## Compliance-Specific Configurations

### HIPAA Audit Logging

```apache
# Enhanced logging for HIPAA compliance
SecRule REQUEST_URI "@rx /(patient|medical|record|prescription)" \
  "id:'3000',\
   phase:2,\
   t:none,\
   pass,\
   log,\
   logdata:'HIPAA Audit - User: %{REMOTE_USER} - IP: %{REMOTE_ADDR} - URI: %{REQUEST_URI} - Method: %{REQUEST_METHOD} - DateTime: %{SERVER_DATE} - UserAgent: %{HTTP_USER_AGENT}'"

# Log successful and failed authentication attempts
SecRule REQUEST_URI "@rx /login" \
  "id:'3001',\
   phase:2,\
   t:none,\
   pass,\
   log,\
   logdata:'Login Attempt - User: %{REMOTE_USER} - IP: %{REMOTE_ADDR} - Status: %{RESPONSE_STATUS}'"

# Monitor file upload operations on PHI
SecRule REQUEST_URI "@rx /upload" \
  "id:'3002',\
   phase:2,\
   t:none,\
   pass,\
   log,\
   logdata:'File Upload - User: %{REMOTE_USER} - IP: %{REMOTE_ADDR} - File: %{REQUEST_BODY_FILENAME} - Size: %{REQUEST_BODY_LENGTH}'"
```

This comprehensive WAF configuration provides multiple layers of protection specifically designed for healthcare applications while maintaining compliance with HIPAA and other regulatory requirements.