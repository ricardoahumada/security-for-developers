# SonarQube Integration with Jenkins Pipeline

This code example demonstrates how to integrate SAST scanning using SonarQube into a Jenkins CI/CD pipeline for automated security testing.

## Complete Jenkins Pipeline with SonarQube

```groovy
pipeline {
    agent any
    
    environment {
        SONARQUBE_TOKEN = credentials('sonarqube-token')
        SONARQUBE_URL = 'https://sonar.example.com'
        PROJECT_KEY = 'healthcare-portal'
        PROJECT_NAME = 'Healthcare Management Portal'
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Compile & Test') {
            steps {
                script {
                    def dockerHome = tool 'Docker'
                    sh """
                        ${dockerHome}/bin/docker run --rm -v \$(pwd):/project openjdk:11 \
                        mvn clean compile test -f /project/pom.xml
                    """
                }
            }
        }
        
        stage('SAST Analysis') {
            steps {
                script {
                    def scannerHome = tool 'SonarQube'
                    withSonarQubeEnv('SonarQube-Production') {
                        sh """
                            ${scannerHome}/bin/sonar-scanner \\
                            -Dsonar.projectKey=${env.PROJECT_KEY} \\
                            -Dsonar.projectName='${env.PROJECT_NAME}' \\
                            -Dsonar.projectVersion=1.0 \\
                            -Dsonar.sources=src/main/java \\
                            -Dsonar.tests=src/test/java \\
                            -Dsonar.java.binaries=target/classes \\
                            -Dsonar.java.test.binaries=target/test-classes \\
                            -Dsonar.java.coveragePlugin=jacoco \\
                            -Dsonar.jacoco.reportPaths=target/jacoco.exec \\
                            -Dsonar.java.libraries=target/lib/* \\
                            -Dsonar.sourceEncoding=UTF-8 \\
                            -Dsonar.scm.provider=git \\
                            -Dsonar.qualitygate.wait=true
                        """
                    }
                }
            }
        }
        
        stage('Quality Gate Check') {
            steps {
                timeout(time: 1, unit: 'HOURS') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }
        
        stage('Security Report Generation') {
            when {
                anyOf {
                    branch 'main'
                    branch 'develop'
                    buildingTag()
                }
            }
            steps {
                script {
                    def dockerHome = tool 'Docker'
                    sh """
                        ${dockerHome}/bin/docker run --rm \\
                        -e SONAR_HOST_URL=${env.SONARQUBE_URL} \\
                        -e SONAR_TOKEN=${env.SONARQUBE_TOKEN} \\
                        sonarsource/sonar-scanner-cli \\
                        -Dsonar.projectKey=${env.PROJECT_KEY} \\
                        -Dsonar.projectName='${env.PROJECT_NAME}' \\
                        -Dsonar.issues.defaultAssignees=security-team@example.com \\
                        -Dsonar.newCode.referenceBranch=main
                    """
                }
            }
        }
    }
    
    post {
        always {
            script {
                if (env.SONARQUBE_TOKEN) {
                    def qualityGate = SonarQubeGate(
                        SonarQubeToGitHub: true,
                        disableTransitiveStatus: false,
                        projectKey: env.PROJECT_KEY
                    )
                    
                    // Send security summary to stakeholders
                    emailext (
                        subject: "SAST Analysis Complete - ${env.JOB_NAME}",
                        body: """
                        Security Analysis Results:
                        - Project: ${env.PROJECT_KEY}
                        - Build: ${env.BUILD_NUMBER}
                        - Quality Gate: ${qualityGate.status}
                        - Security Hotspots: ${qualityGate.hotspots}
                        - Vulnerabilities: ${qualityGate.vulnerabilities}
                        
                        View detailed report: ${env.SONARQUBE_URL}/dashboard?id=${env.PROJECT_KEY}
                        """,
                        to: 'security-team@example.com, dev-team@example.com',
                        attachmentsPattern: 'security-report.xml'
                    )
                }
            }
        }
        
        success {
            archiveArtifacts artifacts: 'security-report.xml', allowEmptyArchive: true
            sh 'curl -X POST -H "Content-Type: application/json" -d "{\"text\":\"✅ SAST Analysis Passed for ${env.JOB_NAME}\"}" ${SLACK_WEBHOOK_URL}'
        }
        
        failure {
            sh 'curl -X POST -H "Content-Type: application/json" -d "{\"text\":\"❌ SAST Analysis Failed for ${env.JOB_NAME} - Review required\"}" ${SLACK_WEBHOOK_URL}'
            emailext (
                subject: "URGENT: SAST Analysis Failed - ${env.JOB_NAME}",
                body: "Security analysis failed. Immediate attention required.",
                to: 'security-team@example.com'
            )
        }
    }
}
```

## SonarQube Project Configuration (sonar-project.properties)

```properties
# Project Information
sonar.projectKey=healthcare-portal
sonar.projectName=Healthcare Management Portal
sonar.projectVersion=1.0.0
sonar.scm.provider=git
sonar.links.homepage=https://github.com/company/healthcare-portal
sonar.links.ci=https://jenkins.company.com/job/healthcare-portal/

# Source Code Configuration
sonar.sources=src/main/java
sonar.tests=src/test/java
sonar.sourceEncoding=UTF-8

# Java Configuration
sonar.java.binaries=target/classes
sonar.java.test.binaries=target/test-classes
sonar.java.libraries=target/lib/*

# Coverage Configuration
sonar.java.coveragePlugin=jacoco
sonar.jacoco.reportPaths=target/jacoco.exec
sonar.coverage.exclusions=**/generated/**,**/test/**

# Security Configuration
sonar.java.security.WatchServiceFileSystemBarrier=disabled
sonar.java.source.version=11

# Quality Gate Configuration
sonar.qualitygate=security
sonar.newCode.referenceBranch=main

# Issue Assignment
sonar.issues.defaultAssignees=security-team

# Exclusions
sonar.exclusions=**/node_modules/**,**/target/**,**/*.js,**/*.css

# Language-specific Settings
sonar.java.source.version=11
sonar.java.target.version=11
```

## Quality Gate Configuration JSON

```json
{
  "name": "Security Quality Gate",
  "isBuiltIn": false,
  "conditions": [
    {
      "metric": "coverage",
      "op": "LT",
      "value": "80.0",
      "errorThreshold": "80"
    },
    {
      "metric": "duplicated_lines_density",
      "op": "GT",
      "value": "3.0",
      "errorThreshold": "3"
    },
    {
      "metric": "security_hotspots",
      "op": "GT",
      "value": "0",
      "errorThreshold": "0"
    },
    {
      "metric": "vulnerabilities",
      "op": "GT",
      "value": "0",
      "errorThreshold": "0"
    },
    {
      "metric": "code_smells",
      "op": "GT",
      "value": "50",
      "errorThreshold": "50"
    },
    {
      "metric": "bugs",
      "op": "GT",
      "value": "0",
      "errorThreshold": "0"
    },
    {
      "metric": "security_rating",
      "op": "LT",
      "value": "4",
      "errorThreshold": "4"
    }
  ]
}
```

## Custom Security Rules Configuration

```xml
<?xml version="1.0" encoding="UTF-8"?>
<rules>
  <!-- Custom rule for checking SQL injection patterns -->
  <rule>
    <key>CustomSQLInjectionRule</key>
    <name>Custom SQL Injection Detection</name>
    <description>Detects potential SQL injection vulnerabilities in dynamic queries</description>
    <type>VULNERABILITY</type>
    <severity>CRITICAL