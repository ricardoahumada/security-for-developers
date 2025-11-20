# OAuth 2.0 Flow Decision Matrix

## Flow Selection Framework

This comprehensive decision matrix helps developers choose the appropriate OAuth 2.0 flow based on application characteristics and requirements.

```javascript
class OAuthFlowDecisionMatrix {
    constructor() {
        this.flowDefinitions = {
            authorization_code: {
                name: 'Authorization Code',
                clientTypes: ['confidential'],
                environments: ['web_server'],
                securityLevel: 'high',
                complexity: 'medium',
                tokenHandling: 'server_side',
                refreshTokenSupport: true,
                requiresClientSecret: true,
                userConsent: true,
                deprecated: false
            },
            pkce: {
                name: 'Authorization Code with PKCE',
                clientTypes: ['public'],
                environments: ['spa', 'mobile', 'desktop'],
                securityLevel: 'high',
                complexity: 'medium-high',
                tokenHandling: 'client_side',
                refreshTokenSupport: true,
                requiresClientSecret: false,
                userConsent: true,
                deprecated: false
            },
            client_credentials: {
                name: 'Client Credentials',
                clientTypes: ['confidential'],
                environments: ['server_to_server'],
                securityLevel: 'high',
                complexity: 'low',
                tokenHandling: 'server_side',
                refreshTokenSupport: false,
                requiresClientSecret: true,
                userConsent: false,
                deprecated: false
            },
            implicit: {
                name: 'Implicit',
                clientTypes: ['public'],
                environments: ['spa'],
                securityLevel: 'low',
                complexity: 'low',
                tokenHandling: 'client_side',
                refreshTokenSupport: false,
                requiresClientSecret: false,
                userConsent: true,
                deprecated: true
            },
            password_credentials: {
                name: 'Resource Owner Password Credentials',
                clientTypes: ['confidential', 'public'],
                environments: ['legacy'],
                securityLevel: 'very_low',
                complexity: 'low',
                tokenHandling: 'server_side',
                refreshTokenSupport: true,
                requiresClientSecret: true,
                userConsent: false,
                deprecated: true
            }
        };
    }

    // Primary decision method
    recommendFlow(applicationProfile) {
        const analysis = this.analyzeApplicationProfile(applicationProfile);
        const candidateFlows = this.filterCandidateFlows(analysis);
        const rankedFlows = this.rankFlowsBySuitability(candidateFlows, analysis);

        return {
            recommended: rankedFlows[0],
            alternatives: rankedFlows.slice(1, 3),
            analysis: analysis,
            rationale: this.generateRationale(rankedFlows[0], analysis)
        };
    }

    // Analyze application characteristics
    analyzeApplicationProfile(profile) {
        const analysis = {
            clientType: this.determineClientType(profile),
            environment: this.determineEnvironment(profile),
            securityRequirements: this.assessSecurityRequirements(profile),
            hasClientSecret: profile.hasClientSecret || false,
            needsUserConsent: profile.needsUserConsent || false,
            tokenStorage: profile.tokenStorage || 'none',
            tokenLifespan: profile.tokenLifespan || '1_hour',
            userAgent: profile.userAgent || 'unknown',
            distributionMethod: profile.distributionMethod || 'web',
            complianceRequirements: profile.complianceRequirements || []
        };

        // Additional analysis
        analysis.securityRisk = this.assessSecurityRisk(analysis);
        analysis.complexityTolerance = profile.complexityTolerance || 'medium';
        analysis.developmentResources = profile.developmentResources || 'standard';

        return analysis;
    }

    determineClientType(profile) {
        if (profile.distributionMethod === 'server' || profile.deployment === 'backend') {
            return 'confidential';
        }
        if (profile.distributionMethod === 'mobile_app' || 
            profile.distributionMethod === 'desktop_app' ||
            profile.distributionMethod === 'spa') {
            return 'public';
        }
        return 'confidential'; // Default to confidential for safety
    }

    determineEnvironment(profile) {
        if (profile.useCase === 'server_to_server') return 'server_to_server';
        if (profile.distributionMethod === 'spa') return 'spa';
        if (profile.distributionMethod === 'mobile_app') return 'mobile';
        if (profile.distributionMethod === 'desktop_app') return 'desktop';
        if (profile.distributionMethod === 'server' || profile.deployment === 'backend') return 'web_server';
        return 'unknown';
    }

    assessSecurityRequirements(profile) {
        let score = 0;
        
        if (profile.handlesSensitiveData) score += 3;
        if (profile.requiresAuditTrail) score += 2;
        if (profile.regulatoryCompliance) score += 2;
        if (profile.financialTransactions) score += 3;
        if (profile.personalData) score += 2;
        if (profile.multiTenant) score += 1;

        if (score >= 7) return 'very_high';
        if (score >= 5) return 'high';
        if (score >= 3) return 'medium';
        return 'low';
    }

    assessSecurityRisk(analysis) {
        if (analysis.clientType === 'public') return 'high';
        if (analysis.securityRequirements === 'very_high') return 'high';
        if (analysis.tokenStorage === 'client_side') return 'medium';
        return 'low';
    }

    // Filter flows based on application profile
    filterCandidateFlows(analysis) {
        return Object.entries(this.flowDefinitions).filter(([key, flow]) => {
            // Client type compatibility
            const clientTypeMatch = flow.clientTypes.includes(analysis.clientType);
            
            // Environment compatibility
            const environmentMatch = flow.environments.includes(analysis.environment);
            
            // Security level match
            const securityLevelMatch = this.isSecurityLevelAdequate(
                flow.securityLevel, 
                analysis.securityRequirements
            );

            // User consent requirements
            const consentMatch = flow.userConsent === analysis.needsUserConsent;

            // Non-deprecated flows preferred
            const deprecationPenalty = flow.deprecated ? -1 : 0;

            return clientTypeMatch && environmentMatch && securityLevelMatch;
        }).map(([key, flow]) => ({
            ...flow,
            key: key,
            matchScore: this.calculateMatchScore(flow, analysis) + deprecationPenalty
        }));
    }

    isSecurityLevelAdequate(flowSecurity, requiredSecurity) {
        const levels = { very_low: 1, low: 2, medium: 3, high: 4, very_high: 5 };
        return levels[flowSecurity] >= levels[requiredSecurity];
    }

    calculateMatchScore(flow, analysis) {
        let score = 0;
        
        // Base score for being a candidate
        score += 10;

        // Security level bonus
        if (flow.securityLevel === 'high') score += 5;
        if (flow.securityLevel === 'very_high') score += 3;

        // Environment specificity
        if (flow.environments.includes(analysis.environment)) score += 3;

        // Client type specificity
        if (flow.clientTypes.includes(analysis.clientType)) score += 2;

        // Token storage compatibility
        if (flow.tokenHandling === 'server_side' && analysis.tokenStorage === 'server') score += 2;
        if (flow.tokenHandling === 'client_side' && analysis.tokenStorage === 'client') score += 2;

        // Complexity preference
        if (analysis.complexityTolerance === 'low' && flow.complexity === 'low') score += 2;
        if (analysis.complexityTolerance === 'high' && flow.complexity === 'high') score += 1;

        // Deprecated penalty
        if (flow.deprecated) score -= 5;

        return score;
    }

    // Rank flows by suitability
    rankFlowsBySuitability(candidateFlows, analysis) {
        return candidateFlows.sort((a, b) => b.matchScore - a.matchScore);
    }

    generateRationale(recommendedFlow, analysis) {
        const reasons = [];

        if (recommendedFlow.clientTypes.includes(analysis.clientType)) {
            reasons.push(`Appropriate for ${analysis.clientType} client type`);
        }

        if (recommendedFlow.environments.includes(analysis.environment)) {
            reasons.push(`Designed for ${analysis.environment} environment`);
        }

        if (recommendedFlow.securityLevel === 'high' && analysis.securityRequirements !== 'low') {
            reasons.push('Provides high security level suitable for your requirements');
        }

        if (!recommendedFlow.deprecated) {
            reasons.push('Modern, actively supported flow');
        }

        if (recommendedFlow.key === 'pkce' && analysis.clientType === 'public') {
            reasons.push('Essential for public clients to prevent code interception attacks');
        }

        if (recommendedFlow.key === 'client_credentials' && !analysis.needsUserConsent) {
            reasons.push('Perfect for server-to-server communication without user involvement');
        }

        return reasons;
    }

    // Decision tree for common scenarios
    static getQuickDecision(profile) {
        const matrix = new OAuthFlowDecisionMatrix();

        // Quick decision tree
        if (profile.useCase === 'server_to_server') {
            return { flow: 'client_credentials', reason: 'Server-to-server communication' };
        }

        if (profile.clientType === 'confidential' && profile.needsUserConsent) {
            return { flow: 'authorization_code', reason: 'Confidential client with user consent' };
        }

        if (profile.clientType === 'public' && profile.needsUserConsent) {
            return { flow: 'pkce', reason: 'Public client requiring secure authorization' };
        }

        return matrix.recommendFlow(profile).recommended;
    }
}

// Common application profiles
const ApplicationProfiles = {
    // React/Vue/Angular Single Page Applications
    spa_web: {
        distributionMethod: 'spa',
        clientType: 'public',
        environment: 'spa',
        hasClientSecret: false,
        needsUserConsent: true,
        tokenStorage: 'client',
        handlesSensitiveData: true,
        complexityTolerance: 'medium',
        developmentResources: 'standard',
        useCase: 'user_facing_app'
    },

    // React Native / Flutter Mobile Apps
    mobile_app: {
        distributionMethod: 'mobile_app',
        clientType: 'public',
        environment: 'mobile',
        hasClientSecret: false,
        needsUserConsent: true,
        tokenStorage: 'client',
        handlesSensitiveData: true,
        mobilePlatform: 'both',
        complexityTolerance: 'medium',
        developmentResources: 'standard',
        useCase: 'mobile_app'
    },

    // Next.js / Express.js Server-side Applications
    server_web_app: {
        distributionMethod: 'server',
        clientType: 'confidential',
        environment: 'web_server',
        hasClientSecret: true,
        needsUserConsent: true,
        tokenStorage: 'server',
        handlesSensitiveData: true,
        complexityTolerance: 'medium',
        developmentResources: 'standard',
        useCase: 'web_application'
    },

    // Node.js / Python Backend Services
    backend_service: {
        distributionMethod: 'server',
        clientType: 'confidential',
        environment: 'server_to_server',
        hasClientSecret: true,
        needsUserConsent: false,
        tokenStorage: 'server',
        handlesSensitiveData: false,
        complexityTolerance: 'low',
        developmentResources: 'standard',
        useCase: 'server_to_server'
    },

    // Electron Desktop Applications
    desktop_app: {
        distributionMethod: 'desktop_app',
        clientType: 'public',
        environment: 'desktop',
        hasClientSecret: false,
        needsUserConsent: true,
        tokenStorage: 'client',
        handlesSensitiveData: true,
        complexityTolerance: 'medium',
        developmentResources: 'standard',
        useCase: 'desktop_application'
    },

    // Legacy Applications (for migration planning)
    legacy_app: {
        distributionMethod: 'server',
        clientType: 'confidential',
        environment: 'legacy',
        hasClientSecret: true,
        needsUserConsent: false,
        tokenStorage: 'server',
        handlesSensitiveData: false,
        complexityTolerance: 'low',
        developmentResources: 'limited',
        useCase: 'legacy_system'
    }
};

// Decision matrix implementation
class FlowDecisionHelper {
    static getRecommendations() {
        return [
            {
                scenario: 'React SPA with Google Login',
                profile: ApplicationProfiles.spa_web,
                recommendation: {
                    flow: 'pkce',
                    confidence: 'high',
                    alternative: 'authorization_code (with backend proxy)',
                    notes: 'Use PKCE for best security. Consider backend proxy for additional features.'
                }
            },
            {
                scenario: 'iOS/Android App with Social Login',
                profile: ApplicationProfiles.mobile_app,
                recommendation: {
                    flow: 'pkce',
                    confidence: 'high',
                    alternative: 'native_sdk_integration',
                    notes: 'PKCE is essential for mobile apps. Consider platform-specific SDKs.'
                }
            },
            {
                scenario: 'Node.js API integrating with third-party services',
                profile: ApplicationProfiles.backend_service,
                recommendation: {
                    flow: 'client_credentials',
                    confidence: 'high',
                    alternative: 'authorization_code',
                    notes: 'Client Credentials for service-to-service. Use Authorization Code if user consent needed.'
                }
            },
            {
                scenario: 'Next.js e-commerce platform',
                profile: ApplicationProfiles.server_web_app,
                recommendation: {
                    flow: 'authorization_code',
                    confidence: 'high',
                    alternative: 'pkce (for hybrid approach)',
                    notes: 'Authorization Code for server-side rendering. Consider hybrid approach for SEO.'
                }
            },
            {
                scenario: 'Electron productivity app',
                profile: ApplicationProfiles.desktop_app,
                recommendation: {
                    flow: 'pkce',
                    confidence: 'medium',
                    alternative: 'authorization_code (with local server)',
                    notes: 'PKCE for desktop apps. Consider local callback server for better UX.'
                }
            }
        ];
    }

    static async interactiveDecisionTool() {
        console.log('=== OAuth Flow Decision Tool ===\n');

        const recommendations = this.getRecommendations();
        
        recommendations.forEach((rec, index) => {
            console.log(`${index + 1}. ${rec.scenario}`);
            console.log(`   Recommended Flow: ${rec.recommendation.flow.toUpperCase()}`);
            console.log(`   Confidence: ${rec.recommendation.confidence}`);
            console.log(`   Alternative: ${rec.recommendation.alternative}`);
            console.log(`   Notes: ${rec.recommendation.notes}`);
            console.log('');
        });

        // Decision matrix visualization
        console.log('=== Flow Selection Matrix ===');
        console.log('Client Type    | Environment      | Recommended Flow      | Security');
        console.log('---------------|------------------|----------------------|----------');
        console.log('Confidential   | Web Server       | Authorization Code   | High');
        console.log('Confidential   | Server-to-Server | Client Credentials   | High');
        console.log('Public         | SPA              | PKCE                 | High');
        console.log('Public         | Mobile           | PKCE                 | High');
        console.log('Public         | Desktop          | PKCE                 | High');
        console.log('Legacy         | Any              | Migrate to Modern    | Variable');
        console.log('');
    }
}

// Implementation examples for each flow
const ImplementationGuides = {
    authorization_code: {
        when_to_use: 'Confidential clients with user consent',
        pros: ['High security', 'Refresh tokens', 'Server-side token handling'],
        cons: ['Requires client secret', 'More complex', 'Server-side implementation'],
        security_checklist: [
            'Store client secret securely',
            'Validate state parameter',
            'Use HTTPS for all endpoints',
            'Implement proper session management',
            'Validate redirect URIs',
            'Handle token refresh securely'
        ]
    },
    pkce: {
        when_to_use: 'Public clients (mobile, SPA, desktop)',
        pros: ['No client secret required', 'Prevents code interception', 'Modern security'],
        cons: ['More complex implementation', 'Requires cryptographic functions', 'Browser crypto API needed'],
        security_checklist: [
            'Implement proper code verifier generation',
            'Use SHA256 for code challenge',
            'Validate state parameter',
            'Store PKCE parameters securely',
            'Handle errors gracefully'
        ]
    },
    client_credentials: {
        when_to_use: 'Server-to-server communication',
        pros: ['Simple', 'No user consent needed', 'Secure for service communication'],
        cons: ['No user context', 'No refresh tokens', 'Limited scope'],
        security_checklist: [
            'Securely store client credentials',
            'Use least privilege principle',
            'Implement proper service authentication',
            'Monitor token usage',
            'Rotate credentials regularly'
        ]
    }
};

// Export functionality
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        OAuthFlowDecisionMatrix,
        ApplicationProfiles,
        FlowDecisionHelper,
        ImplementationGuides
    };
} else {
    window.OAuthDecisionMatrix = {
        OAuthFlowDecisionMatrix,
        ApplicationProfiles,
        FlowDecisionHelper,
        ImplementationGuides
    };
}

// Demo the decision matrix
FlowDecisionHelper.interactiveDecisionTool();
```

## Quick Reference Decision Tree

```
Start: What type of application do you have?
│
├── Server-to-Server Communication
│   └── Use: Client Credentials Flow
│
├── User-Facing Application (needs user login)
│   ├── Confidential Client (can store secrets)
│   │   └── Use: Authorization Code Flow
│   └── Public Client (mobile, SPA, desktop)
│       └── Use: PKCE Flow
│
└── Legacy System (migration required)
    └── Plan migration to modern flows
```

## Common Scenarios and Solutions

| Scenario | Recommended Flow | Reason | Alternative |
|----------|------------------|--------|-------------|
| **React SPA with Google Login** | PKCE | Public client, modern security | Authorization Code with backend proxy |
| **Mobile banking app** | PKCE | Critical security for public client | Platform-specific SDK with PKCE |
| **Node.js API integration** | Client Credentials | Service-to-service, no user consent | Authorization Code if user consent needed |
| **E-commerce platform** | Authorization Code | Confidential client, user transactions | PKCE for headless approach |
| **Desktop productivity app** | PKCE | Desktop apps are public clients | Authorization Code with local server |
| **Microservices communication** | Client Credentials | Service-to-service, machine-to-machine | mTLS for enhanced security |
| **Legacy web application** | Migration planning | Modern security requirements | Temporary use of existing flow |

## Security Considerations by Flow

### Authorization Code Flow
- **Security Level**: ★★★★★
- **Key Security Features**:
  - Client secret protection
  - Server-side token exchange
  - State parameter CSRF protection
  - Refresh token support

### PKCE Flow
- **Security Level**: ★★★★★
- **Key Security Features**:
  - Code verifier/challenge mechanism
  - No client secret required
  - SHA256 code challenge
  - Protection against code interception

### Client Credentials Flow
- **Security Level**: ★★★★☆
- **Key Security Features**:
  - Service-to-service authentication
  - No user context vulnerabilities
  - Scope-based access control
  - Regular credential rotation recommended

This decision matrix provides a systematic approach to selecting the appropriate OAuth 2.0 flow based on your specific application requirements and security needs.
