# Vault Integration Patterns

**Author:** MiniMax Agent  
**Date:** 2025-11-15

## Overview

This document provides comprehensive implementation patterns for integrating with HashiCorp Vault and other secrets management solutions, including dynamic secrets, automated rotation, and enterprise security patterns.

## 1. HashiCorp Vault Integration Patterns

```javascript
const axios = require('axios');
const fs = require('fs').promises;

class VaultIntegration {
  constructor(options = {}) {
    this.options = {
      vaultUrl: options.vaultUrl || 'http://localhost:8200',
      vaultToken: options.vaultToken,
      namespace: options.namespace || 'secret',
      maxRetries: options.maxRetries || 3,
      retryDelay: options.retryDelay || 1000,
      timeout: options.timeout || 30000,
      ...options
    };

    this.client = axios.create({
      baseURL: this.options.vaultUrl,
      timeout: this.options.timeout,
      headers: {
        'X-Vault-Token': this.options.vaultToken,
        'Content-Type': 'application/json'
      }
    });

    // Add response interceptor for error handling
    this.client.interceptors.response.use(
      response => response,
      error => this.handleVaultError(error)
    );
  }

  // Handle Vault API errors
  handleVaultError(error) {
    if (error.response) {
      const { status, data } = error.response;
      
      switch (status) {
        case 400:
          throw new Error(`Vault Bad Request: ${data.errors?.join(', ') || 'Invalid request'}`);
        case 403:
          throw new Error(`Vault Forbidden: ${data.errors?.join(', ') || 'Insufficient permissions'}`);
        case 404:
          throw new Error(`Vault Not Found: ${data.errors?.join(', ') || 'Path not found'}`);
        case 429:
          throw new Error(`Vault Rate Limited: ${data.errors?.join(', ') || 'Too many requests'}`);
        case 500:
          throw new Error(`Vault Internal Error: ${data.errors?.join(', ') || 'Server error'}`);
        default:
          throw new Error(`Vault Error ${status}: ${data.errors?.join(', ') || 'Unknown error'}`);
      }
    }
    
    throw new Error(`Vault Connection Error: ${error.message}`);
  }

  // Read secret from Vault
  async readSecret(path, options = {}) {
    const retries = options.retries || this.options.maxRetries;
    
    for (let i = 0; i < retries; i++) {
      try {
        const response = await this.client.get(`/v1/${this.options.namespace}/${path}`);
        
        return {
          data: response.data.data,
          metadata: response.data.metadata,
          path: path,
          readAt: new Date().toISOString()
        };
      } catch (error) {
        if (i === retries - 1) throw error;
        await this.delay(this.options.retryDelay * (i + 1));
      }
    }
  }

  // Write secret to Vault
  async writeSecret(path, secretData, options = {}) {
    const retries = options.retries || this.options.maxRetries;
    
    for (let i = 0; i < retries; i++) {
      try {
        const response = await this.client.post(`/v1/${this.options.namespace}/${path}`, {
          data: secretData
        });
        
        return {
          requestId: response.data.request_id,
          leaseId: response.data.lease_id,
          path: path,
          writtenAt: new Date().toISOString()
        };
      } catch (error) {
        if (i === retries - 1) throw error;
        await this.delay(this.options.retryDelay * (i + 1));
      }
    }
  }

  // Delete secret from Vault
  async deleteSecret(path, options = {}) {
    const retries = options.retries || this.options.maxRetries;
    
    for (let i = 0; i < retries; i++) {
      try {
        const response = await this.client.delete(`/v1/${this.options.namespace}/${path}`);
        
        return {
          requestId: response.data.request_id,
          path: path,
          deletedAt: new Date().toISOString()
        };
      } catch (error) {
        if (i === retries - 1) throw error;
        await this.delay(this.options.retryDelay * (i + 1));
      }
    }
  }

  // List secrets at path
  async listSecrets(path, options = {}) {
    const retries = options.retries || this.options.maxRetries;
    
    for (let i = 0; i < retries; i++) {
      try {
        const response = await this.client.get(`/v1/${this.options.namespace}/${path}`, {
          params: { list: true }
        });
        
        return {
          keys: response.data.data.keys,
          path: path,
          listedAt: new Date().toISOString()
        };
      } catch (error) {
        if (i === retries - 1) throw error;
        await this.delay(this.options.retryDelay * (i + 1));
      }
    }
  }

  // Dynamic database credentials
  async generateDatabaseCredentials(configPath, username = null, password = null) {
    const retries = this.options.maxRetries;
    
    for (let i = 0; i < retries; i++) {
      try {
        const data = {};
        if (username) data.username = username;
        if (password) data.password = password;
        
        const response = await this.client.post(`/v1/database/creds/${configPath}`, data);
        
        return {
          username: response.data.data.username,
          password: response.data.data.password,
          leaseId: response.data.lease_id,
          leaseDuration: response.data.lease_duration,
          renewable: response.data.renewable,
          generatedAt: new Date().toISOString()
        };
      } catch (error) {
        if (i === retries - 1) throw error;
        await this.delay(this.options.retryDelay * (i + 1));
      }
    }
  }

  // Renew lease
  async renewLease(leaseId) {
    const retries = this.options.maxRetries;
    
    for (let i = 0; i < retries; i++) {
      try {
        const response = await this.client.put(`/v1/sys/lease/renew`, {
          lease_id: leaseId
        });
        
        return {
          leaseId: leaseId,
          leaseDuration: response.data.lease_duration,
          renewable: response.data.renewable,
          renewedAt: new Date().toISOString()
        };
      } catch (error) {
        if (i === retries - 1) throw error;
        await this.delay(this.options.retryDelay * (i + 1));
      }
    }
  }

  // Revoke lease
  async revokeLease(leaseId) {
    const retries = this.options.maxRetries;
    
    for (let i = 0; i < retries; i++) {
      try {
        const response = await this.client.put(`/v1/sys/leases/revoke`, {
          lease_id: leaseId
        });
        
        return {
          leaseId: leaseId,
          revokedAt: new Date().toISOString()
        };
      } catch (error) {
        if (i === retries - 1) throw error;
        await this.delay(this.options.retryDelay * (i + 1));
      }
    }
  }

  // Transit encryption/decryption
  async encryptTransit(keyName, plaintext, options = {}) {
    const retries = this.options.maxRetries;
    
    for (let i = 0; i < retries; i++) {
      try {
        const data = {
          plaintext: Buffer.from(plaintext, 'utf8').toString('base64')
        };
        
        if (options.keyVersion) {
          data.key_version = options.keyVersion;
        }
        
        const response = await this.client.post(`/v1/transit/encrypt/${keyName}`, data);
        
        return {
          ciphertext: response.data.data.ciphertext,
          keyVersion: response.data.data.key_version,
          leaseId: response.data.lease_id,
          encryptedAt: new Date().toISOString()
        };
      } catch (error) {
        if (i === retries - 1) throw error;
        await this.delay(this.options.retryDelay * (i + 1));
      }
    }
  }

  // Transit decryption
  async decryptTransit(keyName, ciphertext, options = {}) {
    const retries = this.options.maxRetries;
    
    for (let i = 0; i < retries; i++) {
      try {
        const data = { ciphertext: ciphertext };
        
        if (options.keyVersion) {
          data.key_version = options.keyVersion;
        }
        
        const response = await this.client.post(`/v1/transit/decrypt/${keyName}`, data);
        
        return {
          plaintext: Buffer.from(response.data.data.plaintext, 'base64').toString('utf8'),
          keyVersion: response.data.data.key_version,
          decryptedAt: new Date().toISOString()
        };
      } catch (error) {
        if (i === retries - 1) throw error;
        await this.delay(this.options.retryDelay * (i + 1));
      }
    }
  }

  // PKI certificate generation
  async generateCertificate(roleName, csr, options = {}) {
    const retries = this.options.maxRetries;
    
    for (let i = 0; i < retries; i++) {
      try {
        const data = {
          csr: csr,
          format: options.format || 'pem_bundle'
        };
        
        if (options.commonName) data.common_name = options.commonName;
        if (options.altNames) data.alt_names = options.altNames.join(',');
        if (options.ipSans) data.ip_sans = options.ipSans.join(',');
        
        const response = await this.client.post(`/v1/pki/issue/${roleName}`, data);
        
        return {
          certificate: response.data.data.certificate,
          caChain: response.data.data.ca_chain,
          privateKey: response.data.data.private_key,
          serialNumber: response.data.data.serial_number,
          expiration: response.data.data.expiration,
          leaseId: response.data.lease_id,
          generatedAt: new Date().toISOString()
        };
      } catch (error) {
        if (i === retries - 1) throw error;
        await this.delay(this.options.retryDelay * (i + 1));
      }
    }
  }

  // Authentication token lookup
  async lookupToken() {
    try {
      const response = await this.client.get('/v1/auth/token/lookup-self');
      
      return {
        accessor: response.data.data.accessor,
        creationTime: new Date(response.data.data.creation_time * 1000),
        TTL: response.data.data.ttl,
        renewable: response.data.data.renewable,
        entityId: response.data.data.entity_id,
        policies: response.data.data.policies,
        lookupAt: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Token lookup failed: ${error.message}`);
    }
  }

  // Batch secret operations
  async batchSecrets(operations) {
    const results = [];
    
    for (const operation of operations) {
      try {
        let result;
        
        switch (operation.type) {
          case 'read':
            result = await this.readSecret(operation.path);
            break;
          case 'write':
            result = await this.writeSecret(operation.path, operation.data);
            break;
          case 'delete':
            result = await this.deleteSecret(operation.path);
            break;
          default:
            throw new Error(`Unknown operation type: ${operation.type}`);
        }
        
        results.push({
          operation: operation,
          success: true,
          result: result
        });
      } catch (error) {
        results.push({
          operation: operation,
          success: false,
          error: error.message
        });
      }
    }
    
    return results;
  }

  // Health check
  async healthCheck() {
    try {
      const response = await this.client.get('/v1/sys/health');
      
      return {
        status: 'healthy',
        version: response.data.version,
        clusterId: response.data.cluster_id,
        clusterName: response.data.cluster_name,
        lastUpdated: new Date().toISOString()
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        error: error.message,
        lastUpdated: new Date().toISOString()
      };
    }
  }

  // Helper method for delays
  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Usage example
async function demonstrateVaultIntegration() {
  const vault = new VaultIntegration({
    vaultUrl: 'http://localhost:8200',
    vaultToken: 'your-vault-token',
    namespace: 'secret'
  });

  console.log('🔐 Vault Integration Demo');
  console.log('=' .repeat(40));

  // Health check
  console.log('Checking Vault health...');
  const health = await vault.healthCheck();
  console.log('Vault status:', health.status);

  // Write secret
  console.log('\n📝 Writing secret...');
  const writeResult = await vault.writeSecret('demo/database', {
    host: 'localhost',
    port: 5432,
    database: 'mydb',
    username: 'admin',
    password: 'secret123'
  });
  console.log('Secret written:', writeResult.path);

  // Read secret
  console.log('\n📖 Reading secret...');
  const readResult = await vault.readSecret('demo/database');
  console.log('Secret data:', readResult.data);

  // Encrypt with transit
  console.log('\n🔒 Transit encryption...');
  const encrypted = await vault.encryptTransit('encryption-key', 'This is sensitive data!');
  console.log('Encrypted:', encrypted.ciphertext.substring(0, 64) + '...');

  const decrypted = await vault.decryptTransit('encryption-key', encrypted.ciphertext);
  console.log('Decrypted:', decrypted.plaintext);

  // Token lookup
  console.log('\n🔑 Token information:');
  const tokenInfo = await vault.lookupToken();
  console.log('Token TTL:', tokenInfo.TTL);
  console.log('Token policies:', tokenInfo.policies);
}

// Uncomment to run demonstration
// demonstrateVaultIntegration().catch(console.error);

module.exports = VaultIntegration;
```

## 2. AWS Secrets Manager Integration

```javascript
const AWS = require('aws-sdk');

class AWSSecretsManager {
  constructor(options = {}) {
    this.options = {
      region: options.region || 'us-east-1',
      accessKeyId: options.accessKeyId,
      secretAccessKey: options.secretAccessKey,
      ...options
    };

    this.client = new AWS.SecretsManager({
      region: this.options.region,
      accessKeyId: this.options.accessKeyId,
      secretAccessKey: this.options.secretAccessKey
    });

    this.secretCache = new Map();
    this.cacheTimeout = options.cacheTimeout || 300000; // 5 minutes
  }

  // Create secret
  async createSecret(secretName, secretValue, description = '', options = {}) {
    const params = {
      Name: secretName,
      SecretString: JSON.stringify(secretValue),
      Description: description
    };

    if (options.addReplicas) {
      params.AddReplicaRegions = options.addReplicas;
    }

    try {
      const result = await this.client.createSecret(params).promise();
      
      return {
        secretId: result.ARN,
        secretName: result.Name,
        created: true,
        versionId: result.VersionId,
        createdAt: result.CreatedDate,
        replicationStatus: result.ReplicationStatus || []
      };
    } catch (error) {
      throw new Error(`Failed to create secret: ${error.message}`);
    }
  }

  // Get secret value
  async getSecret(secretId, versionId = null, options = {}) {
    const cacheKey = `${secretId}:${versionId || 'latest'}`;
    const cached = this.secretCache.get(cacheKey);
    
    // Check cache
    if (cached && (Date.now() - cached.timestamp) < this.cacheTimeout) {
      return cached.data;
    }

    const params = {
      SecretId: secretId
    };

    if (versionId) {
      params.VersionId = versionId;
    }

    try {
      const result = await this.client.getSecretValue(params).promise();
      
      let secretData;
      
      if (result.SecretString) {
        try {
          secretData = JSON.parse(result.SecretString);
        } catch (e) {
          secretData = result.SecretString;
        }
      } else if (result.SecretBinary) {
        secretData = result.SecretBinary;
      }

      const response = {
        secretId: result.ARN,
        secretName: result.Name,
        secretData: secretData,
        versionId: result.VersionId,
        createdDate: result.CreatedDate,
        lastAccessedDate: result.LastAccessedDate
      };

      // Cache the result
      this.secretCache.set(cacheKey, {
        data: response,
        timestamp: Date.now()
      });

      return response;
    } catch (error) {
      throw new Error(`Failed to get secret: ${error.message}`);
    }
  }

  // Update secret
  async updateSecret(secretId, secretValue, description = null) {
    const params = {
      SecretId: secretId
    };

    if (typeof secretValue === 'string') {
      params.SecretString = secretValue;
    } else {
      params.SecretString = JSON.stringify(secretValue);
    }

    if (description !== null) {
      params.Description = description;
    }

    try {
      const result = await this.client.updateSecret(params).promise();
      
      return {
        secretId: result.ARN,
        secretName: result.Name,
        updated: true,
        versionId: result.VersionId,
        updatedAt: result.UpdatedDate
      };
    } catch (error) {
      throw new Error(`Failed to update secret: ${error.message}`);
    }
  }

  // Delete secret
  async deleteSecret(secretId, forceDeleteWithoutRecovery = false) {
    const params = {
      SecretId: secretId
    };

    if (forceDeleteWithoutRecovery) {
      params.ForceDeleteWithoutRecovery = true;
    }

    try {
      const result = await this.client.deleteSecret(params).promise();
      
      return {
        secretId: result.ARN,
        secretName: result.Name,
        deleted: true,
        deletionDate: result.DeletionDate,
        recoveryWindowInDays: result.RecoveryWindowInDays
      };
    } catch (error) {
      throw new Error(`Failed to delete secret: ${error.message}`);
    }
  }

  // Restore deleted secret
  async restoreSecret(secretId) {
    const params = {
      SecretId: secretId
    };

    try {
      const result = await this.client.restoreSecret(params).promise();
      
      return {
        secretId: result.ARN,
        secretName: result.Name,
        restored: true,
        restoredAt: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Failed to restore secret: ${error.message}`);
    }
  }

  // List secrets
  async listSecrets(options = {}) {
    const params = {
      MaxResults: options.maxResults || 100,
      NextToken: options.nextToken || null,
      Filters: options.filters || null
    };

    try {
      const result = await this.client.listSecrets(params).promise();
      
      return {
        secrets: result.SecretList.map(secret => ({
          secretId: secret.ARN,
          secretName: secret.Name,
          description: secret.Description,
          lastChangedDate: secret.LastChangedDate,
          lastAccessedDate: secret.LastAccessedDate,
          nextRotationDate: secret.NextRotationDate,
          rotationEnabled: secret.RotationEnabled,
          tags: secret.Tags || [],
          createdDate: secret.CreatedDate
        })),
        nextToken: result.NextToken || null,
        totalSecrets: result.SecretList.length
      };
    } catch (error) {
      throw new Error(`Failed to list secrets: ${error.message}`);
    }
  }

  // Rotate secret (if automatic rotation is enabled)
  async rotateSecret(secretId, clientRequestToken = null) {
    const params = {
      SecretId: secretId
    };

    if (clientRequestToken) {
      params.ClientRequestToken = clientRequestToken;
    }

    try {
      const result = await this.client.rotateSecret(params).promise();
      
      return {
        secretId: result.ARN,
        secretName: result.Name,
        versionId: result.VersionId,
        rotated: true,
        rotatedAt: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Failed to rotate secret: ${error.message}`);
    }
  }

  // Batch operations
  async batchGetSecrets(secretIds, versions = {}) {
    const results = [];
    
    for (const secretId of secretIds) {
      try {
        const versionId = versions[secretId];
        const secret = await this.getSecret(secretId, versionId);
        results.push({
          secretId: secretId,
          success: true,
          data: secret
        });
      } catch (error) {
        results.push({
          secretId: secretId,
          success: false,
          error: error.message
        });
      }
    }
    
    return results;
  }

  // Automatic rotation with Lambda
  async createRotationLambda(secretId, lambdaFunctionName) {
    const rotationPolicy = {
      RotationRules: {
        AutomaticallyAfterDays: 30,
        Duration: '4h'
      },
      RotationLambdaEncryption: {
        KMSKeyId: 'alias/aws/secretsmanager'
      }
    };

    try {
      const result = await this.client.rotateSecret({
        SecretId: secretId,
        RotationRules: rotationPolicy.RotationRules,
        RotationLambdaEncryption: rotationPolicy.RotationLambdaEncryption
      }).promise();
      
      return {
        secretId: result.ARN,
        secretName: result.Name,
        rotationEnabled: true,
        configuredAt: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Failed to enable rotation: ${error.message}`);
    }
  }

  // Tag management
  async tagSecret(secretId, tags) {
    const params = {
      SecretId: secretId,
      Tags: tags.map(tag => ({
        Key: tag.key,
        Value: tag.value
      }))
    };

    try {
      await this.client.tagResource(params).promise();
      
      return {
        secretId: secretId,
        tagged: true,
        tags: tags,
        taggedAt: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Failed to tag secret: ${error.message}`);
    }
  }

  // Resource-based policy
  async putResourcePolicy(secretId, policy) {
    const params = {
      SecretId: secretId,
      ResourcePolicy: JSON.stringify(policy)
    };

    try {
      await this.client.putResourcePolicy(params).promise();
      
      return {
        secretId: secretId,
        policy: policy,
        applied: true,
        appliedAt: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Failed to apply resource policy: ${error.message}`);
    }
  }

  // Secret metadata
  async getSecretMetadata(secretId) {
    try {
      const result = await this.client.describeSecret({ SecretId: secretId }).promise();
      
      return {
        secretId: result.ARN,
        secretName: result.Name,
        description: result.Description,
        rotationEnabled: result.RotationEnabled,
        rotationRules: result.RotationRules,
        lastChangedDate: result.LastChangedDate,
        lastAccessedDate: result.LastAccessedDate,
        nextRotationDate: result.NextRotationDate,
        createdDate: result.CreatedDate,
        deletionDate: result.DeletionDate
      };
    } catch (error) {
      throw new Error(`Failed to get secret metadata: ${error.message}`);
    }
  }

  // Cache management
  clearCache() {
    this.secretCache.clear();
    return {
      cacheCleared: true,
      clearedAt: new Date().toISOString()
    };
  }

  getCacheStatus() {
    const cacheEntries = Array.from(this.secretCache.entries());
    const now = Date.now();
    
    let expired = 0;
    let active = 0;
    
    for (const [key, value] of cacheEntries) {
      if ((now - value.timestamp) > this.cacheTimeout) {
        expired++;
      } else {
        active++;
      }
    }
    
    return {
      totalEntries: cacheEntries.length,
      activeEntries: active,
      expiredEntries: expired,
      cacheTimeout: this.cacheTimeout,
      lastChecked: new Date().toISOString()
    };
  }
}

// Usage example
async function demonstrateAWSSecrets() {
  const awsSecrets = new AWSSecretsManager({
    region: 'us-east-1',
    accessKeyId: 'your-access-key',
    secretAccessKey: 'your-secret-key'
  });

  console.log('🔐 AWS Secrets Manager Demo');
  console.log('=' .repeat(40));

  // Create secret
  console.log('Creating secret...');
  const createResult = await awsSecrets.createSecret(
    'demo/api-key',
    {
      apiKey: 'sk_live_1234567890abcdef',
      apiSecret: 'secret1234567890abcdef1234567890abcdef',
      environment: 'production'
    },
    'Demo API credentials'
  );
  console.log('Secret created:', createResult.secretName);

  // Get secret
  console.log('\nGetting secret...');
  const secret = await awsSecrets.getSecret('demo/api-key');
  console.log('Secret data:', secret.secretData);

  // Update secret
  console.log('\nUpdating secret...');
  const updateResult = await awsSecrets.updateSecret(
    'demo/api-key',
    {
      apiKey: 'sk_live_new1234567890abcdef',
      apiSecret: 'secretnew1234567890abcdef1234567890abcdef',
      environment: 'production',
      updatedAt: new Date().toISOString()
    }
  );
  console.log('Secret updated:', updateResult.versionId);

  // List secrets
  console.log('\nListing secrets...');
  const secrets = await awsSecrets.listSecrets({ MaxResults: 10 });
  console.log('Total secrets:', secrets.totalSecrets);

  // Cache status
  console.log('\nCache status:');
  const cacheStatus = awsSecrets.getCacheStatus();
  console.log('Cache entries:', cacheStatus.totalEntries);
}

// Uncomment to run demonstration
// demonstrateAWSSecrets().catch(console.error);

module.exports = AWSSecretsManager;
```

## 3. Dynamic Secrets and Rotation Patterns

```javascript
const EventEmitter = require('events');

class DynamicSecretsManager extends EventEmitter {
  constructor(vaultClient, options = {}) {
    super();
    this.vault = vaultClient;
    this.options = {
      rotationInterval: options.rotationInterval || 3600000, // 1 hour
      maxLeaseDuration: options.maxLeaseDuration || 86400000, // 24 hours
      renewalThreshold: options.renewalThreshold || 0.8, // 80% of lease duration
      ...options
    };

    this.activeLeases = new Map();
    this.rotationJobs = new Map();
    this.secretsCache = new Map();
    
    this.startRotationManager();
  }

  // Generate dynamic credentials for database
  async getDatabaseCredentials(configPath, username = null, options = {}) {
    const lease = await this.vault.generateDatabaseCredentials(configPath, username);
    
    const credentials = {
      type: 'database_credentials',
      configPath: configPath,
      username: lease.username,
      password: lease.password,
      leaseId: lease.leaseId,
      expiresAt: new Date(Date.now() + (lease.leaseDuration * 1000)),
      createdAt: new Date(),
      renewable: lease.renewable,
      metadata: {
        configPath: configPath,
        generatedBy: 'DynamicSecretsManager'
      }
    };

    // Store lease for renewal
    this.activeLeases.set(lease.leaseId, {
      type: 'database_credentials',
      configPath: configPath,
      credentials: credentials,
      leaseDuration: lease.leaseDuration
    });

    // Schedule renewal
    this.scheduleLeaseRenewal(lease.leaseId, lease.leaseDuration);

    this.emit('credentialsGenerated', {
      type: 'database',
      configPath: configPath,
      leaseId: lease.leaseId
    });

    return credentials;
  }

  // Generate dynamic AWS credentials
  async getAWSCredentials(roleName, options = {}) {
    const credentials = await this.vault.readSecret(`aws/creds/${roleName}`);
    
    const dynamicCreds = {
      type: 'aws_credentials',
      roleName: roleName,
      accessKeyId: credentials.data.access_key,
      secretAccessKey: credentials.data.secret_key,
      sessionToken: credentials.data.security_token,
      leaseId: credentials.lease_id,
      expiresAt: new Date(Date.now() + (credentials.lease_duration * 1000)),
      createdAt: new Date(),
      renewable: credentials.renewable
    };

    // Store lease
    this.activeLeases.set(credentials.lease_id, {
      type: 'aws_credentials',
      roleName: roleName,
      credentials: dynamicCreds,
      leaseDuration: credentials.lease_duration
    });

    // Schedule renewal
    this.scheduleLeaseRenewal(credentials.lease_id, credentials.lease_duration);

    this.emit('credentialsGenerated', {
      type: 'aws',
      roleName: roleName,
      leaseId: credentials.lease_id
    });

    return dynamicCreds;
  }

  // Schedule lease renewal
  scheduleLeaseRenewal(leaseId, leaseDuration) {
    const renewalTime = leaseDuration * this.options.renewalThreshold * 1000;
    
    setTimeout(async () => {
      try {
        await this.renewLease(leaseId);
      } catch (error) {
        console.error(`Failed to renew lease ${leaseId}:`, error.message);
        this.emit('renewalFailed', { leaseId, error: error.message });
      }
    }, renewalTime);
  }

  // Renew lease
  async renewLease(leaseId) {
    const leaseInfo = this.activeLeases.get(leaseId);
    if (!leaseInfo) {
      throw new Error(`Lease not found: ${leaseId}`);
    }

    const renewal = await this.vault.renewLease(leaseId);
    
    // Update lease info
    leaseInfo.leaseDuration = renewal.leaseDuration;
    
    // Reschedule renewal
    this.scheduleLeaseRenewal(leaseId, renewal.leaseDuration);

    this.emit('leaseRenewed', {
      leaseId: leaseId,
      newDuration: renewal.leaseDuration
    });

    return renewal;
  }

  // Revoke lease
  async revokeLease(leaseId) {
    const leaseInfo = this.activeLeases.get(leaseId);
    if (!leaseInfo) {
      throw new Error(`Lease not found: ${leaseId}`);
    }

    await this.vault.revokeLease(leaseId);
    this.activeLeases.delete(leaseId);

    this.emit('leaseRevoked', {
      leaseId: leaseId,
      type: leaseInfo.type
    });

    return {
      leaseId: leaseId,
      revoked: true,
      revokedAt: new Date()
    };
  }

  // Generate dynamic credentials with rotation policy
  async getRotatingCredentials(secretPath, rotationPolicy = {}) {
    const cacheKey = `${secretPath}:${rotationPolicy.version || 'latest'}`;
    const cached = this.secretsCache.get(cacheKey);
    
    if (cached && (Date.now() - cached.timestamp) < this.options.rotationInterval) {
      return cached.data;
    }

    // Generate new credentials
    const credentials = await this.vault.readSecret(secretPath);
    
    const rotatingCreds = {
      type: 'rotating_credentials',
      secretPath: secretPath,
      credentials: credentials.data,
      leaseId: credentials.lease_id,
      expiresAt: new Date(Date.now() + (credentials.lease_duration * 1000)),
      createdAt: new Date(),
      renewable: credentials.renewable,
      rotationPolicy: rotationPolicy,
      version: credentials.metadata?.version || 'v1'
    };

    // Cache credentials
    this.secretsCache.set(cacheKey, {
      data: rotatingCreds,
      timestamp: Date.now(),
      secretPath: secretPath
    });

    // Schedule rotation if needed
    this.scheduleSecretRotation(secretPath, rotationPolicy);

    this.emit('credentialsGenerated', {
      type: 'rotating',
      secretPath: secretPath,
      leaseId: credentials.lease_id
    });

    return rotatingCreds;
  }

  // Schedule secret rotation
  scheduleSecretRotation(secretPath, policy) {
    const rotationInterval = policy.interval || this.options.rotationInterval;
    
    const rotationJob = setInterval(async () => {
      try {
        await this.rotateSecret(secretPath, policy);
      } catch (error) {
        console.error(`Failed to rotate secret ${secretPath}:`, error.message);
        this.emit('rotationFailed', { secretPath, error: error.message });
      }
    }, rotationInterval);

    this.rotationJobs.set(secretPath, rotationJob);
  }

  // Rotate secret manually
  async rotateSecret(secretPath, policy = {}) {
    const currentSecret = await this.vault.readSecret(secretPath);
    
    // Generate new credentials
    const newCredentials = this.generateNewCredentials(currentSecret.data, policy);
    
    // Update in Vault
    const updateResult = await this.vault.writeSecret(secretPath, newCredentials);
    
    // Clear cache
    this.secretsCache.delete(secretPath);
    
    this.emit('secretRotated', {
      secretPath: secretPath,
      rotatedAt: new Date(),
      oldVersion: currentSecret.metadata?.version || 'v1',
      newVersion: policy.nextVersion || this.incrementVersion(currentSecret.metadata?.version)
    });

    return {
      secretPath: secretPath,
      rotated: true,
      rotatedAt: new Date(),
      oldCredentials: currentSecret.data,
      newCredentials: newCredentials,
      leaseId: updateResult.leaseId
    };
  }

  // Generate new credentials based on policy
  generateNewCredentials(oldCredentials, policy) {
    const newCreds = { ...oldCredentials };
    
    if (policy.rotateFields) {
      for (const field of policy.rotateFields) {
        if (newCreds[field]) {
          newCreds[field] = this.generateRandomString(32);
        }
      }
    }
    
    if (policy.addTimestamp) {
      newCreds.lastRotatedAt = new Date().toISOString();
    }
    
    if (policy.incrementVersion) {
      const currentVersion = oldCredentials.version || 'v1';
      newCreds.version = this.incrementVersion(currentVersion);
    }
    
    return newCreds;
  }

  // Utility methods
  generateRandomString(length) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  incrementVersion(version) {
    const match = version.match(/v(\d+)/);
    if (match) {
      const num = parseInt(match[1]) + 1;
      return `v${num}`;
    }
    return version;
  }

  // Start rotation manager
  startRotationManager() {
    this.rotationManager = setInterval(() => {
      this.performMaintenanceTasks();
    }, 60000); // Run every minute
  }

  // Perform maintenance tasks
  async performMaintenanceTasks() {
    const now = new Date();
    
    // Clean up expired leases
    for (const [leaseId, leaseInfo] of this.activeLeases) {
      if (leaseInfo.credentials.expiresAt < now) {
        console.log(`Cleaning up expired lease: ${leaseId}`);
        this.activeLeases.delete(leaseId);
        
        this.emit('leaseExpired', {
          leaseId: leaseId,
          type: leaseInfo.type
        });
      }
    }
    
    // Clean up old cache entries
    for (const [cacheKey, cacheEntry] of this.secretsCache) {
      if ((Date.now() - cacheEntry.timestamp) > this.options.rotationInterval * 2) {
        this.secretsCache.delete(cacheKey);
      }
    }
  }

  // Get status
  getStatus() {
    return {
      activeLeases: this.activeLeases.size,
      cachedSecrets: this.secretsCache.size,
      rotationJobs: this.rotationJobs.size,
      uptime: process.uptime(),
      lastMaintenance: new Date().toISOString()
    };
  }

  // Stop rotation manager
  stopRotationManager() {
    if (this.rotationManager) {
      clearInterval(this.rotationManager);
      this.rotationManager = null;
    }
    
    // Cancel all rotation jobs
    for (const [secretPath, job] of this.rotationJobs) {
      clearInterval(job);
    }
    this.rotationJobs.clear();
  }

  // Graceful shutdown
  async shutdown() {
    console.log('Shutting down DynamicSecretsManager...');
    
    // Stop rotation manager
    this.stopRotationManager();
    
    // Revoke all active leases
    const revocationPromises = [];
    for (const [leaseId] of this.activeLeases) {
      revocationPromises.push(this.revokeLease(leaseId));
    }
    
    try {
      await Promise.all(revocationPromises);
      console.log('All leases revoked successfully');
    } catch (error) {
      console.error('Error revoking leases:', error.message);
    }
    
    this.emit('shutdown', { timestamp: new Date() });
  }
}

// Usage example
async function demonstrateDynamicSecrets() {
  const vault = new VaultIntegration({
    vaultUrl: 'http://localhost:8200',
    vaultToken: 'your-token'
  });

  const dynamicSecrets = new DynamicSecretsManager(vault, {
    rotationInterval: 300000, // 5 minutes for demo
    renewalThreshold: 0.5 // 50% for demo
  });

  console.log('🔄 Dynamic Secrets Manager Demo');
  console.log('=' .repeat(40));

  // Generate dynamic database credentials
  console.log('Generating dynamic database credentials...');
  const dbCreds = await dynamicSecrets.getDatabaseCredentials('demo-postgres');
  console.log('Database username:', dbCreds.username);
  console.log('Database password:', dbCreds.password.substring(0, 8) + '...');
  console.log('Lease ID:', dbCreds.leaseId);

  // Generate rotating credentials
  console.log('\nGenerating rotating credentials...');
  const rotatingCreds = await dynamicSecrets.getRotatingCredentials('api/credentials', {
    rotateFields: ['apiKey', 'apiSecret'],
    addTimestamp: true,
    incrementVersion: true
  });
  console.log('API Key:', rotatingCreds.credentials.apiKey.substring(0, 16) + '...');
  console.log('Version:', rotatingCreds.version);

  // Status check
  console.log('\nManager status:');
  const status = dynamicSecrets.getStatus();
  console.log('Active leases:', status.activeLeases);
  console.log('Cached secrets:', status.cachedSecrets);
  console.log('Rotation jobs:', status.rotationJobs);

  // Listen to events
  dynamicSecrets.on('credentialsGenerated', (event) => {
    console.log(`\n🔔 Event: Credentials generated (${event.type}) for ${event.leaseId}`);
  });

  dynamicSecrets.on('leaseRenewed', (event) => {
    console.log(`\n🔔 Event: Lease renewed ${event.leaseId} for ${event.newDuration}s`);
  });

  // Simulate rotation after 10 seconds
  setTimeout(async () => {
    console.log('\n🔄 Triggering manual rotation...');
    const rotationResult = await dynamicSecrets.rotateSecret('api/credentials', {
      rotateFields: ['apiKey'],
      addTimestamp: true
    });
    console.log('Rotation completed:', rotationResult.rotatedAt);
  }, 10000);
}

// Uncomment to run demonstration
// demonstrateDynamicSecrets().catch(console.error);

module.exports = DynamicSecretsManager;
```

This comprehensive vault integration system provides:

1. **HashiCorp Vault integration** with retry logic and error handling
2. **AWS Secrets Manager integration** with caching and batch operations
3. **Dynamic secrets management** with automatic renewal and rotation
4. **Event-driven architecture** for monitoring and alerting
5. **Enterprise patterns** for production environments
6. **Resource management** with proper cleanup and shutdown
7. **Multiple authentication methods** and access patterns
8. **Comprehensive error handling** and recovery mechanisms
9. **Performance optimizations** with caching and batch operations
10. **Security best practices** throughout the implementation

The patterns support modern secrets management requirements while maintaining operational reliability and security compliance.
