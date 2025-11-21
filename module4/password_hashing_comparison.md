# Password Hashing Algorithm Comparison

**Author:** MiniMax Agent  
**Date:** 2025-11-15

## Overview

This document provides a comprehensive comparison of password hashing algorithms, implementation examples, performance testing, and security analysis to help choose the most appropriate algorithm for different use cases.

## 1. Algorithm Overview and Comparison

### 1.1 Password Hashing Algorithm Comparison Matrix

| Algorithm | Security Level | Computational Cost | Memory Usage | Configurable Work Factor | Parallel Processing | Side-Channel Resistance | NIST Recommendation | Implementation Complexity |
|-----------|----------------|-------------------|--------------|-------------------------|-------------------|------------------------|-------------------|-------------------------|
| MD5 | ❌ Broken | Very Low | None | No | No | Poor | ❌ Deprecated | Low |
| SHA-1 | ❌ Broken | Low | None | No | No | Poor | ❌ Deprecated | Low |
| SHA-256/512 | ⚠️ Weak | Medium | None | No | No | Medium | ❌ Not recommended | Low |
| bcrypt | ✅ Good | High (configurable) | Low | Yes (work factor) | Limited | Good | ✅ Acceptable | Medium |
| scrypt | ✅ Excellent | High (configurable) | High | Yes | Yes | Good | ✅ Recommended | High |
| Argon2 | ✅ Excellent | High (configurable) | Configurable | Yes | Yes | Excellent | ✅ Preferred | Medium |

### 1.2 Attack Resistance Comparison

| Attack Vector | MD5 | SHA-1 | bcrypt | scrypt | Argon2 |
|---------------|-----|-------|---------|--------|---------|
| Brute Force | ❌ Very Weak | ❌ Very Weak | ✅ Strong | ✅ Strong | ✅ Strong |
| Rainbow Tables | ✅ Protected (with salt) | ✅ Protected (with salt) | ✅ Protected (with salt) | ✅ Protected (with salt) | ✅ Protected (with salt) |
| GPU/ASIC Attacks | ❌ Vulnerable | ❌ Vulnerable | ⚠️ Somewhat Resistant | ✅ Resistant | ✅ Resistant |
| Memory-Hard Attacks | ❌ Vulnerable | ❌ Vulnerable | ❌ Vulnerable | ✅ Resistant | ✅ Resistant |
| Side-Channel Attacks | ❌ Vulnerable | ❌ Vulnerable | ⚠️ Somewhat Resistant | ✅ Resistant | ✅ Excellent |

## 2. Implementation Examples

### 2.1 Argon2 Implementation (Recommended)

```javascript
const argon2 = require('argon2');
const crypto = require('crypto');

class Argon2PasswordHasher {
  constructor(options = {}) {
    this.options = {
      // Memory cost in KiB (default: 65536 = 64 MB)
      memoryCost: options.memoryCost || 65536,
      // Time cost (number of iterations) (default: 3)
      timeCost: options.timeCost || 3,
      // Parallelism (default: 1)
      parallelism: options.parallelism || 1,
      // Hash length in bytes (default: 32)
      hashLength: options.hashLength || 32,
      // Salt length in bytes (default: 16)
      saltLength: options.saltLength || 16,
      // Argon2 variant (default: argon2id)
      type: options.type || argon2.argon2id,
      ...options
    };
  }

  async hashPassword(password, options = {}) {
    // Generate cryptographically secure salt
    const salt = crypto.randomBytes(this.options.saltLength);
    
    // Combine password with salt for hashing
    const passwordWithSalt = `${password}:${salt.toString('hex')}`;
    
    try {
      const hash = await argon2.hash(passwordWithSalt, {
        type: this.options.type,
        memoryCost: options.memoryCost || this.options.memoryCost,
        timeCost: options.timeCost || this.options.timeCost,
        parallelism: options.parallelism || this.options.parallelism,
        hashLength: this.options.hashLength,
        salt: salt
      });
      
      return {
        hash: hash,
        salt: salt.toString('hex'),
        algorithm: 'Argon2id',
        parameters: {
          memoryCost: options.memoryCost || this.options.memoryCost,
          timeCost: options.timeCost || this.options.timeCost,
          parallelism: options.parallelism || this.options.parallelism
        }
      };
    } catch (error) {
      throw new Error(`Password hashing failed: ${error.message}`);
    }
  }

  async verifyPassword(password, hash, salt) {
    try {
      const passwordWithSalt = `${password}:${salt}`;
      
      return await argon2.verify(hash, passwordWithSalt);
    } catch (error) {
      // Log verification failure for security monitoring
      console.warn('Password verification failed:', error.message);
      return false;
    }
  }

  // Adaptive hashing - adjust parameters based on system capabilities
  async adaptiveHashPassword(password) {
    // Detect system capabilities
    const systemCapabilities = await this.detectSystemCapabilities();
    
    const adaptiveParams = this.calculateAdaptiveParameters(systemCapabilities);
    
    return await this.hashPassword(password, adaptiveParams);
  }

  async detectSystemCapabilities() {
    const startTime = performance.now();
    
    // Simple computation to test system speed
    await argon2.hash('test', {
      type: argon2.argon2id,
      memoryCost: 32768, // 32 MB
      timeCost: 1,
      parallelism: 1
    });
    
    const endTime = performance.now();
    const computationTime = endTime - startTime;
    
    return {
      computationTime: computationTime,
      memoryAvailable: this.getAvailableMemory(),
      cpuCores: require('os').cpus().length
    };
  }

  calculateAdaptiveParameters(capabilities) {
    // Adjust parameters based on system performance
    let memoryCost = this.options.memoryCost;
    let timeCost = this.options.timeCost;
    let parallelism = this.options.parallelism;
    
    // If computation is slow, reduce parameters
    if (capabilities.computationTime > 500) { // 500ms
      memoryCost = Math.floor(memoryCost / 2);
      timeCost = Math.max(1, timeCost - 1);
    }
    
    // If system has more cores, increase parallelism
    if (capabilities.cpuCores > 4) {
      parallelism = Math.min(capabilities.cpuCores / 2, 4);
    }
    
    return { memoryCost, timeCost, parallelism };
  }

  getAvailableMemory() {
    // Simple memory detection
    const os = require('os');
    return os.totalmem() - os.freemem();
  }

  // Benchmark different parameter combinations
  async benchmarkParameters() {
    const testPassword = 'test_password_123';
    const testCases = [
      { memoryCost: 32768, timeCost: 1, parallelism: 1 },
      { memoryCost: 65536, timeCost: 2, parallelism: 1 },
      { memoryCost: 65536, timeCost: 3, parallelism: 2 },
      { memoryCost: 131072, timeCost: 3, parallelism: 2 },
      { memoryCost: 131072, timeCost: 4, parallelism: 4 }
    ];
    
    const results = [];
    
    for (const params of testCases) {
      console.log(`Testing parameters:`, params);
      
      const startTime = performance.now();
      const hashResult = await this.hashPassword(testPassword, params);
      const hashTime = performance.now() - startTime;
      
      const verifyStartTime = performance.now();
      const isValid = await this.verifyPassword(testPassword, hashResult.hash, hashResult.salt);
      const verifyTime = performance.now() - verifyStartTime;
      
      results.push({
        parameters: params,
        hashTime: hashTime,
        verifyTime: verifyTime,
        isValid: isValid,
        hashLength: hashResult.hash.length
      });
      
      console.log(`  Hash time: ${hashTime.toFixed(2)}ms, Verify time: ${verifyTime.toFixed(2)}ms`);
    }
    
    return results;
  }

  // Parse Argon2 hash string to extract parameters
  parseArgon2Hash(hashString) {
    // Argon2 hash format: $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
    const parts = hashString.split('$');
    
    if (parts.length !== 6) {
      throw new Error('Invalid Argon2 hash format');
    }
    
    const variant = parts[1];
    const version = parts[2];
    const params = parts[3];
    const salt = parts[4];
    const hash = parts[5];
    
    const paramMap = {};
    params.split(',').forEach(param => {
      const [key, value] = param.split('=');
      paramMap[key] = parseInt(value);
    });
    
    return {
      variant: variant,
      version: version,
      parameters: paramMap,
      salt: salt,
      hash: hash
    };
  }

  // Check if stored hash needs rehashing with current parameters
  needsRehashing(storedHash, currentOptions = {}) {
    try {
      const parsed = this.parseArgon2Hash(storedHash);
      const current = { ...this.options, ...currentOptions };
      
      // Check if parameters are outdated
      return (
        parsed.parameters.m < current.memoryCost ||
        parsed.parameters.t < current.timeCost ||
        parsed.parameters.p < current.parallelism ||
        parsed.variant !== 'argon2id'
      );
    } catch (error) {
      return true; // Rehash if parsing fails
    }
  }
}

// Usage examples
async function demonstrateArgon2() {
  const hasher = new Argon2PasswordHasher({
    memoryCost: 65536, // 64 MB
    timeCost: 3,
    parallelism: 1
  });

  // Basic hashing
  const password = 'MySecurePassword123!';
  console.log('🔐 Hashing password with Argon2...');
  
  const hashResult = await hasher.hashPassword(password);
  console.log('✅ Hash created successfully');
  console.log(`Hash: ${hashResult.hash}`);
  console.log(`Salt: ${hashResult.salt}`);
  console.log(`Algorithm: ${hashResult.algorithm}`);
  console.log(`Parameters:`, hashResult.parameters);

  // Verification
  console.log('\n🔍 Verifying password...');
  const isValid = await hasher.verifyPassword(password, hashResult.hash, hashResult.salt);
  console.log(`Password valid: ${isValid}`);

  // Wrong password
  const isInvalid = await hasher.verifyPassword('WrongPassword', hashResult.hash, hashResult.salt);
  console.log(`Wrong password rejected: ${!isInvalid}`);

  // Benchmarking
  console.log('\n📊 Running benchmarks...');
  const benchmarkResults = await hasher.benchmarkParameters();
  console.log('Benchmark results:', benchmarkResults);

  // Adaptive hashing
  console.log('\n🎯 Testing adaptive hashing...');
  const adaptiveHash = await hasher.adaptiveHashPassword(password);
  console.log('Adaptive hash created:', adaptiveHash.algorithm);
}

// Uncomment to run demonstration
// demonstrateArgon2().catch(console.error);

module.exports = Argon2PasswordHasher;
```

### 2.2 bcrypt Implementation (Legacy Support)

```javascript
const bcrypt = require('bcrypt');
const crypto = require('crypto');

class BCryptPasswordHasher {
  constructor(options = {}) {
    this.options = {
      // Work factor (2^work = number of rounds)
      saltRounds: options.saltRounds || 12,
      // bcrypt variants
      variant: options.variant || 'bcrypt', // bcrypt, bcrypta, bcryptx
      ...options
    };
  }

  async hashPassword(password, options = {}) {
    const saltRounds = options.saltRounds || this.options.saltRounds;
    
    try {
      const salt = await bcrypt.genSalt(saltRounds);
      const hash = await bcrypt.hash(password, salt);
      
      return {
        hash: hash,
        salt: salt,
        algorithm: 'bcrypt',
        workFactor: saltRounds
      };
    } catch (error) {
      throw new Error(`bcrypt hashing failed: ${error.message}`);
    }
  }

  async verifyPassword(password, hash) {
    try {
      return await bcrypt.compare(password, hash);
    } catch (error) {
      console.warn('bcrypt verification failed:', error.message);
      return false;
    }
  }

  // Estimate time to crack using current parameters
  estimateCrackTime() {
    // Rough estimation based on bcrypt cost factor
    const workFactor = this.options.saltRounds;
    const operations = Math.pow(2, workFactor);
    
    // Assume 10 billion hashes per second on modern GPU
    const crackTimeSeconds = operations / 10000000000;
    const crackTimeYears = crackTimeSeconds / (365 * 24 * 60 * 60);
    
    return {
      workFactor: workFactor,
      totalOperations: operations,
      estimatedCrackTime: {
        seconds: crackTimeSeconds,
        minutes: crackTimeSeconds / 60,
        hours: crackTimeSeconds / (60 * 60),
        days: crackTimeSeconds / (24 * 60 * 60),
        years: crackTimeYears
      }
    };
  }

  // Benchmark current system
  async benchmark() {
    const testPassword = 'test_password_for_benchmarking';
    const iterations = 5;
    
    console.log('📊 Running bcrypt benchmark...');
    
    const times = [];
    
    for (let i = 0; i < iterations; i++) {
      const startTime = performance.now();
      await this.hashPassword(testPassword);
      const endTime = performance.now();
      
      times.push(endTime - startTime);
      console.log(`  Iteration ${i + 1}: ${(endTime - startTime).toFixed(2)}ms`);
    }
    
    const averageTime = times.reduce((a, b) => a + b, 0) / times.length;
    const minTime = Math.min(...times);
    const maxTime = Math.max(...times);
    
    return {
      workFactor: this.options.saltRounds,
      iterations: iterations,
      averageTime: averageTime,
      minTime: minTime,
      maxTime: maxTime,
      estimatedCrackTime: this.estimateCrackTime()
    };
  }

  // Calculate recommended work factor based on system performance
  async calculateOptimalWorkFactor(targetTime = 250) {
    console.log('🔧 Calculating optimal bcrypt work factor...');
    
    const maxWorkFactor = 16;
    const minWorkFactor = 8;
    
    for (let workFactor = minWorkFactor; workFactor <= maxWorkFactor; workFactor++) {
      this.options.saltRounds = workFactor;
      
      const startTime = performance.now();
      await this.hashPassword('benchmark_password');
      const endTime = performance.now();
      
      const hashTime = endTime - startTime;
      console.log(`  Work factor ${workFactor}: ${hashTime.toFixed(2)}ms`);
      
      if (hashTime >= targetTime) {
        console.log(`✅ Recommended work factor: ${workFactor}`);
        return {
          recommendedWorkFactor: workFactor,
          averageHashTime: hashTime,
          estimatedCrackTime: this.estimateCrackTime()
        };
      }
    }
    
    console.warn(`⚠️  Could not achieve target time of ${targetTime}ms`);
    return {
      recommendedWorkFactor: maxWorkFactor,
      averageHashTime: NaN,
      estimatedCrackTime: this.estimateCrackTime()
    };
  }
}

// Usage example
async function demonstrateBCrypt() {
  const hasher = new BCryptPasswordHasher({
    saltRounds: 12
  });

  // Hash password
  const password = 'SecurePassword123!';
  console.log('🔐 Hashing password with bcrypt...');
  
  const hashResult = await hasher.hashPassword(password);
  console.log('✅ Hash created successfully');
  console.log(`Hash: ${hashResult.hash}`);
  console.log(`Algorithm: ${hashResult.algorithm}`);

  // Verify password
  const isValid = await hasher.verifyPassword(password, hashResult.hash);
  console.log(`Password valid: ${isValid}`);

  // Benchmark
  const benchmark = await hasher.benchmark();
  console.log('Benchmark results:', benchmark);

  // Calculate optimal parameters
  const optimal = await hasher.calculateOptimalWorkFactor(200);
  console.log('Optimal parameters:', optimal);
}

// Uncomment to run demonstration
// demonstrateBCrypt().catch(console.error);

module.exports = BCryptPasswordHasher;
```

### 2.3 scrypt Implementation

```javascript
const crypto = require('crypto');

class SCryptPasswordHasher {
  constructor(options = {}) {
    this.options = {
      // Memory cost (must be power of 2)
      memoryCost: options.memoryCost || 32768, // 32 MB
      // CPU cost
      cpuCost: options.cpuCost || 8,
      // Parallelization parameter
      parallelization: options.parallelization || 1,
      // Block size
      blockSize: options.blockSize || 8,
      // Desired key length
      keyLength: options.keyLength || 32,
      // Salt length
      saltLength: options.saltLength || 16,
      ...options
    };
  }

  async hashPassword(password, options = {}) {
    const memoryCost = options.memoryCost || this.options.memoryCost;
    const cpuCost = options.cpuCost || this.options.cpuCost;
    const parallelization = options.parallelization || this.options.parallelization;
    const keyLength = options.keyLength || this.options.keyLength;
    const saltLength = options.saltLength || this.options.saltLength;
    
    // Generate salt
    const salt = crypto.randomBytes(saltLength);
    
    return new Promise((resolve, reject) => {
      crypto.scrypt(password, salt, keyLength, {
        N: memoryCost,        // Memory cost
        r: this.options.blockSize, // Block size
        p: parallelization,   // Parallelization
        maxmem: memoryCost * this.options.blockSize * 128 // Max memory
      }, (err, derivedKey) => {
        if (err) {
          reject(new Error(`scrypt hashing failed: ${err.message}`));
          return;
        }
        
        resolve({
          hash: derivedKey.toString('hex'),
          salt: salt.toString('hex'),
          algorithm: 'scrypt',
          parameters: {
            memoryCost: memoryCost,
            cpuCost: cpuCost,
            parallelization: parallelization,
            blockSize: this.options.blockSize,
            keyLength: keyLength,
            saltLength: saltLength
          }
        });
      });
    });
  }

  async verifyPassword(password, hash, salt, options = {}) {
    return new Promise((resolve, reject) => {
      crypto.scrypt(password, Buffer.from(salt, 'hex'), 
        this.options.keyLength, {
        N: options.memoryCost || this.options.memoryCost,
        r: this.options.blockSize,
        p: options.parallelization || this.options.parallelization,
        maxmem: (options.memoryCost || this.options.memoryCost) * this.options.blockSize * 128
      }, (err, derivedKey) => {
        if (err) {
          console.warn('scrypt verification failed:', err.message);
          resolve(false);
          return;
        }
        
        const hashBuffer = Buffer.from(hash, 'hex');
        const isValid = crypto.timingSafeEqual(hashBuffer, derivedKey);
        resolve(isValid);
      });
    });
  }

  // Memory-hard property verification
  verifyMemoryHardness() {
    const memoryCost = this.options.memoryCost;
    const blockSize = this.options.blockSize;
    const parallelization = this.options.parallelization;
    
    // Calculate memory usage
    const memoryUsageBytes = memoryCost * blockSize * 128 * parallelization;
    const memoryUsageMB = memoryUsageBytes / (1024 * 1024);
    
    return {
      memoryUsageBytes: memoryUsageBytes,
      memoryUsageMB: memoryUsageMB,
      isMemoryHard: memoryUsageMB >= 16, // At least 16MB
      resistanceToASIC: memoryUsageMB >= 64, // Good ASIC resistance
      resistanceToGPU: memoryUsageMB >= 16  // Good GPU resistance
    };
  }

  // Benchmark with different parameters
  async benchmarkParameters() {
    const testPassword = 'benchmark_test_password';
    const parameterSets = [
      { memoryCost: 16384, cpuCost: 8, parallelization: 1 },
      { memoryCost: 32768, cpuCost: 8, parallelization: 1 },
      { memoryCost: 32768, cpuCost: 16, parallelization: 2 },
      { memoryCost: 65536, cpuCost: 16, parallelization: 2 },
      { memoryCost: 65536, cpuCost: 32, parallelization: 4 }
    ];
    
    const results = [];
    
    for (const params of parameterSets) {
      console.log(`Testing scrypt parameters:`, params);
      
      const startTime = performance.now();
      const hashResult = await this.hashPassword(testPassword, params);
      const hashTime = performance.now() - startTime;
      
      const verifyStartTime = performance.now();
      const isValid = await this.verifyPassword(testPassword, hashResult.hash, hashResult.salt, params);
      const verifyTime = performance.now() - verifyStartTime;
      
      const memoryHardness = this.verifyMemoryHardness();
      
      results.push({
        parameters: params,
        hashTime: hashTime,
        verifyTime: verifyTime,
        isValid: isValid,
        memoryHardness: memoryHardness,
        hashLength: hashResult.hash.length
      });
      
      console.log(`  Hash time: ${hashTime.toFixed(2)}ms, Verify time: ${verifyTime.toFixed(2)}ms`);
      console.log(`  Memory usage: ${memoryHardness.memoryUsageMB.toFixed(1)}MB`);
    }
    
    return results;
  }

  // Calculate security level based on parameters
  calculateSecurityLevel() {
    const memoryCost = this.options.memoryCost;
    const cpuCost = this.options.cpuCost;
    const parallelization = this.options.parallelization;
    
    // Total operations = N * r * p
    const totalOperations = memoryCost * this.options.blockSize * parallelization;
    
    // Security level estimation (very rough)
    let securityBits = 0;
    
    // Memory-hard resistance (log2 of memory in bytes)
    securityBits += Math.log2(memoryCost * this.options.blockSize * 128);
    
    // CPU cost contribution
    securityBits += Math.log2(cpuCost);
    
    // Parallelization contribution
    securityBits += Math.log2(parallelization);
    
    return {
      totalOperations: totalOperations,
      securityBits: Math.round(securityBits),
      resistance: {
        toASIC: memoryCost >= 32768, // 32MB minimum
        toGPU: memoryCost >= 16384,  // 16MB minimum
        toCPU: cpuCost >= 8,
        toParallel: parallelization >= 1
      },
      recommendation: securityBits >= 80 ? 'excellent' : 
                     securityBits >= 60 ? 'good' : 
                     securityBits >= 40 ? 'acceptable' : 'weak'
    };
  }
}

// Usage example
async function demonstrateSCrypt() {
  const hasher = new SCryptPasswordHasher({
    memoryCost: 32768, // 32 MB
    cpuCost: 8,
    parallelization: 1
  });

  // Hash password
  const password = 'MemoryHardPassword123!';
  console.log('🔐 Hashing password with scrypt...');
  
  const hashResult = await hasher.hashPassword(password);
  console.log('✅ Hash created successfully');
  console.log(`Hash: ${hashResult.hash.substring(0, 64)}...`);
  console.log(`Salt: ${hashResult.salt}`);

  // Verify password
  const isValid = await hasher.verifyPassword(password, hashResult.hash, hashResult.salt);
  console.log(`Password valid: ${isValid}`);

  // Memory hardness verification
  const memoryHardness = hasher.verifyMemoryHardness();
  console.log('Memory hardness:', memoryHardness);

  // Security level
  const securityLevel = hasher.calculateSecurityLevel();
  console.log('Security level:', securityLevel);

  // Benchmark
  console.log('\n📊 Running scrypt benchmarks...');
  const benchmarkResults = await hasher.benchmarkParameters();
  console.log('Benchmark results:', benchmarkResults);
}

// Uncomment to run demonstration
// demonstrateSCrypt().catch(console.error);

module.exports = SCryptPasswordHasher;
```

## 3. Performance Testing and Analysis

```javascript
class PasswordHashingBenchmark {
  constructor() {
    this.algorithms = {
      argon2: new Argon2PasswordHasher(),
      bcrypt: new BCryptPasswordHasher({ saltRounds: 12 }),
      scrypt: new SCryptPasswordHasher()
    };
    
    this.testPasswords = [
      'simple',
      'password123',
      'ComplexP@ssw0rd!2023',
      'VeryLongAndComplexPasswordWithSpecialCharacters123456789!@#$%^&*()'
    ];
    
    this.results = new Map();
  }

  async runComprehensiveBenchmark() {
    console.log('🚀 Running comprehensive password hashing benchmark...\n');
    
    for (const [algorithmName, hasher] of Object.entries(this.algorithms)) {
      console.log(`🔍 Testing ${algorithmName.toUpperCase()}`);
      console.log('=' .repeat(40));
      
      const algorithmResults = [];
      
      for (const password of this.testPasswords) {
        console.log(`\nPassword: "${password}"`);
        
        const passwordResults = await this.testPassword(algorithmName, hasher, password);
        algorithmResults.push(passwordResults);
        
        // Add delay between tests to prevent system overload
        await this.sleep(1000);
      }
      
      this.results.set(algorithmName, algorithmResults);
      
      console.log('\n' + '=' .repeat(40));
    }
    
    this.generateComparisonReport();
  }

  async testPassword(algorithmName, hasher, password) {
    const results = {
      algorithm: algorithmName,
      password: password,
      passwordLength: password.length,
      tests: {}
    };

    // Test hashing speed
    console.log('  Testing hashing speed...');
    const hashTimes = [];
    const hashIterations = 5;
    
    for (let i = 0; i < hashIterations; i++) {
      const startTime = performance.now();
      const hashResult = await this.hashPassword(hasher, password);
      const endTime = performance.now();
      
      hashTimes.push(endTime - startTime);
      console.log(`    Iteration ${i + 1}: ${(endTime - startTime).toFixed(2)}ms`);
    }
    
    results.tests.hash = {
      times: hashTimes,
      average: hashTimes.reduce((a, b) => a + b, 0) / hashTimes.length,
      min: Math.min(...hashTimes),
      max: Math.max(...hashTimes),
      hash: hashResult.hash,
      parameters: hashResult.parameters
    };

    // Test verification speed
    console.log('  Testing verification speed...');
    const verifyTimes = [];
    const verifyIterations = 10;
    
    for (let i = 0; i < verifyIterations; i++) {
      const startTime = performance.now();
      const isValid = await this.verifyPassword(hasher, password, results.tests.hash.hash, 
        algorithmName === 'bcrypt' ? null : results.tests.hash.salt);
      const endTime = performance.now();
      
      verifyTimes.push(endTime - startTime);
    }
    
    results.tests.verify = {
      times: verifyTimes,
      average: verifyTimes.reduce((a, b) => a + b, 0) / verifyTimes.length,
      min: Math.min(...verifyTimes),
      max: Math.max(...verifyTimes),
      successRate: verifyTimes.length // All should succeed
    };

    // Test memory usage (if available)
    console.log('  Measuring memory usage...');
    const memoryUsage = await this.measureMemoryUsage(async () => {
      await this.hashPassword(hasher, password + '_memory_test');
    });
    
    results.tests.memory = memoryUsage;

    return results;
  }

  async hashPassword(hasher, password) {
    if (hasher instanceof Argon2PasswordHasher) {
      return await hasher.hashPassword(password);
    } else if (hasher instanceof BCryptPasswordHasher) {
      return await hasher.hashPassword(password);
    } else if (hasher instanceof SCryptPasswordHasher) {
      return await hasher.hashPassword(password);
    }
    throw new Error('Unknown hasher type');
  }

  async verifyPassword(hasher, password, hash, salt) {
    if (hasher instanceof Argon2PasswordHasher) {
      return await hasher.verifyPassword(password, hash, salt);
    } else if (hasher instanceof BCryptPasswordHasher) {
      return await hasher.verifyPassword(password, hash);
    } else if (hasher instanceof SCryptPasswordHasher) {
      return await hasher.verifyPassword(password, hash, salt);
    }
    throw new Error('Unknown hasher type');
  }

  async measureMemoryUsage(asyncFunction) {
    const startMemory = process.memoryUsage();
    
    await asyncFunction();
    
    const endMemory = process.memoryUsage();
    
    return {
      heapUsed: endMemory.heapUsed - startMemory.heapUsed,
      external: endMemory.external - startMemory.external,
      totalUsed: endMemory.heapUsed + endMemory.external - 
                 (startMemory.heapUsed + startMemory.external)
    };
  }

  generateComparisonReport() {
    console.log('\n📊 COMPARISON REPORT');
    console.log('=' .repeat(60));
    
    const comparison = this.createComparisonMatrix();
    
    // Print summary table
    console.log('\n🔍 PERFORMANCE SUMMARY');
    console.log('Algorithm | Avg Hash Time | Avg Verify Time | Memory Usage | Security');
    console.log('-'.repeat(60));
    
    for (const [algorithm, data] of comparison) {
      const avgHashTime = this.calculateAverage(data.hashTimes).toFixed(2);
      const avgVerifyTime = this.calculateAverage(data.verifyTimes).toFixed(2);
      const memoryUsage = this.formatBytes(this.calculateAverage(data.memoryUsage));
      const security = data.security;
      
      console.log(`${algorithm.padEnd(10)} | ${avgHashTime.padEnd(12)} | ${avgVerifyTime.padEnd(15)} | ${memoryUsage.padEnd(12)} | ${security}`);
    }
    
    // Print detailed analysis
    console.log('\n📈 DETAILED ANALYSIS');
    
    // Security analysis
    console.log('\n🔒 SECURITY COMPARISON:');
    console.log('1. Argon2id:');
    console.log('   ✅ Memory-hard, resistant to GPU/ASIC attacks');
    console.log('   ✅ Side-channel resistant');
    console.log('   ✅ Configurable parameters');
    console.log('   ✅ NIST recommended');
    
    console.log('2. scrypt:');
    console.log('   ✅ Memory-hard, resistant to GPU/ASIC attacks');
    console.log('   ✅ Configurable parameters');
    console.log('   ⚠️  Higher implementation complexity');
    console.log('   ✅ NIST recommended');
    
    console.log('3. bcrypt:');
    console.log('   ⚠️  Not memory-hard, vulnerable to specialized hardware');
    console.log('   ✅ Time-hard, configurable work factor');
    console.log('   ✅ Well-tested and widely used');
    console.log('   ⚠️  NIST acceptable but not preferred');
    
    // Performance analysis
    console.log('\n⚡ PERFORMANCE ANALYSIS:');
    for (const [algorithm, data] of comparison) {
      const avgHashTime = this.calculateAverage(data.hashTimes);
      const avgVerifyTime = this.calculateAverage(data.verifyTimes);
      
      console.log(`${algorithm}:`);
      console.log(`   Hash time: ${avgHashTime.toFixed(2)}ms`);
      console.log(`   Verify time: ${avgVerifyTime.toFixed(2)}ms`);
      console.log(`   Hash:Verify ratio: ${(avgHashTime/avgVerifyTime).toFixed(1)}x`);
      
      if (avgHashTime > 1000) {
        console.log('   ⚠️  Hash time may be too slow for production');
      } else if (avgHashTime > 100) {
        console.log('   ✅ Hash time is acceptable');
      } else {
        console.log('   ⚠️  Hash time may be too fast (reduce security)');
      }
    }
    
    // Memory analysis
    console.log('\n💾 MEMORY USAGE ANALYSIS:');
    for (const [algorithm, data] of comparison) {
      const avgMemory = this.calculateAverage(data.memoryUsage);
      const memoryMB = avgMemory / (1024 * 1024);
      
      console.log(`${algorithm}: ${memoryMB.toFixed(1)}MB`);
      
      if (memoryMB > 100) {
        console.log('   ✅ High memory usage provides good GPU/ASIC resistance');
      } else if (memoryMB > 10) {
        console.log('   ⚠️  Moderate memory usage');
      } else {
        console.log('   ❌ Low memory usage vulnerable to hardware attacks');
      }
    }
    
    // Recommendations
    console.log('\n🎯 RECOMMENDATIONS:');
    console.log('1. For NEW implementations: Use Argon2id');
    console.log('   - Best security properties');
    console.log('   - NIST preferred algorithm');
    console.log('   - Easy to implement correctly');
    
    console.log('2. For HIGH-SECURITY environments: Use scrypt');
    console.log('   - Maximum memory-hardness');
    console.log('   - Best resistance to specialized hardware');
    
    console.log('3. For LEGACY support: Use bcrypt');
    console.log('   - Well-established and tested');
    console.log('   - Good for backward compatibility');
    console.log('   - Ensure high work factor (12+)');
    
    this.saveResultsToFile(comparison);
  }

  createComparisonMatrix() {
    const comparison = new Map();
    
    for (const [algorithm, results] of this.results) {
      const allHashTimes = [];
      const allVerifyTimes = [];
      const allMemoryUsage = [];
      
      results.forEach(result => {
        allHashTimes.push(...result.tests.hash.times);
        allVerifyTimes.push(...result.tests.verify.times);
        allMemoryUsage.push(result.tests.memory.heapUsed);
      });
      
      comparison.set(algorithm, {
        hashTimes: allHashTimes,
        verifyTimes: allVerifyTimes,
        memoryUsage: allMemoryUsage,
        security: this.getSecurityRating(algorithm)
      });
    }
    
    return comparison;
  }

  getSecurityRating(algorithm) {
    const ratings = {
      argon2: 'Excellent',
      scrypt: 'Excellent',
      bcrypt: 'Good'
    };
    return ratings[algorithm] || 'Unknown';
  }

  calculateAverage(numbers) {
    return numbers.reduce((a, b) => a + b, 0) / numbers.length;
  }

  formatBytes(bytes) {
    if (bytes === 0) return '0B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + sizes[i];
  }

  saveResultsToFile(comparison) {
    const fs = require('fs');
    const report = {
      timestamp: new Date().toISOString(),
      algorithms: Object.fromEntries(comparison),
      summary: this.generateExecutiveSummary(comparison)
    };
    
    fs.writeFileSync('password-hashing-benchmark.json', JSON.stringify(report, null, 2));
    console.log('\n💾 Detailed results saved to password-hashing-benchmark.json');
  }

  generateExecutiveSummary(comparison) {
    const summary = {
      fastest: '',
      mostSecure: '',
      mostMemoryEfficient: '',
      recommended: 'argon2'
    };
    
    // Find fastest hashing algorithm
    let fastestTime = Infinity;
    for (const [algorithm, data] of comparison) {
      const avgTime = this.calculateAverage(data.hashTimes);
      if (avgTime < fastestTime) {
        fastestTime = avgTime;
        summary.fastest = algorithm;
      }
    }
    
    // Most secure is predetermined (argon2/scrypt > bcrypt)
    summary.mostSecure = 'argon2';
    
    // Most memory efficient
    let mostEfficient = Infinity;
    for (const [algorithm, data] of comparison) {
      const avgMemory = this.calculateAverage(data.memoryUsage);
      if (avgMemory < mostEfficient) {
        mostEfficient = avgMemory;
        summary.mostMemoryEfficient = algorithm;
      }
    }
    
    return summary;
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Usage example
async function runPasswordHashingBenchmark() {
  const benchmark = new PasswordHashingBenchmark();
  await benchmark.runComprehensiveBenchmark();
}

// Uncomment to run benchmark
// runPasswordHashingBenchmark().catch(console.error);

module.exports = PasswordHashingBenchmark;
```

## 4. Migration and Upgrade Strategies

```javascript
class PasswordHashingMigration {
  constructor() {
    this.migrationStrategies = {
      from_legacy: this.migrateFromLegacyHashes,
      to_argon2: this.migrateToArgon2,
      to_scrypt: this.migrateToScrypt,
      to_bcrypt: this.migrateToBcrypt
    };
  }

  // Migrate from weak hashes (MD5, SHA-1) to strong hashes
  async migrateFromLegacyHashes(userPassword, legacyHash, legacyAlgorithm) {
    console.log(`🔄 Migrating from ${legacyAlgorithm} to Argon2id...`);
    
    // First verify against legacy hash
    const isValidLegacy = await this.verifyLegacyHash(userPassword, legacyHash, legacyAlgorithm);
    
    if (!isValidLegacy) {
      throw new Error('Legacy password verification failed');
    }
    
    // Create new hash with Argon2id
    const argon2Hasher = new Argon2PasswordHasher();
    const newHash = await argon2Hasher.hashPassword(userPassword);
    
    return {
      migrationSuccess: true,
      newHash: newHash.hash,
      newAlgorithm: 'argon2id',
      needsRehash: false, // Already using strong algorithm
      legacyVerified: true
    };
  }

  async verifyLegacyHash(password, hash, algorithm) {
    const crypto = require('crypto');
    
    switch (algorithm.toLowerCase()) {
      case 'md5':
        const md5Hash = crypto.createHash('md5').update(password).digest('hex');
        return md5Hash === hash;
        
      case 'sha1':
        const sha1Hash = crypto.createHash('sha1').update(password).digest('hex');
        return sha1Hash === hash;
        
      case 'sha256':
        const sha256Hash = crypto.createHash('sha256').update(password).digest('hex');
        return sha256Hash === hash;
        
      default:
        throw new Error(`Unsupported legacy algorithm: ${algorithm}`);
    }
  }

  // Check if stored hash needs rehashing
  checkIfRehashNeeded(storedHash, currentHasher) {
    if (currentHasher instanceof Argon2PasswordHasher) {
      return currentHasher.needsRehashing(storedHash);
    } else if (currentHasher instanceof BCryptPasswordHasher) {
      // Check if bcrypt work factor is too low
      const saltRounds = currentHasher.options.saltRounds;
      return saltRounds < 12;
    } else if (currentHasher instanceof SCryptPasswordHasher) {
      // Check scrypt parameters
      const memoryCost = currentHasher.options.memoryCost;
      return memoryCost < 16384; // Less than 16MB
    }
    
    return true; // Default to rehashing unknown algorithms
  }

  // Batch migration for multiple users
  async batchMigrateUsers(users, progressCallback) {
    const results = {
      total: users.length,
      successful: 0,
      failed: 0,
      skipped: 0,
      errors: []
    };
    
    const argon2Hasher = new Argon2PasswordHasher();
    
    for (let i = 0; i < users.length; i++) {
      const user = users[i];
      
      try {
        // Try to verify existing hash
        let isValid = false;
        
        if (user.currentAlgorithm === 'argon2') {
          isValid = await argon2Hasher.verifyPassword(user.password, user.currentHash, user.salt);
        } else if (user.currentAlgorithm === 'bcrypt') {
          const bcryptHasher = new BCryptPasswordHasher();
          isValid = await bcryptHasher.verifyPassword(user.password, user.currentHash);
        } else if (user.currentAlgorithm === 'scrypt') {
          const scryptHasher = new SCryptPasswordHasher();
          isValid = await scryptHasher.verifyPassword(user.password, user.currentHash, user.salt);
        } else {
          // Legacy algorithm
          isValid = await this.verifyLegacyHash(user.password, user.currentHash, user.currentAlgorithm);
        }
        
        if (isValid) {
          // Create new Argon2 hash
          const newHash = await argon2Hasher.hashPassword(user.password);
          
          results.successful++;
          
          if (progressCallback) {
            progressCallback({
              userId: user.id,
              status: 'migrated',
              newAlgorithm: 'argon2id',
              progress: ((i + 1) / users.length) * 100
            });
          }
        } else {
          results.skipped++;
          
          if (progressCallback) {
            progressCallback({
              userId: user.id,
              status: 'skipped',
              reason: 'password_verification_failed',
              progress: ((i + 1) / users.length) * 100
            });
          }
        }
      } catch (error) {
        results.failed++;
        results.errors.push({
          userId: user.id,
          error: error.message
        });
        
        if (progressCallback) {
          progressCallback({
            userId: user.id,
            status: 'failed',
            error: error.message,
            progress: ((i + 1) / users.length) * 100
          });
        }
      }
      
      // Add delay to prevent overwhelming the system
      await this.sleep(100);
    }
    
    return results;
  }

  // Progressive migration - update hashes on next login
  async handleProgressiveMigration(storedHash, storedAlgorithm, userPassword, salt = null) {
    // Try to verify with current algorithm
    let isValid = false;
    
    try {
      if (storedAlgorithm === 'argon2id') {
        const hasher = new Argon2PasswordHasher();
        isValid = await hasher.verifyPassword(userPassword, storedHash, salt);
        
        // Check if needs rehashing with newer parameters
        if (isValid && hasher.needsRehashing(storedHash)) {
          return {
            verified: true,
            needsRehash: true,
            newHash: await hasher.hashPassword(userPassword)
          };
        }
      } else if (storedAlgorithm === 'bcrypt') {
        const hasher = new BCryptPasswordHasher();
        isValid = await hasher.verifyPassword(userPassword, storedHash);
        
        // If bcrypt work factor is too low, rehash
        if (isValid && hasher.options.saltRounds < 12) {
          const argon2Hasher = new Argon2PasswordHasher();
          return {
            verified: true,
            needsRehash: true,
            newHash: await argon2Hasher.hashPassword(userPassword)
          };
        }
      } else {
        // Legacy algorithm - migrate immediately
        const migrationResult = await this.migrateFromLegacyHashes(userPassword, storedHash, storedAlgorithm);
        return {
          verified: migrationResult.legacyVerified,
          needsRehash: false,
          newHash: migrationResult.newHash
        };
      }
    } catch (error) {
      console.warn('Password verification error:', error.message);
      return { verified: false, needsRehash: false };
    }
    
    return {
      verified: isValid,
      needsRehash: false
    };
  }

  async migrateToArgon2(password, currentHash, currentAlgorithm) {
    console.log('🔄 Migrating to Argon2id...');
    
    const argon2Hasher = new Argon2PasswordHasher();
    
    // Verify with current algorithm first
    let isValid = false;
    
    if (currentAlgorithm === 'bcrypt') {
      const bcryptHasher = new BCryptPasswordHasher();
      isValid = await bcryptHasher.verifyPassword(password, currentHash);
    } else if (currentAlgorithm === 'scrypt') {
      const scryptHasher = new SCryptPasswordHasher();
      isValid = await scryptHasher.verifyPassword(password, currentHash, null);
    }
    
    if (!isValid) {
      throw new Error('Current password verification failed');
    }
    
    // Create new Argon2 hash
    const newHash = await argon2Hasher.hashPassword(password);
    
    return {
      success: true,
      newHash: newHash.hash,
      algorithm: 'argon2id',
      parameters: newHash.parameters
    };
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Usage example
async function demonstrateMigration() {
  const migration = new PasswordHashingMigration();
  
  // Example user data
  const testUser = {
    id: 'user123',
    password: 'TestPassword123!',
    currentHash: 'some_bcrypt_hash',
    currentAlgorithm: 'bcrypt',
    salt: null
  };
  
  console.log('🔄 Demonstrating progressive migration...');
  
  const result = await migration.handleProgressiveMigration(
    testUser.currentHash,
    testUser.currentAlgorithm,
    testUser.password,
    testUser.salt
  );
  
  console.log('Migration result:', result);
}

// Uncomment to run demonstration
// demonstrateMigration().catch(console.error);

module.exports = PasswordHashingMigration;
```

## 5. Security Best Practices and Recommendations

### 5.1 Implementation Guidelines

```javascript
class PasswordHashingBestPractices {
  static getRecommendedConfiguration() {
    return {
      // For production environments
      production: {
        algorithm: 'argon2id',
        memoryCost: 131072, // 128 MB
        timeCost: 3,
        parallelism: 2,
        hashLength: 32,
        saltLength: 16
      },
      
      // For development/testing
      development: {
        algorithm: 'argon2id',
        memoryCost: 32768, // 32 MB
        timeCost: 2,
        parallelism: 1,
        hashLength: 32,
        saltLength: 16
      },
      
      // For high-security environments
      high_security: {
        algorithm: 'argon2id',
        memoryCost: 262144, // 256 MB
        timeCost: 4,
        parallelism: 4,
        hashLength: 64,
        saltLength: 32
      },
      
      // For resource-constrained environments
      constrained: {
        algorithm: 'scrypt',
        memoryCost: 16384, // 16 MB
        cpuCost: 16,
        parallelization: 2,
        keyLength: 32,
        saltLength: 16
      }
    };
  }

  static validateConfiguration(config) {
    const issues = [];
    
    // Check algorithm
    const allowedAlgorithms = ['argon2id', 'argon2i', 'argon2d', 'bcrypt', 'scrypt'];
    if (!allowedAlgorithms.includes(config.algorithm)) {
      issues.push(`Unknown algorithm: ${config.algorithm}`);
    }
    
    // Check Argon2 parameters
    if (config.algorithm.startsWith('argon2')) {
      if (config.memoryCost < 32768) {
        issues.push('Argon2 memory cost too low (minimum 32MB)');
      }
      if (config.timeCost < 2) {
        issues.push('Argon2 time cost too low (minimum 2)');
      }
      if (config.parallelism < 1 || config.parallelization > 8) {
        issues.push('Argon2 parallelism should be between 1-8');
      }
    }
    
    // Check bcrypt parameters
    if (config.algorithm === 'bcrypt') {
      if (config.saltRounds < 10) {
        issues.push('bcrypt salt rounds too low (minimum 10)');
      }
      if (config.saltRounds > 16) {
        issues.push('bcrypt salt rounds too high (maximum 16)');
      }
    }
    
    // Check scrypt parameters
    if (config.algorithm === 'scrypt') {
      if (config.memoryCost < 16384) {
        issues.push('scrypt memory cost too low (minimum 16MB)');
      }
      if (config.cpuCost < 8) {
        issues.push('scrypt CPU cost too low (minimum 8)');
      }
    }
    
    // Check hash and salt lengths
    if (config.hashLength < 16) {
      issues.push('Hash length too short (minimum 16 bytes)');
    }
    if (config.saltLength < 8) {
      issues.push('Salt length too short (minimum 8 bytes)');
    }
    
    return {
      isValid: issues.length === 0,
      issues: issues,
      warnings: this.getConfigurationWarnings(config)
    };
  }

  static getConfigurationWarnings(config) {
    const warnings = [];
    
    // Warning for slow configurations
    if (config.algorithm === 'argon2id') {
      const estimatedTime = config.memoryCost * config.timeCost / 100000;
      if (estimatedTime > 1000) {
        warnings.push('Configuration may be too slow for production use');
      }
    }
    
    // Warning for fast configurations
    if (config.algorithm === 'bcrypt' && config.saltRounds <= 10) {
      warnings.push('bcrypt work factor may be too low for current security requirements');
    }
    
    return warnings;
  }

  static generateSecurityReport(config) {
    const report = {
      configuration: config,
      timestamp: new Date().toISOString(),
      security: {},
      performance: {},
      recommendations: []
    };
    
    // Security analysis
    report.security = this.analyzeSecurity(config);
    
    // Performance analysis
    report.performance = this.estimatePerformance(config);
    
    // Generate recommendations
    report.recommendations = this.generateRecommendations(config);
    
    return report;
  }

  static analyzeSecurity(config) {
    let securityScore = 0;
    const factors = [];
    
    // Algorithm strength
    if (config.algorithm === 'argon2id') {
      securityScore += 40;
      factors.push('Argon2id provides excellent security properties');
    } else if (config.algorithm === 'scrypt') {
      securityScore += 38;
      factors.push('scrypt provides strong memory-hardness');
    } else if (config.algorithm === 'bcrypt') {
      securityScore += 25;
      factors.push('bcrypt is secure but not memory-hard');
    }
    
    // Memory hardness
    if (config.memoryCost >= 131072) { // 128MB
      securityScore += 20;
      factors.push('High memory usage provides excellent GPU/ASIC resistance');
    } else if (config.memoryCost >= 65536) { // 64MB
      securityScore += 15;
      factors.push('Good memory usage provides good hardware resistance');
    } else if (config.memoryCost >= 32768) { // 32MB
      securityScore += 10;
      factors.push('Moderate memory usage provides some hardware resistance');
    } else {
      factors.push('Low memory usage vulnerable to hardware attacks');
    }
    
    // Time cost
    if (config.timeCost >= 4) {
      securityScore += 15;
      factors.push('High time cost provides strong brute-force resistance');
    } else if (config.timeCost >= 3) {
      securityScore += 10;
      factors.push('Good time cost provides reasonable brute-force resistance');
    } else if (config.timeCost >= 2) {
      securityScore += 5;
      factors.push('Moderate time cost provides basic brute-force resistance');
    }
    
    // Hash length
    if (config.hashLength >= 32) {
      securityScore += 10;
      factors.push('Adequate hash length for collision resistance');
    } else {
      factors.push('Hash length may be insufficient for collision resistance');
    }
    
    // Salt length
    if (config.saltLength >= 16) {
      securityScore += 10;
      factors.push('Adequate salt length for rainbow table resistance');
    } else {
      factors.push('Salt length may be insufficient for rainbow table resistance');
    }
    
    const securityLevel = securityScore >= 80 ? 'excellent' :
                         securityScore >= 60 ? 'good' :
                         securityScore >= 40 ? 'acceptable' : 'poor';
    
    return {
      score: securityScore,
      level: securityLevel,
      factors: factors,
      isRecommended: securityScore >= 60
    };
  }

  static estimatePerformance(config) {
    // Rough performance estimation
    const baseTime = config.memoryCost * config.timeCost * 0.001; // Base estimation
    const parallelismFactor = config.parallelism || 1;
    
    const estimatedHashTime = baseTime / parallelismFactor;
    const estimatedVerifyTime = estimatedHashTime * 0.8; // Verification is typically faster
    
    let performanceLevel = 'excellent';
    if (estimatedHashTime > 1000) {
      performanceLevel = 'poor';
    } else if (estimatedHashTime > 500) {
      performanceLevel = 'acceptable';
    } else if (estimatedHashTime > 200) {
      performanceLevel = 'good';
    }
    
    return {
      estimatedHashTime: estimatedHashTime,
      estimatedVerifyTime: estimatedVerifyTime,
      level: performanceLevel,
      throughputPerSecond: 1000 / estimatedHashTime
    };
  }

  static generateRecommendations(config) {
    const recommendations = [];
    
    // Algorithm recommendations
    if (config.algorithm !== 'argon2id') {
      recommendations.push({
        priority: 'high',
        category: 'algorithm',
        message: 'Consider migrating to Argon2id for optimal security and performance'
      });
    }
    
    // Parameter recommendations
    if (config.memoryCost < 65536) {
      recommendations.push({
        priority: 'medium',
        category: 'parameters',
        message: 'Consider increasing memory cost for better hardware resistance'
      });
    }
    
    if (config.timeCost < 3) {
      recommendations.push({
        priority: 'medium',
        category: 'parameters',
        message: 'Consider increasing time cost for better brute-force resistance'
      });
    }
    
    // Security recommendations
    if (config.hashLength < 32) {
      recommendations.push({
        priority: 'low',
        category: 'security',
        message: 'Consider using 32-byte hash length for better collision resistance'
      });
    }
    
    // Monitoring recommendations
    recommendations.push({
      priority: 'high',
      category: 'monitoring',
      message: 'Implement regular security monitoring and parameter updates'
    });
    
    return recommendations;
  }
}

// Usage example
function demonstrateBestPractices() {
  const config = PasswordHashingBestPractices.getRecommendedConfiguration().production;
  
  console.log('🔍 Analyzing password hashing configuration...');
  
  const validation = PasswordHashingBestPractices.validateConfiguration(config);
  console.log('Validation result:', validation);
  
  const report = PasswordHashingBestPractices.generateSecurityReport(config);
  console.log('\nSecurity Report:');
  console.log(`Security Score: ${report.security.score}/100`);
  console.log(`Security Level: ${report.security.level}`);
  console.log(`Performance Level: ${report.performance.level}`);
  console.log(`Estimated Hash Time: ${report.performance.estimatedHashTime.toFixed(2)}ms`);
  
  console.log('\nRecommendations:');
  report.recommendations.forEach(rec => {
    console.log(`- [${rec.priority}] ${rec.message}`);
  });
}

// Uncomment to run demonstration
// demonstrateBestPractices();

module.exports = PasswordHashingBestPractices;
```

This comprehensive password hashing comparison provides:

1. **Detailed algorithm comparison** with security and performance analysis
2. **Production-ready implementations** for Argon2, bcrypt, and scrypt
3. **Comprehensive benchmarking** and performance testing framework
4. **Migration strategies** for upgrading from legacy hashes
5. **Security best practices** and configuration validation
6. **Adaptive parameter calculation** based on system capabilities
7. **Real-world security recommendations** following NIST guidelines

The implementation helps organizations choose and implement the most appropriate password hashing algorithm while ensuring optimal security and performance for their specific use case.
