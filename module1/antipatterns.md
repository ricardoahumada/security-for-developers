# Common Mistakes and Anti-Patterns

## Anti-Pattern 1: Confusing the Two Concepts
```javascript
// BAD: Mixing authentication and authorization logic
function login(userId, password) {
    if (verifyPassword(userId, password)) {
        // BAD: Storing permissions in authentication
        return {
            authenticated: true,
            permissions: ['read', 'write', 'admin']  // This should be separate
        };
    }
}

// GOOD: Separate concerns
function authenticate(username, password) {
    // Authentication logic only
    return verifyIdentity(username, password);
}

function authorize(userId, resource, action) {
    // Authorization logic only
    return checkPermissions(userId, resource, action);
}
```

## Anti-Pattern 2: Role Confusion
```javascript
// BAD: Roles implying authentication
const roles = {
    'authenticated_user': true,  // This should be authentication state
    'admin': ['read', 'write', 'delete']
};

// GOOD: Clear separation
const authState = {
    isAuthenticated: true,
    userId: '123'
};

const permissions = {
    'admin': ['read', 'write', 'delete'],
    'user': ['read']
};
```

## Anti-Pattern 3: Session vs Permission Mixing
```javascript
// BAD: Using session status as permission check
if (user.sessionExists()) {
    allowAccess(sensitiveResource);  // Wrong: Session doesn't imply permission
}

// GOOD: Check both authentication and authorization
if (user.isAuthenticated() && user.hasPermission('sensitive_resource', 'read')) {
    allowAccess(sensitiveResource);
}
```