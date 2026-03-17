const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// VULNERABILITY 1: Hardcoded, easily guessable JWT secret key.
// Secrets should never be hardcoded directly into the source code.
const SECRET_KEY = "super_secret_key_123";

function registerUser(username, password) {
    // VULNERABILITY 2: Using MD5 for password hashing is highly insecure!
    // MD5 is obsolete and easily cracked using rainbow tables or brute force.
    const hashedPassword = crypto.createHash('md5').update(password).digest('hex');
    
    // In a real app, we would save this object to a database
    const user = {
        username: username,
        password: hashedPassword
    };
    
    return user;
}

function loginUser(user, passwordAttempt) {
    // Hashing the login attempt with the same weak MD5 algorithm
    const hashedAttempt = crypto.createHash('md5').update(passwordAttempt).digest('hex');
    
    // VULNERABILITY 3: Vulnerable to timing attacks. 
    // Standard `===` operator fails fast, allowing attackers to guess hashes character by character.
    if (user.password === hashedAttempt) {
        
        // Generating a token with the hardcoded secret
        const token = jwt.sign({ username: user.username }, SECRET_KEY);
        return { success: true, token: token };
    }
    
    return { success: false, message: "Invalid credentials" };
}

module.exports = { registerUser, loginUser };