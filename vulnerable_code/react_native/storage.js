import { AsyncStorage } from 'react-native';

// CWE-94: Improper Control of Generation of Code ('Code Injection')
// VULNERABLE: eval() on unsanitized user-supplied string
// An attacker can inject arbitrary JS: e.g. {"__proto__": ...} or function calls

export const processUserData = (userDataStr) => {
  const parsedData = eval("(" + userDataStr + ")");
  return parsedData;
};
