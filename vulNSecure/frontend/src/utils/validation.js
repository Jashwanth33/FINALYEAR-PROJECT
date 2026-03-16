// Email validation
export const isValidEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

// Password validation
export const validatePassword = (password) => {
  const errors = [];
  
  if (password.length < 8) {
    errors.push('Password must be at least 8 characters long');
  }
  
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  
  if (!/\d/.test(password)) {
    errors.push('Password must contain at least one number');
  }
  
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
};

// Username validation
export const isValidUsername = (username) => {
  const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
  return usernameRegex.test(username);
};

// URL validation
export const isValidUrl = (url) => {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
};

// IP address validation
export const isValidIP = (ip) => {
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  return ipv4Regex.test(ip) || ipv6Regex.test(ip);
};

// Phone number validation
export const isValidPhone = (phone) => {
  const phoneRegex = /^\+?[\d\s\-\(\)]{10,}$/;
  return phoneRegex.test(phone);
};

// Date validation
export const isValidDate = (date) => {
  const parsedDate = new Date(date);
  return !isNaN(parsedDate.getTime());
};

// File validation
export const validateFile = (file, options = {}) => {
  const {
    maxSize = 10 * 1024 * 1024, // 10MB default
    allowedTypes = [],
    allowedExtensions = []
  } = options;

  const errors = [];

  if (file.size > maxSize) {
    errors.push(`File size must be less than ${maxSize / (1024 * 1024)}MB`);
  }

  if (allowedTypes.length > 0 && !allowedTypes.includes(file.type)) {
    errors.push(`File type must be one of: ${allowedTypes.join(', ')}`);
  }

  if (allowedExtensions.length > 0) {
    const extension = file.name.split('.').pop().toLowerCase();
    if (!allowedExtensions.includes(extension)) {
      errors.push(`File extension must be one of: ${allowedExtensions.join(', ')}`);
    }
  }

  return {
    isValid: errors.length === 0,
    errors
  };
};

// Form validation utilities
export class FormValidator {
  constructor(rules = {}) {
    this.rules = rules;
  }

  validate(data) {
    const errors = {};
    let isValid = true;

    for (const [field, fieldRules] of Object.entries(this.rules)) {
      const value = data[field];
      const fieldErrors = [];

      for (const rule of fieldRules) {
        const result = rule.validator(value, data);
        if (!result) {
          fieldErrors.push(rule.message);
          isValid = false;
        }
      }

      if (fieldErrors.length > 0) {
        errors[field] = fieldErrors;
      }
    }

    return { isValid, errors };
  }

  addRule(field, validator, message) {
    if (!this.rules[field]) {
      this.rules[field] = [];
    }
    this.rules[field].push({ validator, message });
  }
}

// Common validation rules
export const validationRules = {
  required: (value) => value !== null && value !== undefined && value !== '',
  email: (value) => !value || isValidEmail(value),
  minLength: (min) => (value) => !value || value.length >= min,
  maxLength: (max) => (value) => !value || value.length <= max,
  pattern: (regex) => (value) => !value || regex.test(value),
  numeric: (value) => !value || !isNaN(Number(value)),
  positive: (value) => !value || Number(value) > 0,
  integer: (value) => !value || Number.isInteger(Number(value)),
  url: (value) => !value || isValidUrl(value),
  phone: (value) => !value || isValidPhone(value),
  date: (value) => !value || isValidDate(value),
  match: (fieldName) => (value, data) => !value || value === data[fieldName]
};

// Data sanitization utilities
export const sanitize = {
  string: (str) => {
    if (typeof str !== 'string') return '';
    return str.trim().replace(/[<>]/g, '');
  },
  
  email: (email) => {
    if (typeof email !== 'string') return '';
    return email.toLowerCase().trim();
  },
  
  number: (num) => {
    const parsed = parseFloat(num);
    return isNaN(parsed) ? 0 : parsed;
  },
  
  integer: (num) => {
    const parsed = parseInt(num, 10);
    return isNaN(parsed) ? 0 : parsed;
  },
  
  boolean: (bool) => {
    if (typeof bool === 'boolean') return bool;
    if (typeof bool === 'string') {
      return bool.toLowerCase() === 'true';
    }
    return Boolean(bool);
  },
  
  url: (url) => {
    if (typeof url !== 'string') return '';
    url = url.trim();
    if (url && !url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://' + url;
    }
    return url;
  },
  
  html: (html) => {
    if (typeof html !== 'string') return '';
    return html
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');
  }
};

// XSS prevention
export const escapeHtml = (unsafe) => {
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
};

// SQL injection prevention (for display purposes)
export const escapeSql = (str) => {
  if (typeof str !== 'string') return str;
  return str.replace(/'/g, "''").replace(/;/g, '');
};

// Input validation for security
export const isSecureInput = (input) => {
  const dangerousPatterns = [
    /<script/i,
    /javascript:/i,
    /on\w+\s*=/i,
    /eval\s*\(/i,
    /expression\s*\(/i,
    /vbscript:/i,
    /data:text\/html/i
  ];
  
  return !dangerousPatterns.some(pattern => pattern.test(input));
};

// Rate limiting validation
export class RateLimiter {
  constructor(maxRequests = 100, windowMs = 60000) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
    this.requests = new Map();
  }

  isAllowed(identifier) {
    const now = Date.now();
    const windowStart = now - this.windowMs;
    
    if (!this.requests.has(identifier)) {
      this.requests.set(identifier, []);
    }
    
    const userRequests = this.requests.get(identifier);
    
    // Remove old requests outside the window
    const validRequests = userRequests.filter(time => time > windowStart);
    this.requests.set(identifier, validRequests);
    
    if (validRequests.length >= this.maxRequests) {
      return false;
    }
    
    validRequests.push(now);
    return true;
  }

  getRemainingRequests(identifier) {
    const now = Date.now();
    const windowStart = now - this.windowMs;
    
    if (!this.requests.has(identifier)) {
      return this.maxRequests;
    }
    
    const userRequests = this.requests.get(identifier);
    const validRequests = userRequests.filter(time => time > windowStart);
    
    return Math.max(0, this.maxRequests - validRequests.length);
  }
}

// Custom validation hook for React
export const useFormValidation = (initialState, validationRules) => {
  const [values, setValues] = React.useState(initialState);
  const [errors, setErrors] = React.useState({});
  const [isValid, setIsValid] = React.useState(false);

  const validator = React.useMemo(() => new FormValidator(validationRules), [validationRules]);

  React.useEffect(() => {
    const result = validator.validate(values);
    setErrors(result.errors);
    setIsValid(result.isValid);
  }, [values, validator]);

  const setValue = (field, value) => {
    setValues(prev => ({ ...prev, [field]: value }));
  };

  const setAllValues = (newValues) => {
    setValues(newValues);
  };

  const reset = () => {
    setValues(initialState);
    setErrors({});
    setIsValid(false);
  };

  return {
    values,
    errors,
    isValid,
    setValue,
    setAllValues,
    reset
  };
};