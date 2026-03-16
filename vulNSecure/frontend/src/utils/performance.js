// Debounce function to limit the rate of function calls
export const debounce = (func, delay) => {
  let timeoutId;
  return (...args) => {
    clearTimeout(timeoutId);
    timeoutId = setTimeout(() => func.apply(null, args), delay);
  };
};

// Throttle function to limit function calls to once per specified interval
export const throttle = (func, limit) => {
  let inThrottle;
  return (...args) => {
    if (!inThrottle) {
      func.apply(null, args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
};

// Memoization function for expensive calculations
export const memoize = (fn) => {
  const cache = new Map();
  return (...args) => {
    const key = JSON.stringify(args);
    if (cache.has(key)) {
      return cache.get(key);
    }
    const result = fn(...args);
    cache.set(key, result);
    return result;
  };
};

// Performance monitoring utilities
export class PerformanceMonitor {
  static measurements = new Map();

  static start(label) {
    this.measurements.set(label, performance.now());
  }

  static end(label) {
    const startTime = this.measurements.get(label);
    if (startTime) {
      const duration = performance.now() - startTime;
      console.log(`${label}: ${duration.toFixed(2)}ms`);
      this.measurements.delete(label);
      return duration;
    }
    return null;
  }

  static measure(label, fn) {
    this.start(label);
    const result = fn();
    this.end(label);
    return result;
  }

  static async measureAsync(label, asyncFn) {
    this.start(label);
    const result = await asyncFn();
    this.end(label);
    return result;
  }
}

// Lazy loading utility for components
export const lazyWithRetry = (componentImport, retries = 3) => {
  return React.lazy(async () => {
    let attempt = 0;
    while (attempt < retries) {
      try {
        return await componentImport();
      } catch (error) {
        attempt++;
        if (attempt >= retries) {
          throw error;
        }
        // Wait before retrying
        await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
      }
    }
  });
};

// Virtual scrolling utility for large lists
export class VirtualScrollManager {
  constructor(itemHeight, containerHeight, buffer = 5) {
    this.itemHeight = itemHeight;
    this.containerHeight = containerHeight;
    this.buffer = buffer;
  }

  getVisibleRange(scrollTop, totalItems) {
    const visibleStart = Math.floor(scrollTop / this.itemHeight);
    const visibleEnd = Math.min(
      visibleStart + Math.ceil(this.containerHeight / this.itemHeight),
      totalItems - 1
    );

    return {
      start: Math.max(0, visibleStart - this.buffer),
      end: Math.min(totalItems - 1, visibleEnd + this.buffer),
      visibleStart,
      visibleEnd
    };
  }

  getTotalHeight(totalItems) {
    return totalItems * this.itemHeight;
  }

  getItemTop(index) {
    return index * this.itemHeight;
  }
}

// Image lazy loading utility
export const createIntersectionObserver = (callback, options = {}) => {
  const defaultOptions = {
    root: null,
    rootMargin: '50px',
    threshold: 0.1,
    ...options
  };

  return new IntersectionObserver(callback, defaultOptions);
};

// Bundle size optimization - dynamic imports
export const loadModule = async (modulePath) => {
  try {
    const module = await import(modulePath);
    return module.default || module;
  } catch (error) {
    console.error(`Failed to load module: ${modulePath}`, error);
    throw error;
  }
};

// Memory management utilities
export class MemoryManager {
  static cleanup = new Set();

  static addCleanupTask(task) {
    this.cleanup.add(task);
  }

  static removeCleanupTask(task) {
    this.cleanup.delete(task);
  }

  static runCleanup() {
    this.cleanup.forEach(task => {
      try {
        task();
      } catch (error) {
        console.error('Cleanup task failed:', error);
      }
    });
    this.cleanup.clear();
  }

  static createAbortController() {
    const controller = new AbortController();
    this.addCleanupTask(() => controller.abort());
    return controller;
  }
}

// Request optimization utilities
export const batchRequests = (requests, batchSize = 5) => {
  const batches = [];
  for (let i = 0; i < requests.length; i += batchSize) {
    batches.push(requests.slice(i, i + batchSize));
  }
  return batches;
};

export const executeInBatches = async (requests, batchSize = 5, delay = 100) => {
  const batches = batchRequests(requests, batchSize);
  const results = [];

  for (const batch of batches) {
    const batchResults = await Promise.allSettled(batch);
    results.push(...batchResults);
    
    // Add delay between batches to prevent overwhelming the server
    if (delay > 0) {
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  return results;
};

// Cache management
export class CacheManager {
  static cache = new Map();
  static maxSize = 100;
  static ttl = 5 * 60 * 1000; // 5 minutes

  static set(key, value, customTtl = this.ttl) {
    // Remove oldest entries if cache is full
    if (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }

    this.cache.set(key, {
      value,
      timestamp: Date.now(),
      ttl: customTtl
    });
  }

  static get(key) {
    const item = this.cache.get(key);
    if (!item) return null;

    // Check if item has expired
    if (Date.now() - item.timestamp > item.ttl) {
      this.cache.delete(key);
      return null;
    }

    return item.value;
  }

  static clear() {
    this.cache.clear();
  }

  static cleanup() {
    const now = Date.now();
    for (const [key, item] of this.cache.entries()) {
      if (now - item.timestamp > item.ttl) {
        this.cache.delete(key);
      }
    }
  }
}

// Performance hooks for React components
export const usePerformanceMonitor = (componentName) => {
  React.useEffect(() => {
    PerformanceMonitor.start(`${componentName} mount`);
    return () => {
      PerformanceMonitor.end(`${componentName} mount`);
    };
  }, [componentName]);
};

export const useDebounce = (value, delay) => {
  const [debouncedValue, setDebouncedValue] = React.useState(value);

  React.useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedValue(value);
    }, delay);

    return () => {
      clearTimeout(handler);
    };
  }, [value, delay]);

  return debouncedValue;
};

export const useThrottle = (value, limit) => {
  const [throttledValue, setThrottledValue] = React.useState(value);
  const lastRan = React.useRef(Date.now());

  React.useEffect(() => {
    const handler = setTimeout(() => {
      if (Date.now() - lastRan.current >= limit) {
        setThrottledValue(value);
        lastRan.current = Date.now();
      }
    }, limit - (Date.now() - lastRan.current));

    return () => {
      clearTimeout(handler);
    };
  }, [value, limit]);

  return throttledValue;
};