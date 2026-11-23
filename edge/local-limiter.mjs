// Loopback preview and unit-test stand-in for the per-location Cloudflare counter.
import service from './limiter/worker.mjs';

export function localAdmissionLimiter(clock = Date.now) {
  const clients = new Map();
  let window;
  const budget = {
    async limit({key}) {
      const current = Math.floor(clock() / 10000);
      if (current !== window) {
        clients.clear();
        window = current;
      }
      const count = clients.get(key) || 0;
      if (count >= 20) return {success: false};
      clients.set(key, count + 1);
      return {success: true};
    }
  };
  return {
    fetch(url, options) {
      return service.fetch(new Request(url, options), {ADMISSION_BUDGET: budget});
    }
  };
}
