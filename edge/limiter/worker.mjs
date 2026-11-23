// Called through the lab's private service binding. No public routes are configured.
export default {
  async fetch(request, env) {
    if (request.method !== 'POST' || request.url !== 'https://lab-limiter.internal/check') {
      return new Response(null, {status: 404});
    }
    const client = request.headers.get('X-Lab-Client') || '';
    if (!/^[a-f0-9]{64}$/.test(client)) return new Response(null, {status: 400});

    const {success} = await env.ADMISSION_BUDGET.limit({key: client});
    return new Response(null, {status: success ? 204 : 429});
  }
};
