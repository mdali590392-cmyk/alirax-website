export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS Headers Security
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // Token Validation Helper
    const authHeader = request.headers.get('Authorization');
    const token = authHeader ? authHeader.split(' ')[1] : null;

    if (path.startsWith('/api/key/')) {
      if (!token) {
        return new Response(JSON.stringify({ error: 'Unauthorized access' }), {
          status: 401,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      // User Identifer (Token se mock kar rahe hain)
      const userId = `user_${token.slice(0, 8)}`;

      // 1. Get Current Key
      if (path === '/api/key/get' && request.method === 'GET') {
        const existingKey = await env.ALIRAX_KV.get(`key_${userId}`);
        return new Response(JSON.stringify({ key: existingKey || null }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      // 2. Generate New Key
      if (path === '/api/key/generate' && request.method === 'POST') {
        const newKey = `alirax-sk-${crypto.randomUUID().replace(/-/g, '')}`;
        
        // Save user -> key mapping
        await env.ALIRAX_KV.put(`key_${userId}`, newKey);
        // Save key validation lookup
        await env.ALIRAX_KV.put(`valid_key_${newKey}`, userId);

        return new Response(JSON.stringify({ key: newKey }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      // 3. Revoke Key
      if (path === '/api/key/revoke' && request.method === 'POST') {
        const existingKey = await env.ALIRAX_KV.get(`key_${userId}`);
        if (existingKey) {
          await env.ALIRAX_KV.delete(`key_${userId}`);
          await env.ALIRAX_KV.delete(`valid_key_${existingKey}`);
        }
        return new Response(JSON.stringify({ success: true }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }
    }

    return new Response('AliRax AI Backend Ready', { status: 200 });
  }
};
