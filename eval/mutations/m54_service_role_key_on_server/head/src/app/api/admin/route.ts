import { createClient } from '@supabase/supabase-js';

const admin = createClient(process.env.SUPABASE_URL!, 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJpc3MiOiAiYWNjZXNzZ3VhcmQtZml4dHVyZSIsICJyZWYiOiAiZml4dHVyZTAwMDAwMDAwMDAiLCAicm9sZSI6ICJzZXJ2aWNlX3JvbGUifQ.ZmFrZS1zaWduYXR1cmUtZm9yLWV2YWw');

export async function GET() {
  const { data } = await admin.from('profiles').select('*');
  return Response.json(data);
}
