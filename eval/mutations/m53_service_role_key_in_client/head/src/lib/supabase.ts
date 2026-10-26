import { createClient } from '@supabase/supabase-js';

export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJpc3MiOiAiYWNjZXNzZ3VhcmQtZml4dHVyZSIsICJyZWYiOiAiZml4dHVyZTAwMDAwMDAwMDAiLCAicm9sZSI6ICJzZXJ2aWNlX3JvbGUifQ.ZmFrZS1zaWduYXR1cmUtZm9yLWV2YWw',
);
