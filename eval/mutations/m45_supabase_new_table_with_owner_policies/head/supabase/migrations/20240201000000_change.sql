create table public.notes (id bigint primary key, owner uuid, body text);
alter table public.notes enable row level security;
create policy "notes own" on public.notes for all to authenticated
  using ((select auth.uid()) = owner) with check ((select auth.uid()) = owner);
