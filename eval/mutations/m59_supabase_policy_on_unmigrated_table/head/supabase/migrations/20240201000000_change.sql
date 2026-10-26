drop policy if exists "insert own comment" on public.comments;
create policy "insert own comment" on public.comments for insert to authenticated
  with check ((select auth.uid()) = author_id);
