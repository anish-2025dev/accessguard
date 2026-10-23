alter table public.posts add column reply_to bigint references public.posts;
drop policy "posts insert own" on public.posts;
create policy "posts insert own" on public.posts for insert to authenticated
  with check (
    (select auth.uid()) = author
    and ((reply_to is null and body is not null) or (reply_to is not null))
  );
