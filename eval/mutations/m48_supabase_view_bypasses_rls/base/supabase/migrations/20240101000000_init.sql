create table public.profiles (id uuid primary key references auth.users, name text);
alter table public.profiles enable row level security;
create policy "profiles read own" on public.profiles for select to authenticated
  using ((select auth.uid()) = id);
create policy "profiles update own" on public.profiles for update to authenticated
  using ((select auth.uid()) = id);

create table public.posts (id bigint generated always as identity primary key,
  author uuid not null references auth.users, body text);
alter table public.posts enable row level security;
create policy "posts are public" on public.posts for select to anon, authenticated
  using (true);
create policy "posts insert own" on public.posts for insert to authenticated
  with check ((select auth.uid()) = author);

create view public.post_feed with (security_invoker = true) as
  select id, body from public.posts;
