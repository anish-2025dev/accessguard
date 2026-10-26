create table public.videos (id bigint generated always as identity primary key,
  title text not null, url text not null);
alter table public.videos enable row level security;
create policy "Anyone can view videos" on public.videos for select using (true);
-- Admin insert policies (using service role in edge functions)
create policy "Service role can insert videos" on public.videos for insert with check (true);
