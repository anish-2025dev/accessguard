create table public.inquiries (id bigint generated always as identity primary key,
  email text not null, message text not null, created_at timestamptz not null default now());
alter table public.inquiries enable row level security;
create policy "Public can insert inquiries" on public.inquiries for insert to anon, authenticated
  with check (true);
create policy "Admins can view inquiries" on public.inquiries for select to authenticated
  using (exists (select 1 from public.profiles p where p.id = (select auth.uid()) and p.name = 'admin'));
