alter policy "profiles update own" on public.profiles
  using ((select auth.uid()) = id or id is null);
