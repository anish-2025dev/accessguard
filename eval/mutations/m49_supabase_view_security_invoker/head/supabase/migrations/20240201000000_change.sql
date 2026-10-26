create view public.profile_names with (security_invoker = true) as
  select id, name from public.profiles;
