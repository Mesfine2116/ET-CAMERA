-- =====================================================================
-- SnapVault — Supabase setup. Run ONCE in: Supabase Dashboard → SQL Editor → New query → Run
-- Before using the app also do:  Authentication → Providers → Email → turn OFF "Confirm email"
-- The FIRST account that registers automatically becomes the approved admin.
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- ---------- tables ----------
create table if not exists public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  username    text unique not null check (username ~ '^[a-z0-9._-]{3,24}$'),
  full_name   text not null default '',
  role        text not null default 'user'    check (role in ('admin','user')),
  status      text not null default 'pending' check (status in ('pending','approved','blocked')),
  created_at  timestamptz not null default now(),
  approved_at timestamptz
);
create index if not exists profiles_status_idx on public.profiles(status);

create table if not exists public.photos (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null references public.profiles(id) on delete cascade,
  public_id  text not null unique,                                   -- unique: nobody can claim someone else's file
  url        text not null check (url like 'https://res.cloudinary.com/%'),
  format     text,
  width      int,
  height     int,
  bytes      bigint,
  created_at timestamptz not null default now()
);
create index if not exists photos_user_created_idx on public.photos(user_id, created_at desc);
create index if not exists photos_created_idx on public.photos(created_at desc);

-- ---------- helper functions (SECURITY DEFINER so policies don't recurse) ----------
create or replace function public.is_admin() returns boolean
language sql security definer stable set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin' and status = 'approved')
$$;

create or replace function public.is_approved() returns boolean
language sql security definer stable set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and status = 'approved')
$$;

grant execute on function public.is_admin(), public.is_approved() to authenticated;

-- ---------- row level security ----------
alter table public.profiles enable row level security;
alter table public.photos   enable row level security;

drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles for select to authenticated
  using (id = auth.uid() or public.is_admin());

drop policy if exists photos_select on public.photos;
create policy photos_select on public.photos for select to authenticated
  using ((user_id = auth.uid() and public.is_approved()) or public.is_admin());

drop policy if exists photos_insert on public.photos;
create policy photos_insert on public.photos for insert to authenticated
  with check (user_id = auth.uid() and public.is_approved());

drop policy if exists photos_delete on public.photos;
create policy photos_delete on public.photos for delete to authenticated
  using ((user_id = auth.uid() and public.is_approved()) or public.is_admin());

-- no client can write to profiles directly; admin actions go through the functions below
revoke insert, update, delete on public.profiles from anon, authenticated;
revoke all on public.photos from anon;
revoke update on public.photos from authenticated;

-- ---------- new-user trigger: creates the profile (first user = admin) ----------
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  v_first boolean;
  v_username text;
begin
  select not exists (select 1 from public.profiles) into v_first;
  v_username := lower(coalesce(nullif(new.raw_user_meta_data->>'username',''), split_part(new.email,'@',1)));
  insert into public.profiles (id, username, full_name, role, status, approved_at)
  values (
    new.id, v_username, coalesce(new.raw_user_meta_data->>'full_name',''),
    case when v_first then 'admin' else 'user' end,
    case when v_first then 'approved' else 'pending' end,
    case when v_first then now() else null end
  );
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- ---------- admin functions ----------
create or replace function public.admin_set_status(target uuid, new_status text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Not allowed'; end if;
  if new_status not in ('pending','approved','blocked') then raise exception 'Invalid status'; end if;
  if target = auth.uid() then raise exception 'You cannot change your own status'; end if;
  update public.profiles
     set status = new_status,
         approved_at = case when new_status = 'approved' then now() else approved_at end
   where id = target;
end $$;

create or replace function public.admin_set_role(target uuid, new_role text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Not allowed'; end if;
  if new_role not in ('admin','user') then raise exception 'Invalid role'; end if;
  if target = auth.uid() then raise exception 'You cannot change your own role'; end if;
  update public.profiles set role = new_role where id = target;
end $$;

create or replace function public.admin_delete_user(target uuid) returns void
language plpgsql security definer set search_path = public, auth as $$
begin
  if not public.is_admin() then raise exception 'Not allowed'; end if;
  if target = auth.uid() then raise exception 'You cannot delete yourself'; end if;
  delete from auth.users where id = target;   -- cascades to profiles and photos
end $$;

create or replace function public.admin_set_password(target uuid, new_password text) returns void
language plpgsql security definer set search_path = public, extensions, auth as $$
begin
  if not public.is_admin() then raise exception 'Not allowed'; end if;
  if length(coalesce(new_password,'')) < 6 then raise exception 'Password must be at least 6 characters'; end if;
  update auth.users
     set encrypted_password = crypt(new_password, gen_salt('bf')), updated_at = now()
   where id = target;
end $$;

create or replace function public.admin_member_stats()
returns table (user_id uuid, photo_count bigint, total_bytes bigint)
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Not allowed'; end if;
  return query
    select p.user_id, count(*)::bigint, coalesce(sum(p.bytes), 0)::bigint
      from public.photos p group by p.user_id;
end $$;

-- only signed-in users may call the admin functions (each one also checks is_admin())
revoke all on function public.admin_set_status(uuid, text)   from public, anon;
revoke all on function public.admin_set_role(uuid, text)     from public, anon;
revoke all on function public.admin_delete_user(uuid)        from public, anon;
revoke all on function public.admin_set_password(uuid, text) from public, anon;
revoke all on function public.admin_member_stats()           from public, anon;
grant execute on function public.admin_set_status(uuid, text)   to authenticated;
grant execute on function public.admin_set_role(uuid, text)     to authenticated;
grant execute on function public.admin_delete_user(uuid)        to authenticated;
grant execute on function public.admin_set_password(uuid, text) to authenticated;
grant execute on function public.admin_member_stats()           to authenticated;

-- If you ever need to promote someone manually:
-- update public.profiles set role = 'admin', status = 'approved' where username = 'your-username';
