-- =====================================================================
-- SnapVault: Trash
--
--  * When a MEMBER deletes a photo or video, it only disappears from their own library.
--    It is not removed from Cloudinary. It moves to the Trash, which only admins can open.
--  * In the Trash an admin sees the deleted items grouped by member and can restore them
--    or delete them permanently (from the app AND from Cloudinary).
--  * When an ADMIN deletes a photo or video, it is removed for good (the app also removes
--    the Cloudinary file; this needs the "cloudinary" Edge Function, see cloudinary-edge-function.ts).
--
-- Run ONCE in: Supabase Dashboard -> SQL Editor -> New query -> Run.   Safe to run again.
-- (The same changes are also part of supabase-setup.sql.)
-- =====================================================================

alter table public.photos add column if not exists deleted_at timestamptz;
create index if not exists photos_trash_idx on public.photos (deleted_at desc) where deleted_at is not null;

-- Members only ever read their own photos that are NOT in the trash. Admins read everything.
drop policy if exists photos_select on public.photos;
create policy photos_select on public.photos for select to authenticated
  using ((user_id = auth.uid() and deleted_at is null and public.is_approved()) or public.is_admin());

-- Only admins may delete rows. A member's "delete" goes through trash_photos() below.
drop policy if exists photos_delete on public.photos;
create policy photos_delete on public.photos for delete to authenticated
  using (public.is_admin());

-- A member deletes their own photos: they are hidden from the member and kept for the admin.
create or replace function public.trash_photos(p_ids uuid[]) returns integer
language plpgsql security definer set search_path = public as $$
declare v_count integer;
begin
  if not public.is_approved() then raise exception 'Not allowed'; end if;
  if p_ids is null or cardinality(p_ids) = 0 then return 0; end if;
  if cardinality(p_ids) > 500 then raise exception 'Too many at once'; end if;
  update public.photos
     set deleted_at = now()
   where id = any(p_ids) and user_id = auth.uid() and deleted_at is null;
  get diagnostics v_count = row_count;
  return v_count;
end $$;

-- Admin: put items back in their owner's library.
create or replace function public.admin_restore_photos(p_ids uuid[]) returns integer
language plpgsql security definer set search_path = public as $$
declare v_count integer;
begin
  if not public.is_admin() then raise exception 'Not allowed'; end if;
  if p_ids is null or cardinality(p_ids) = 0 then return 0; end if;
  if cardinality(p_ids) > 500 then raise exception 'Too many at once'; end if;
  update public.photos set deleted_at = null where id = any(p_ids) and deleted_at is not null;
  get diagnostics v_count = row_count;
  return v_count;
end $$;

-- Members page: the counts show each member's visible library (the trash is not counted).
create or replace function public.admin_member_stats()
returns table (user_id uuid, photo_count bigint, total_bytes bigint)
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Not allowed'; end if;
  return query
    select p.user_id, count(*)::bigint, coalesce(sum(p.bytes), 0)::bigint
      from public.photos p where p.deleted_at is null group by p.user_id;
end $$;

revoke all on function public.trash_photos(uuid[])         from public, anon;
revoke all on function public.admin_restore_photos(uuid[]) from public, anon;
revoke all on function public.admin_member_stats()         from public, anon;
grant execute on function public.trash_photos(uuid[])         to authenticated;
grant execute on function public.admin_restore_photos(uuid[]) to authenticated;
grant execute on function public.admin_member_stats()         to authenticated;