-- =====================================================================
-- SnapVault: WIPE ALL DATA and create two accounts
--   mesfine / 12345678  -> admin
--   edu     / 12345678  -> normal user (approved)
-- Run in: Supabase Dashboard -> SQL Editor -> New query -> Run
-- Needs the tables and functions from supabase-setup.sql to exist already.
-- WARNING: this permanently deletes every user, profile and photo/video record.
-- (Files stay in Cloudinary, see the note after the script.)
-- =====================================================================

do $$
declare
  v_domain text := 'gmail.com';          -- must equal USERNAME_DOMAIN in index.html
  v_pass   text := '12345678';
  v_id     uuid;
  r        record;
begin
  -- 1) clear everything (deleting auth users cascades to profiles, photos, identities, sessions)
  delete from public.photos;
  delete from public.profiles;
  delete from auth.users;

  -- 2) create the two accounts (username, display name, role)
  for r in
    select * from (values
      ('mesfine', 'Mesfine', 'admin'),
      ('edu',     'Edu',     'user')
    ) as t(username, full_name, role)
  loop
    v_id := gen_random_uuid();

    insert into auth.users (
      instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
      raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
      confirmation_token, recovery_token, email_change_token_new, email_change,
      email_change_token_current, phone_change, phone_change_token, reauthentication_token
    ) values (
      '00000000-0000-0000-0000-000000000000', v_id, 'authenticated', 'authenticated',
      r.username || '@' || v_domain,
      extensions.crypt(v_pass, extensions.gen_salt('bf')),
      now(),
      '{"provider":"email","providers":["email"]}'::jsonb,
      jsonb_build_object('username', r.username, 'full_name', r.full_name),
      now(), now(),
      '', '', '', '', '', '', '', ''
    );
    -- (the on_auth_user_created trigger creates the profile row)

    insert into auth.identities (id, user_id, provider_id, provider, identity_data, last_sign_in_at, created_at, updated_at)
    values (
      gen_random_uuid(), v_id, v_id::text, 'email',
      jsonb_build_object('sub', v_id::text, 'email', r.username || '@' || v_domain, 'email_verified', true),
      now(), now(), now()
    );

    -- make the role and approval explicit instead of relying on "first user = admin"
    update public.profiles
       set role = r.role, status = 'approved', approved_at = now(), full_name = r.full_name
     where id = v_id;
  end loop;
end $$;

-- 3) check the result: you should see exactly 2 rows
select p.username, p.full_name, p.role, p.status, u.email
  from public.profiles p
  join auth.users u on u.id = p.id
 order by p.role, p.username;