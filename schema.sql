-- ============================================================
-- Shop Pro / سوق برو — Supabase schema
-- Run in: Supabase Dashboard → SQL Editor → New query → Run
-- ============================================================

-- 1) TABLES ---------------------------------------------------

create table public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  phone       text unique not null,
  role        text not null default 'merchant' check (role in ('merchant','admin')),
  created_at  timestamptz not null default now()
);

create table public.stores (
  id          uuid primary key default gen_random_uuid(),
  owner_id    uuid not null unique references public.profiles(id) on delete cascade,
  name        text not null,
  slug        text unique not null default substr(replace(gen_random_uuid()::text,'-',''),1,10),
  logo_url    text,
  facebook    text,
  instagram   text,
  tiktok      text,
  plan        text not null default 'trial' check (plan in ('trial','unlimited')),
  created_at  timestamptz not null default now()
);

create table public.products (
  id          uuid primary key default gen_random_uuid(),
  store_id    uuid not null references public.stores(id) on delete cascade,
  name        text not null,
  price       numeric(12,2) not null check (price >= 0),
  barcode     text not null,
  image_url   text,
  created_at  timestamptz not null default now(),
  unique (store_id, barcode)
);
create index on public.products (store_id, name);

-- single-row settings (admin WhatsApp number, trial limit, price)
create table public.app_settings (
  id              int primary key default 1 check (id = 1),
  admin_whatsapp  text not null default '0770193164',
  trial_limit     int  not null default 50,
  price_dzd       int  not null default 3000
);
insert into public.app_settings default values;

-- 2) HELPERS --------------------------------------------------

create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin');
$$;

-- auto-create profile when a user signs up (phone is stored in user metadata)
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, phone)
  values (new.id, coalesce(new.raw_user_meta_data->>'phone', split_part(new.email,'@',1)));
  return new;
end $$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- 3) BUSINESS RULES (triggers) --------------------------------

-- a) trial limit: max 50 products (edits don't count — only INSERT)
create or replace function public.enforce_trial_limit()
returns trigger language plpgsql security definer set search_path = public as $$
declare v_plan text; v_count int; v_limit int;
begin
  select plan into v_plan from stores where id = new.store_id;
  if v_plan = 'trial' then
    select trial_limit into v_limit from app_settings where id = 1;
    select count(*) into v_count from products where store_id = new.store_id;
    if v_count >= v_limit then
      raise exception 'TRIAL_LIMIT_REACHED' using errcode = 'P0001';
    end if;
  end if;
  return new;
end $$;

create trigger products_trial_limit
  before insert on public.products
  for each row execute function public.enforce_trial_limit();

-- b) only the admin may change a store's plan or owner
create or replace function public.protect_store_plan()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if (new.plan is distinct from old.plan or new.owner_id is distinct from old.owner_id)
     and not public.is_admin() then
    raise exception 'FORBIDDEN';
  end if;
  return new;
end $$;

create trigger stores_protect_plan
  before update on public.stores
  for each row execute function public.protect_store_plan();

-- c) nobody (except the admin) can change a role
create or replace function public.protect_role()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if new.role is distinct from old.role and not public.is_admin() then
    raise exception 'FORBIDDEN';
  end if;
  return new;
end $$;

create trigger profiles_protect_role
  before update on public.profiles
  for each row execute function public.protect_role();

-- 4) ROW LEVEL SECURITY --------------------------------------

alter table public.profiles     enable row level security;
alter table public.stores       enable row level security;
alter table public.products     enable row level security;
alter table public.app_settings enable row level security;

-- profiles
create policy "profiles: read own or admin" on public.profiles
  for select using (id = auth.uid() or public.is_admin());
create policy "profiles: admin update" on public.profiles
  for update using (public.is_admin());

-- stores (public read so customers can open a store from its QR)
create policy "stores: public read" on public.stores
  for select using (true);
create policy "stores: owner insert" on public.stores
  for insert with check (owner_id = auth.uid());
create policy "stores: owner or admin update" on public.stores
  for update using (owner_id = auth.uid() or public.is_admin());

-- products (public read so customers can scan a barcode)
create policy "products: public read" on public.products
  for select using (true);
create policy "products: owner write" on public.products
  for all using (
    exists (select 1 from public.stores s where s.id = store_id and (s.owner_id = auth.uid() or public.is_admin()))
  ) with check (
    exists (select 1 from public.stores s where s.id = store_id and (s.owner_id = auth.uid() or public.is_admin()))
  );

-- settings (everyone reads the WhatsApp number; only admin edits)
create policy "settings: public read" on public.app_settings
  for select using (true);
create policy "settings: admin update" on public.app_settings
  for update using (public.is_admin());

-- 5) STORAGE (images) ----------------------------------------
-- Files must be uploaded under a folder named after the user id:  <user_id>/filename.jpg

insert into storage.buckets (id, name, public) values
  ('store-logos','store-logos', true),
  ('product-images','product-images', true)
on conflict do nothing;

create policy "images: public read" on storage.objects
  for select using (bucket_id in ('store-logos','product-images'));

create policy "images: owner upload" on storage.objects
  for insert to authenticated
  with check (bucket_id in ('store-logos','product-images')
              and (storage.foldername(name))[1] = auth.uid()::text);

create policy "images: owner update/delete" on storage.objects
  for all to authenticated
  using (bucket_id in ('store-logos','product-images')
         and (storage.foldername(name))[1] = auth.uid()::text);

-- 6) CREATE THE ADMIN (run AFTER creating the admin user) -----
-- Step 1: Dashboard → Authentication → Users → Add user
--         email: 0770000000@shoppro.app  (your phone @shoppro.app) + your password
-- Step 2: run this with YOUR phone:
--
-- update public.profiles set role = 'admin'
-- where phone = '0770000000';
