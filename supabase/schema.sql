-- Homy Supabase schema for the closed-circle E2EE messenger
-- Free tier compatible: users + keys + backups, no paid add-ons required.

create table if not exists public.users (
  id text primary key,
  username text not null unique,
  -- Authentication secrets stay in the encrypted local database. These nullable
  -- columns are retained only for migration compatibility with the early schema.
  password_hash text,
  pin_hash text,
  recovery_phrase text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  last_seen_at timestamptz default now()
);

create table if not exists public.public_keys (
  id text primary key,
  user_id text not null references public.users(id) on delete cascade,
  device_id text not null,
  public_key bytea not null,
  created_at timestamptz not null default now(),
  unique(user_id, device_id)
);

create table if not exists public.prekeys (
  id text primary key,
  user_id text not null references public.users(id) on delete cascade,
  key_id text not null,
  public_key bytea not null,
  created_at timestamptz not null default now(),
  unique(user_id, key_id)
);

create table if not exists public.encrypted_backups (
  id text primary key,
  user_id text not null references public.users(id) on delete cascade,
  device_id text not null,
  backup_blob bytea not null,
  created_at timestamptz not null default now(),
  unique(user_id, device_id)
);

create table if not exists public.friend_requests (
  id text primary key,
  requester_id text not null references public.users(id) on delete cascade,
  recipient_id text not null references public.users(id) on delete cascade,
  status text not null default 'pending' check (status in ('pending', 'accepted', 'rejected')),
  created_at timestamptz not null default now(),
  responded_at timestamptz,
  unique(requester_id, recipient_id),
  check (requester_id <> recipient_id)
);

create table if not exists public.conversations (
  id text primary key,
  user_a text not null references public.users(id) on delete cascade,
  user_b text not null references public.users(id) on delete cascade,
  last_message text,
  updated_at timestamptz not null default now(),
  unique(user_a, user_b)
);

create table if not exists public.messages (
  id text primary key,
  conversation_id text not null references public.conversations(id) on delete cascade,
  sender_id text not null references public.users(id) on delete cascade,
  recipient_id text not null references public.users(id) on delete cascade,
  ciphertext bytea not null,
  nonce bytea not null,
  x3dh_ephemeral_public_key bytea,
  x3dh_prekey_id text,
  sent_at timestamptz not null default now(),
  edited_at timestamptz,
  deleted_for_everyone boolean not null default false,
  disappearing_mode text not null default 'off'
);

alter table public.messages add column if not exists x3dh_ephemeral_public_key bytea;
alter table public.messages add column if not exists x3dh_prekey_id text;

create table if not exists public.presence (
  user_id text primary key references public.users(id) on delete cascade,
  status text not null default 'offline',
  last_seen_at timestamptz not null default now()
);

create table if not exists public.typing_events (
  id text primary key,
  conversation_id text not null references public.conversations(id) on delete cascade,
  user_id text not null references public.users(id) on delete cascade,
  is_typing boolean not null default false,
  updated_at timestamptz not null default now(),
  unique(conversation_id, user_id)
);

create table if not exists public.read_receipts (
  id text primary key,
  message_id text not null references public.messages(id) on delete cascade,
  user_id text not null references public.users(id) on delete cascade,
  read_at timestamptz not null default now(),
  unique(message_id, user_id)
);

create or replace function public.set_updated_at()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

drop trigger if exists users_updated_at on public.users;
create trigger users_updated_at
before update on public.users
for each row
execute function public.set_updated_at();

drop trigger if exists conversations_updated_at on public.conversations;
create trigger conversations_updated_at
before update on public.conversations
for each row
execute function public.set_updated_at();

create index if not exists users_username_idx on public.users (username);
create index if not exists public_keys_user_idx on public.public_keys (user_id);
create index if not exists prekeys_user_idx on public.prekeys (user_id);
create index if not exists encrypted_backups_user_idx on public.encrypted_backups (user_id);
create index if not exists friend_requests_recipient_idx on public.friend_requests (recipient_id, status, created_at desc);
create index if not exists friend_requests_requester_idx on public.friend_requests (requester_id, status, created_at desc);
create index if not exists messages_conversation_idx on public.messages (conversation_id, sent_at desc);
create index if not exists typing_events_conversation_idx on public.typing_events (conversation_id, updated_at desc);
create index if not exists read_receipts_message_idx on public.read_receipts (message_id, read_at desc);

-- Phase 2 bootstrap RLS:
-- Keep RLS enabled for safety, but allow app setup actions via anon/authenticated keys.
alter table public.users enable row level security;
alter table public.public_keys enable row level security;
alter table public.prekeys enable row level security;
alter table public.encrypted_backups enable row level security;
alter table public.friend_requests enable row level security;
alter table public.conversations enable row level security;
alter table public.messages enable row level security;
alter table public.presence enable row level security;
alter table public.typing_events enable row level security;
alter table public.read_receipts enable row level security;

drop policy if exists users_select_bootstrap on public.users;
drop policy if exists users_insert_bootstrap on public.users;
drop policy if exists users_update_bootstrap on public.users;
drop policy if exists public_keys_select_bootstrap on public.public_keys;
drop policy if exists public_keys_insert_bootstrap on public.public_keys;
drop policy if exists public_keys_update_bootstrap on public.public_keys;
drop policy if exists prekeys_select_bootstrap on public.prekeys;
drop policy if exists prekeys_insert_bootstrap on public.prekeys;
drop policy if exists prekeys_update_bootstrap on public.prekeys;
drop policy if exists conversations_select_bootstrap on public.conversations;
drop policy if exists conversations_insert_bootstrap on public.conversations;
drop policy if exists conversations_update_bootstrap on public.conversations;
drop policy if exists messages_select_bootstrap on public.messages;
drop policy if exists messages_insert_bootstrap on public.messages;
drop policy if exists messages_update_bootstrap on public.messages;
drop policy if exists presence_select_bootstrap on public.presence;
drop policy if exists presence_insert_bootstrap on public.presence;
drop policy if exists presence_update_bootstrap on public.presence;
drop policy if exists typing_events_select_bootstrap on public.typing_events;
drop policy if exists typing_events_insert_bootstrap on public.typing_events;
drop policy if exists typing_events_update_bootstrap on public.typing_events;
drop policy if exists read_receipts_select_bootstrap on public.read_receipts;
drop policy if exists read_receipts_insert_bootstrap on public.read_receipts;
drop policy if exists read_receipts_update_bootstrap on public.read_receipts;
drop policy if exists friend_requests_select_bootstrap on public.friend_requests;
drop policy if exists friend_requests_insert_bootstrap on public.friend_requests;
drop policy if exists friend_requests_update_bootstrap on public.friend_requests;

create policy users_select_bootstrap
on public.users
for select
to anon, authenticated
using (true);

create policy users_insert_bootstrap
on public.users
for insert
to anon, authenticated
with check (true);

create policy users_update_bootstrap
on public.users
for update
to anon, authenticated
using (true)
with check (true);

create policy public_keys_select_bootstrap
on public.public_keys
for select
to anon, authenticated
using (true);

create policy public_keys_insert_bootstrap
on public.public_keys
for insert
to anon, authenticated
with check (true);

create policy friend_requests_select_bootstrap
on public.friend_requests
for select
to anon, authenticated
using (true);

create policy friend_requests_insert_bootstrap
on public.friend_requests
for insert
to anon, authenticated
with check (requester_id <> recipient_id);

create policy friend_requests_update_bootstrap
on public.friend_requests
for update
to anon, authenticated
using (true)
with check (status in ('pending', 'accepted', 'rejected'));

create policy public_keys_update_bootstrap
on public.public_keys
for update
to anon, authenticated
using (true)
with check (true);

create policy prekeys_select_bootstrap
on public.prekeys
for select
to anon, authenticated
using (true);

create policy prekeys_insert_bootstrap
on public.prekeys
for insert
to anon, authenticated
with check (true);

create policy prekeys_update_bootstrap
on public.prekeys
for update
to anon, authenticated
using (true)
with check (true);

create policy conversations_select_bootstrap
on public.conversations
for select
to anon, authenticated
using (true);

create policy conversations_insert_bootstrap
on public.conversations
for insert
to anon, authenticated
with check (true);

create policy conversations_update_bootstrap
on public.conversations
for update
to anon, authenticated
using (true)
with check (true);

create policy messages_select_bootstrap
on public.messages
for select
to anon, authenticated
using (true);

create policy messages_insert_bootstrap
on public.messages
for insert
to anon, authenticated
with check (true);

create policy messages_update_bootstrap
on public.messages
for update
to anon, authenticated
using (true)
with check (true);

create policy presence_select_bootstrap
on public.presence
for select
to anon, authenticated
using (true);

create policy presence_insert_bootstrap
on public.presence
for insert
to anon, authenticated
with check (true);

create policy presence_update_bootstrap
on public.presence
for update
to anon, authenticated
using (true)
with check (true);

create policy typing_events_select_bootstrap
on public.typing_events
for select
to anon, authenticated
using (true);

create policy typing_events_insert_bootstrap
on public.typing_events
for insert
to anon, authenticated
with check (true);

create policy typing_events_update_bootstrap
on public.typing_events
for update
to anon, authenticated
using (true)
with check (true);

create policy read_receipts_select_bootstrap
on public.read_receipts
for select
to anon, authenticated
using (true);

create policy read_receipts_insert_bootstrap
on public.read_receipts
for insert
to anon, authenticated
with check (true);

create policy read_receipts_update_bootstrap
on public.read_receipts
for update
to anon, authenticated
using (true)
with check (true);

-- Optional: a simple lookup query for later auth checks
-- select id, username, password_hash, pin_hash, recovery_phrase
-- from public.users
-- where username = $1;
