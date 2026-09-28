-- ================================================================
-- HOMY v2 — LOCKED-DOWN SCHEMA
-- RLS on every table. auth.uid() everywhere. No open policies.
-- ================================================================

-- ---------- 1) TABLES ----------

create table public.profiles (
  id         uuid primary key references auth.users (id) on delete cascade,
  username   text not null unique check (username ~ '^[a-z0-9_]{3,20}$'),
  bio        text not null default '' check (char_length(bio) <= 160),
  created_at timestamptz not null default now()
);

create table public.public_keys (
  user_id      uuid primary key references auth.users (id) on delete cascade,
  identity_key bytea not null,
  updated_at   timestamptz not null default now()
);

create table public.prekeys (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null references auth.users (id) on delete cascade,
  prekey     bytea not null,
  created_at timestamptz not null default now()
);

create table public.friend_requests (
  id           uuid primary key default gen_random_uuid(),
  requester_id uuid not null references auth.users (id) on delete cascade,
  recipient_id uuid not null references auth.users (id) on delete cascade,
  status       text not null default 'pending'
               check (status in ('pending', 'accepted', 'rejected')),
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now(),
  unique (requester_id, recipient_id),
  check (requester_id <> recipient_id)
);

create table public.conversations (
  id         uuid primary key default gen_random_uuid(),
  user_a     uuid not null references auth.users (id) on delete cascade,
  user_b     uuid not null references auth.users (id) on delete cascade,
  created_at timestamptz not null default now(),
  unique (user_a, user_b),
  check (user_a <= user_b)   -- canonical order; self-chat allowed (a = b)
);

create table public.messages (
  id              uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references public.conversations (id) on delete cascade,
  sender_id       uuid not null references auth.users (id) on delete cascade,
  ciphertext      bytea not null,
  nonce           bytea not null,
  sent_at         timestamptz not null default now(),
  edited_at       timestamptz,
  deleted_at      timestamptz
);

create table public.read_receipts (
  id              uuid primary key default gen_random_uuid(),
  message_id      uuid not null references public.messages (id) on delete cascade,
  conversation_id uuid not null references public.conversations (id) on delete cascade,
  reader_id       uuid not null references auth.users (id) on delete cascade,
  read_at         timestamptz not null default now(),
  unique (message_id, reader_id)
);

create table public.typing_events (
  conversation_id uuid not null references public.conversations (id) on delete cascade,
  user_id         uuid not null references auth.users (id) on delete cascade,
  typing          boolean not null default true,
  updated_at      timestamptz not null default now(),
  primary key (conversation_id, user_id)
);

create table public.presence (
  user_id   uuid primary key references auth.users (id) on delete cascade,
  online    boolean not null default false,
  last_seen timestamptz not null default now()
);

create table public.encrypted_backups (
  user_id    uuid primary key references auth.users (id) on delete cascade,
  ciphertext bytea not null,
  updated_at timestamptz not null default now()
);

-- ---------- 2) INDEXES + HELPER FUNCTIONS ----------

create index messages_conv_idx      on public.messages (conversation_id, sent_at desc);
create index friend_requests_in_idx on public.friend_requests (recipient_id, status);
create index prekeys_user_idx       on public.prekeys (user_id);

-- Who are my friends? (bypasses RLS internally, callable only when logged in)
create or replace function public.are_friends(a uuid, b uuid)
returns boolean
language sql stable security definer set search_path = public
as $$   select exists (
    select 1 from public.friend_requests fr
    where fr.status = 'accepted'
      and ((fr.requester_id = a and fr.recipient_id = b)
        or (fr.requester_id = b and fr.recipient_id = a))
  );
 $$;

-- Am I in this conversation? (used to guard messages, receipts, typing)
create or replace function public.is_participant(p_conversation uuid, p_user uuid)
returns boolean
language sql stable security definer set search_path = public
as $$   select exists (
    select 1 from public.conversations c
    where c.id = p_conversation and p_user in (c.user_a, c.user_b)
  );
 $$;

-- Username availability check for the signup screen (safe for logged-out users)
create or replace function public.username_available(p_username text)
returns boolean
language sql stable security definer set search_path = public
as $$   select not exists (
    select 1 from public.profiles p where p.username = lower(p_username)
  );
 $$;

-- Auto-create a profile when a user signs up (username comes from signup metadata)
create or replace function public.handle_new_user()
returns trigger
language plpgsql security definer set search_path = public
as $$ begin
  insert into public.profiles (id, username)
  values (new.id, lower(new.raw_user_meta_data ->> 'username'));
  return new;
end;
 $$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Functions are executable by public by default — lock that down
revoke execute on function public.are_friends(uuid, uuid) from public, anon;
revoke execute on function public.is_participant(uuid, uuid) from public, anon;
revoke execute on function public.handle_new_user() from public, anon;
revoke execute on function public.username_available(text) from public;
grant execute on function public.are_friends(uuid, uuid) to authenticated;
grant execute on function public.is_participant(uuid, uuid) to authenticated;
grant execute on function public.username_available(text) to anon, authenticated;

-- ---------- 3) ENABLE RLS ON EVERYTHING ----------

alter table public.profiles          enable row level security;
alter table public.public_keys       enable row level security;
alter table public.prekeys           enable row level security;
alter table public.friend_requests   enable row level security;
alter table public.conversations     enable row level security;
alter table public.messages          enable row level security;
alter table public.read_receipts     enable row level security;
alter table public.typing_events     enable row level security;
alter table public.presence          enable row level security;
alter table public.encrypted_backups enable row level security;

-- ---------- 4) POLICIES (auth.uid() everywhere; no open policies) ----------

-- profiles: the username directory (no secrets here)
create policy "profiles_select" on public.profiles
  for select to authenticated
  using (auth.uid() is not null);

create policy "profiles_insert_self" on public.profiles
  for insert to authenticated
  with check (auth.uid() = id);

create policy "profiles_update_self" on public.profiles
  for update to authenticated
  using (auth.uid() = id)
  with check (auth.uid() = id);

-- public keys / prekeys: anyone logged in can read (needed for key exchange);
-- you can only publish your own
create policy "keys_select" on public.public_keys
  for select to authenticated
  using (auth.uid() is not null);

create policy "keys_insert_own" on public.public_keys
  for insert to authenticated
  with check (auth.uid() = user_id);

create policy "keys_update_own" on public.public_keys
  for update to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy "prekeys_select" on public.prekeys
  for select to authenticated
  using (auth.uid() is not null);

create policy "prekeys_insert_own" on public.prekeys
  for insert to authenticated
  with check (auth.uid() = user_id);

create policy "prekeys_delete_own" on public.prekeys
  for delete to authenticated
  using (auth.uid() = user_id);

-- friend requests: visible to the two people involved, nobody else
create policy "fr_select" on public.friend_requests
  for select to authenticated
  using (auth.uid() = requester_id or auth.uid() = recipient_id);

create policy "fr_insert" on public.friend_requests
  for insert to authenticated
  with check (auth.uid() = requester_id and status = 'pending');

create policy "fr_update_recipient" on public.friend_requests
  for update to authenticated
  using (auth.uid() = recipient_id and status = 'pending')
  with check (auth.uid() = recipient_id and status in ('accepted', 'rejected'));

create policy "fr_delete" on public.friend_requests
  for delete to authenticated
  using (auth.uid() = requester_id or auth.uid() = recipient_id);

-- conversations: participants only; creating one requires being in it,
-- canonical ordering, and (for two different people) an accepted friendship
create policy "conversations_select" on public.conversations
  for select to authenticated
  using (auth.uid() = user_a or auth.uid() = user_b);

create policy "conversations_insert" on public.conversations
  for insert to authenticated
  with check (
    (auth.uid() = user_a or auth.uid() = user_b)
    and user_a <= user_b
    and (user_a = user_b or are_friends(user_a, user_b))
  );

-- messages: only conversation participants read; only the sender writes/edits/deletes
create policy "messages_select" on public.messages
  for select to authenticated
  using (is_participant(conversation_id, auth.uid()));

create policy "messages_insert" on public.messages
  for insert to authenticated
  with check (
    sender_id = auth.uid()
    and is_participant(conversation_id, auth.uid())
  );

create policy "messages_update_own" on public.messages
  for update to authenticated
  using (sender_id = auth.uid())
  with check (sender_id = auth.uid());

create policy "messages_delete_own" on public.messages
  for delete to authenticated
  using (sender_id = auth.uid());

-- read receipts: participants read; you only file receipts as yourself
create policy "receipts_select" on public.read_receipts
  for select to authenticated
  using (is_participant(conversation_id, auth.uid()));

create policy "receipts_insert" on public.read_receipts
  for insert to authenticated
  with check (
    reader_id = auth.uid()
    and is_participant(conversation_id, auth.uid())
  );

-- typing: participants read; you only set your own row
create policy "typing_select" on public.typing_events
  for select to authenticated
  using (is_participant(conversation_id, auth.uid()));

create policy "typing_insert_own" on public.typing_events
  for insert to authenticated
  with check (
    user_id = auth.uid()
    and is_participant(conversation_id, auth.uid())
  );

create policy "typing_update_own" on public.typing_events
  for update to authenticated
  using (user_id = auth.uid())
  with check (user_id = auth.uid());

-- presence: friends (and you) can see it; you only write your own
create policy "presence_select" on public.presence
  for select to authenticated
  using (auth.uid() = user_id or are_friends(auth.uid(), user_id));

create policy "presence_insert_own" on public.presence
  for insert to authenticated
  with check (auth.uid() = user_id);

create policy "presence_update_own" on public.presence
  for update to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- encrypted backups: strictly your own blob (used later for multi-device)
create policy "backups_select_own" on public.encrypted_backups
  for select to authenticated
  using (auth.uid() = user_id);

create policy "backups_insert_own" on public.encrypted_backups
  for insert to authenticated
  with check (auth.uid() = user_id);

create policy "backups_update_own" on public.encrypted_backups
  for update to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- ---------- 5) REALTIME (RLS-filtered; works only for logged-in clients) ----------

alter publication supabase_realtime add table public.messages;
alter publication supabase_realtime add table public.friend_requests;
alter publication supabase_realtime add table public.typing_events;
alter publication supabase_realtime add table public.presence;
alter publication supabase_realtime add table public.read_receipts;

-- ---------- 6) GRANTS (RLS is the boundary; grants are the door) ----------

grant usage on schema public to anon, authenticated, service_role;
grant all on all tables in schema public to authenticated, service_role;
