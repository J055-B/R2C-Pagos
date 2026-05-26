-- Ejecuta esto en Supabase > SQL Editor

create table agents (
  id uuid primary key default gen_random_uuid(),
  username text unique not null,
  password_hash text not null,
  name text not null,
  is_admin boolean default false,
  created_at timestamptz default now()
);

create table clients (
  id serial primary key,
  agent_id uuid references agents(id) on delete cascade,
  url text not null,
  object_type text not null,
  record_id text not null,
  total_investment numeric default 0,
  created_at timestamptz default now(),
  unique(agent_id, record_id)
);

create table invite_codes (
  id serial primary key,
  code text unique not null,
  used boolean default false,
  created_by uuid references agents(id),
  used_by uuid references agents(id),
  used_at timestamptz,
  created_at timestamptz default now()
);

-- Admin inicial — contraseña: admin123
insert into agents (username, password_hash, name, is_admin) values
('admin', '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 'Administrador', true);
