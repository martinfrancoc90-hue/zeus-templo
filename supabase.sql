-- Zeus Templo Fitness · base de datos
-- Pegar completo en Supabase > SQL Editor y ejecutar. Se puede volver a ejecutar sin perder datos.
-- ANTES de ejecutar: cambiar el celular y la clave del dueño al final del archivo.

create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

create table if not exists public.zeus_estado (
  id int primary key default 1 check (id = 1),
  datos jsonb not null default '{}'::jsonb,
  version bigint not null default 0,
  actualizado timestamptz not null default now()
);
insert into public.zeus_estado (id) values (1) on conflict do nothing;

create table if not exists public.zeus_accesos (
  socio_id text primary key,
  tel text unique not null,
  clave_hash text not null,
  rol text not null default 'socio',
  intentos int not null default 0,
  bloqueado_hasta timestamptz
);
create table if not exists public.zeus_sesiones (
  token uuid primary key default gen_random_uuid(),
  socio_id text not null references public.zeus_accesos on delete cascade,
  creado timestamptz not null default now()
);
create table if not exists public.zeus_avisos (
  socio_id text primary key,
  fecha timestamptz not null default now()
);

-- Nadie lee ni escribe las tablas directo: todo pasa por las funciones de abajo.
alter table public.zeus_estado enable row level security;
alter table public.zeus_accesos enable row level security;
alter table public.zeus_sesiones enable row level security;
alter table public.zeus_avisos enable row level security;
revoke all on public.zeus_estado, public.zeus_accesos, public.zeus_sesiones, public.zeus_avisos from anon, authenticated;

create or replace function public.zeus_quien(p_token uuid) returns public.zeus_accesos
language sql security definer set search_path = public, extensions as $$
  select a.* from zeus_sesiones s join zeus_accesos a using (socio_id)
  where s.token = p_token and s.creado > now() - interval '180 days'
$$;

create or replace function public.zeus_login(p_tel text, p_clave text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare a zeus_accesos; t uuid;
begin
  select * into a from zeus_accesos where tel = regexp_replace(coalesce(p_tel,''), '\D', '', 'g');
  if not found then
    perform pg_sleep(0.3);
    return jsonb_build_object('error', 'Celular o PIN incorrecto');
  end if;
  if a.bloqueado_hasta is not null and a.bloqueado_hasta > now() then
    return jsonb_build_object('error', 'Demasiados intentos. Probá de nuevo en 15 minutos.');
  end if;
  if a.clave_hash = crypt(coalesce(p_clave,''), a.clave_hash) then
    update zeus_accesos set intentos = 0, bloqueado_hasta = null where socio_id = a.socio_id;
    insert into zeus_sesiones (socio_id) values (a.socio_id) returning token into t;
    return jsonb_build_object('token', t, 'rol', a.rol, 'id', a.socio_id);
  end if;
  update zeus_accesos set
    bloqueado_hasta = case when intentos + 1 >= 5 then now() + interval '15 minutes' else null end,
    intentos = case when intentos + 1 >= 5 then 0 else intentos + 1 end
  where socio_id = a.socio_id;
  return jsonb_build_object('error', 'Celular o PIN incorrecto');
end $$;

create or replace function public.zeus_salir(p_token uuid) returns jsonb
language sql security definer set search_path = public, extensions as $$
  delete from zeus_sesiones where token = p_token;
  select '{"ok":true}'::jsonb
$$;

create or replace function public.zeus_admin_get(p_token uuid) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare q zeus_accesos;
begin
  q := zeus_quien(p_token);
  if q.socio_id is null or q.rol <> 'admin' then return jsonb_build_object('error', 'sesion'); end if;
  return (select jsonb_build_object('datos', e.datos, 'version', e.version,
    'avisos', (select coalesce(jsonb_agg(jsonb_build_object('socioId', socio_id, 'fecha', fecha) order by fecha), '[]'::jsonb) from zeus_avisos),
    'conAcceso', (select coalesce(jsonb_agg(socio_id), '[]'::jsonb) from zeus_accesos where rol = 'socio'))
    from zeus_estado e where e.id = 1);
end $$;

create or replace function public.zeus_admin_save(p_token uuid, p_datos jsonb, p_version bigint) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare q zeus_accesos; v bigint;
begin
  q := zeus_quien(p_token);
  if q.socio_id is null or q.rol <> 'admin' then return jsonb_build_object('error', 'sesion'); end if;
  if jsonb_typeof(p_datos -> 'socios') is distinct from 'array' then return jsonb_build_object('error', 'Datos inválidos'); end if;
  update zeus_estado set datos = p_datos, version = version + 1, actualizado = now()
    where id = 1 and version = p_version returning version into v;
  if v is null then return jsonb_build_object('error', 'conflicto'); end if;
  delete from zeus_accesos where rol = 'socio'
    and socio_id not in (select x ->> 'id' from jsonb_array_elements(p_datos -> 'socios') x);
  delete from zeus_avisos
    where socio_id not in (select x ->> 'id' from jsonb_array_elements(p_datos -> 'socios') x);
  return jsonb_build_object('version', v);
end $$;

create or replace function public.zeus_admin_pin(p_token uuid, p_socio text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare q zeus_accesos; t text; pin text;
begin
  q := zeus_quien(p_token);
  if q.socio_id is null or q.rol <> 'admin' then return jsonb_build_object('error', 'sesion'); end if;
  select regexp_replace(coalesce(x ->> 'tel',''), '\D', '', 'g') into t
    from zeus_estado e, jsonb_array_elements(e.datos -> 'socios') x where e.id = 1 and x ->> 'id' = p_socio;
  if t is null then return jsonb_build_object('error', 'No se encontró el socio'); end if;
  if length(t) < 6 then return jsonb_build_object('error', 'El socio no tiene un celular válido cargado'); end if;
  pin := lpad(floor(random() * 10000)::int::text, 4, '0');
  begin
    insert into zeus_accesos (socio_id, tel, clave_hash) values (p_socio, t, crypt(pin, gen_salt('bf')))
    on conflict (socio_id) do update set tel = excluded.tel, clave_hash = excluded.clave_hash, intentos = 0, bloqueado_hasta = null;
  exception when unique_violation then
    return jsonb_build_object('error', 'Ese celular ya lo usa otra persona');
  end;
  delete from zeus_sesiones where socio_id = p_socio;
  return jsonb_build_object('pin', pin);
end $$;

create or replace function public.zeus_admin_aviso_borrar(p_token uuid, p_socio text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare q zeus_accesos;
begin
  q := zeus_quien(p_token);
  if q.socio_id is null or q.rol <> 'admin' then return jsonb_build_object('error', 'sesion'); end if;
  delete from zeus_avisos where socio_id = p_socio;
  return '{"ok":true}'::jsonb;
end $$;

create or replace function public.zeus_socio_get(p_token uuid) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare q zeus_accesos; d jsonb; s jsonb;
begin
  q := zeus_quien(p_token);
  if q.socio_id is null then return jsonb_build_object('error', 'sesion'); end if;
  select datos into d from zeus_estado where id = 1;
  select x into s from jsonb_array_elements(d -> 'socios') x where x ->> 'id' = q.socio_id;
  if s is null then return jsonb_build_object('error', 'sesion'); end if;
  return jsonb_build_object('socio', s, 'planes', d -> 'planes', 'grupos', d -> 'grupos', 'rutinas', d -> 'rutinas',
    'ejExtra', d -> 'ejExtra', 'alias', d -> 'alias',
    'aviso', exists (select 1 from zeus_avisos where socio_id = q.socio_id));
end $$;

create or replace function public.zeus_socio_avisar(p_token uuid) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare q zeus_accesos;
begin
  q := zeus_quien(p_token);
  if q.socio_id is null or q.rol <> 'socio' then return jsonb_build_object('error', 'sesion'); end if;
  insert into zeus_avisos (socio_id) values (q.socio_id) on conflict (socio_id) do update set fecha = now();
  return '{"ok":true}'::jsonb;
end $$;

revoke all on function public.zeus_quien(uuid) from public, anon, authenticated;
grant execute on function
  public.zeus_login(text, text), public.zeus_salir(uuid), public.zeus_admin_get(uuid),
  public.zeus_admin_save(uuid, jsonb, bigint), public.zeus_admin_pin(uuid, text),
  public.zeus_admin_aviso_borrar(uuid, text), public.zeus_socio_get(uuid), public.zeus_socio_avisar(uuid)
to anon, authenticated;

-- ============ ACCESO DEL DUEÑO ============
-- Cambiar los dos valores entre comillas: el celular (solo números) y una clave larga.
-- Para cambiar la clave más adelante, editar acá y volver a ejecutar solo este bloque.
insert into public.zeus_accesos (socio_id, tel, clave_hash, rol)
values ('admin', regexp_replace('CELULAR_DEL_DUENO', '\D', '', 'g'), extensions.crypt('CLAVE_DEL_DUENO', extensions.gen_salt('bf')), 'admin')
on conflict (socio_id) do update set tel = excluded.tel, clave_hash = excluded.clave_hash, intentos = 0, bloqueado_hasta = null;
