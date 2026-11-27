-- Zeus Templo Fitness · actualización 2: semana, registro de entrenamientos y cargas
-- Pegar completo en Supabase > SQL Editor y ejecutar una vez. No modifica ni borra los datos existentes.

-- ============ DATOS PROPIOS DE CADA SOCIO (semana, registro de entrenamientos y cargas) ============
create table if not exists public.zeus_socio_datos (
  socio_id text primary key,
  datos jsonb not null default '{}'::jsonb,
  version bigint not null default 0,
  actualizado timestamptz not null default now()
);
alter table public.zeus_socio_datos enable row level security;
revoke all on public.zeus_socio_datos from anon, authenticated;

create or replace function public.zeus_socio_datos_get(p_token uuid) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare q zeus_accesos; r zeus_socio_datos;
begin
  q := zeus_quien(p_token);
  if q.socio_id is null or q.rol <> 'socio' then return jsonb_build_object('error', 'sesion'); end if;
  select * into r from zeus_socio_datos where socio_id = q.socio_id;
  return jsonb_build_object('datos', coalesce(r.datos, '{}'::jsonb), 'version', coalesce(r.version, 0));
end $$;

create or replace function public.zeus_socio_datos_save(p_token uuid, p_datos jsonb, p_version bigint) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare q zeus_accesos; v bigint;
begin
  q := zeus_quien(p_token);
  if q.socio_id is null or q.rol <> 'socio' then return jsonb_build_object('error', 'sesion'); end if;
  if jsonb_typeof(p_datos) is distinct from 'object' or length(p_datos::text) > 800000 then
    return jsonb_build_object('error', 'Datos inválidos');
  end if;
  insert into zeus_socio_datos (socio_id, datos, version) values (q.socio_id, p_datos, 1)
  on conflict (socio_id) do update set datos = excluded.datos, version = zeus_socio_datos.version + 1, actualizado = now()
    where zeus_socio_datos.version = p_version
  returning version into v;
  if v is null then return jsonb_build_object('error', 'conflicto'); end if;
  return jsonb_build_object('version', v);
end $$;

create or replace function public.zeus_admin_socio_datos(p_token uuid, p_socio text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare q zeus_accesos; d jsonb;
begin
  q := zeus_quien(p_token);
  if q.socio_id is null or q.rol <> 'admin' then return jsonb_build_object('error', 'sesion'); end if;
  select datos into d from zeus_socio_datos where socio_id = p_socio;
  if d ->> 'comparte' = 'false' then return jsonb_build_object('privado', true); end if;
  return jsonb_build_object('datos', coalesce(d, '{}'::jsonb));
end $$;

-- Al dar de baja un socio también se borran sus registros.
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
  delete from zeus_socio_datos
    where socio_id not in (select x ->> 'id' from jsonb_array_elements(p_datos -> 'socios') x);
  return jsonb_build_object('version', v);
end $$;

grant execute on function
  public.zeus_socio_datos_get(uuid), public.zeus_socio_datos_save(uuid, jsonb, bigint), public.zeus_admin_socio_datos(uuid, text)
to anon, authenticated;
