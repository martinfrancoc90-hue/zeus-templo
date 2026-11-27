-- Zeus Templo Fitness · actualización 3: panel de asistencia del dueño
-- Pegar completo en Supabase > SQL Editor y ejecutar una vez. No modifica ni borra los datos existentes.

-- ============ PANEL DE ASISTENCIA DEL DUEÑO ============
create or replace function public.zeus_admin_asistencia(p_token uuid) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare q zeus_accesos; r jsonb;
begin
  q := zeus_quien(p_token);
  if q.socio_id is null or q.rol <> 'admin' then return jsonb_build_object('error', 'sesion'); end if;
  select coalesce(jsonb_object_agg(d.socio_id,
    case when d.datos ->> 'comparte' = 'false' then jsonb_build_object('privado', true)
    else jsonb_build_object(
      'sem', coalesce(d.datos -> 'sem', '{}'::jsonb),
      'dias', (
        select coalesce(jsonb_object_agg(e.key, jsonb_build_object(
          'n', (select count(*) from jsonb_object_keys(case when jsonb_typeof(e.value -> 'sets') = 'object' then e.value -> 'sets' else '{}'::jsonb end)),
          'tot', coalesce(e.value -> 'tot', '0'::jsonb))), '{}'::jsonb)
        from jsonb_each(case when jsonb_typeof(d.datos -> 'log') = 'object' then d.datos -> 'log' else '{}'::jsonb end) e
        where e.key >= to_char(now() - interval '42 days', 'YYYY-MM-DD')))
    end), '{}'::jsonb)
  into r from zeus_socio_datos d;
  return jsonb_build_object('socios', r);
end $$;
grant execute on function public.zeus_admin_asistencia(uuid) to anon, authenticated;
