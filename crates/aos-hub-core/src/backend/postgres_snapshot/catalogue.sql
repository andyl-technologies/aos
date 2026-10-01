-- Semantic current-schema facts, independent of database, role, OID and index names.
-- Expression strings are token-normalized by the reader before comparison.
WITH objects AS (
    SELECT c.oid, c.relname, c.relkind, c.relpersistence, c.relrowsecurity,
           c.relforcerowsecurity, c.relispartition, c.reloptions
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
), facts AS (
    SELECT 'relation' AS kind, o.relname AS owner,
           jsonb_build_object(
               'kind', o.relkind::text, 'persistence', o.relpersistence::text,
               'row_security', o.relrowsecurity, 'force_row_security', o.relforcerowsecurity,
               'partition', o.relispartition, 'options', o.reloptions,
               'definition', CASE WHEN o.relkind IN ('v', 'm') THEN pg_catalog.pg_get_viewdef(o.oid, false) END
           ) AS detail
    FROM objects o WHERE o.relkind NOT IN ('i', 'S')

    UNION ALL
    SELECT 'column', o.relname,
           jsonb_build_object(
               'ordinal', a.attnum, 'name', a.attname,
               'type', pg_catalog.format_type(a.atttypid, a.atttypmod),
               'not_null', a.attnotnull, 'identity', a.attidentity::text,
               'generated', a.attgenerated::text,
               'collation', CASE WHEN a.attcollation = t.typcollation THEN 'default'
                                 ELSE cn.nspname || '.' || co.collname END,
               'default', CASE WHEN d.refobjid IS NOT NULL THEN 'owned_sequence'
                               ELSE pg_catalog.pg_get_expr(ad.adbin, ad.adrelid, false) END
           )
    FROM objects o
    JOIN pg_catalog.pg_attribute a ON a.attrelid = o.oid AND a.attnum > 0
    JOIN pg_catalog.pg_type t ON t.oid = a.atttypid
    LEFT JOIN pg_catalog.pg_collation co ON co.oid = a.attcollation
    LEFT JOIN pg_catalog.pg_namespace cn ON cn.oid = co.collnamespace
    LEFT JOIN pg_catalog.pg_attrdef ad ON ad.adrelid = o.oid AND ad.adnum = a.attnum
    LEFT JOIN pg_catalog.pg_depend d ON d.classid = 'pg_class'::regclass
         AND d.refobjid = o.oid AND d.refobjsubid = a.attnum AND d.deptype IN ('a', 'i')
         AND EXISTS (SELECT 1 FROM pg_catalog.pg_class s WHERE s.oid = d.objid AND s.relkind = 'S')
    WHERE o.relkind = 'r' AND NOT a.attisdropped

    UNION ALL
    SELECT 'dropped_column', o.relname, jsonb_build_object('ordinal', a.attnum)
    FROM objects o
    JOIN pg_catalog.pg_attribute a ON a.attrelid = o.oid AND a.attnum > 0 AND a.attisdropped
    WHERE o.relkind = 'r'

    UNION ALL
    SELECT 'constraint', o.relname,
           jsonb_build_object(
               'kind', c.contype::text, 'validated', c.convalidated,
               'enforced', c.conenforced, 'deferrable', c.condeferrable,
               'deferred', c.condeferred, 'local', c.conislocal,
               'inherited', c.coninhcount,
               'columns', (SELECT jsonb_agg(a.attname ORDER BY k.ordinal)
                           FROM unnest(c.conkey) WITH ORDINALITY k(attnum, ordinal)
                           JOIN pg_catalog.pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum),
               'referenced_schema', rn.nspname, 'referenced_table', r.relname,
               'referenced_columns', (SELECT jsonb_agg(a.attname ORDER BY k.ordinal)
                           FROM unnest(c.confkey) WITH ORDINALITY k(attnum, ordinal)
                           JOIN pg_catalog.pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.attnum),
               'update', c.confupdtype::text, 'delete', c.confdeltype::text,
               'match', c.confmatchtype::text,
               'expression', pg_catalog.pg_get_expr(c.conbin, c.conrelid, false)
           )
    FROM objects o
    JOIN pg_catalog.pg_constraint c ON c.conrelid = o.oid
    LEFT JOIN pg_catalog.pg_class r ON r.oid = c.confrelid
    LEFT JOIN pg_catalog.pg_namespace rn ON rn.oid = r.relnamespace
    WHERE o.relkind = 'r'

    UNION ALL
    SELECT 'index', o.relname,
           jsonb_build_object(
               'method', am.amname, 'unique', i.indisunique, 'primary', i.indisprimary,
               'valid', i.indisvalid, 'ready', i.indisready, 'immediate', i.indimmediate,
               'nulls_not_distinct', i.indnullsnotdistinct,
               'keys', (SELECT jsonb_agg(pg_catalog.pg_get_indexdef(i.indexrelid, k, false) ORDER BY k)
                        FROM generate_series(1, i.indnatts) k),
               'key_count', i.indnkeyatts,
               'predicate', pg_catalog.pg_get_expr(i.indpred, i.indrelid, false)
           )
    FROM objects o
    JOIN pg_catalog.pg_index i ON i.indrelid = o.oid
    JOIN pg_catalog.pg_class ix ON ix.oid = i.indexrelid
    JOIN pg_catalog.pg_am am ON am.oid = ix.relam
    WHERE o.relkind = 'r'

    UNION ALL
    SELECT 'sequence', COALESCE(t.relname, ''),
           jsonb_build_object(
               'column', a.attname, 'type', pg_catalog.format_type(s.seqtypid, NULL),
               'start', s.seqstart, 'increment', s.seqincrement, 'minimum', s.seqmin,
               'maximum', s.seqmax, 'cache', s.seqcache, 'cycle', s.seqcycle
           )
    FROM objects o
    JOIN pg_catalog.pg_sequence s ON s.seqrelid = o.oid
    LEFT JOIN pg_catalog.pg_depend d ON d.classid = 'pg_class'::regclass AND d.objid = o.oid
         AND d.refclassid = 'pg_class'::regclass AND d.deptype IN ('a', 'i')
    LEFT JOIN pg_catalog.pg_class t ON t.oid = d.refobjid
    LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid = d.refobjid AND a.attnum = d.refobjsubid
    WHERE o.relkind = 'S'

    UNION ALL
    SELECT 'trigger', o.relname, jsonb_build_object('name', t.tgname)
    FROM objects o JOIN pg_catalog.pg_trigger t ON t.tgrelid = o.oid
    WHERE NOT t.tgisinternal

    UNION ALL
    SELECT 'foreign_key_trigger', o.relname,
           jsonb_build_object(
               'constraint_table', ct.relname, 'type', t.tgtype,
               'enabled', t.tgenabled::text, 'deferrable', t.tgdeferrable,
               'initially_deferred', t.tginitdeferred,
               'constraint_columns', (SELECT jsonb_agg(a.attname ORDER BY k.ordinal)
                           FROM unnest(c.conkey) WITH ORDINALITY k(attnum, ordinal)
                           JOIN pg_catalog.pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum)
           )
    FROM objects o JOIN pg_catalog.pg_trigger t ON t.tgrelid = o.oid
    JOIN pg_catalog.pg_constraint c ON c.oid = t.tgconstraint AND c.contype = 'f'
    JOIN pg_catalog.pg_class ct ON ct.oid = c.conrelid
    WHERE t.tgisinternal

    UNION ALL
    SELECT 'routine', '', jsonb_build_object('name', p.proname, 'kind', p.prokind::text)
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public'

    UNION ALL
    SELECT 'policy', o.relname, jsonb_build_object('name', p.polname)
    FROM objects o JOIN pg_catalog.pg_policy p ON p.polrelid = o.oid

    UNION ALL
    SELECT 'inheritance', o.relname, jsonb_build_object('parent', p.relname)
    FROM objects o JOIN pg_catalog.pg_inherits i ON i.inhrelid = o.oid
    JOIN pg_catalog.pg_class p ON p.oid = i.inhparent

    UNION ALL
    SELECT 'user_type', '', jsonb_build_object('name', t.typname, 'kind', t.typtype::text)
    FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
    WHERE n.nspname = 'public' AND t.typrelid = 0 AND t.typelem = 0

    UNION ALL
    SELECT 'user_collation', '', jsonb_build_object('name', c.collname)
    FROM pg_catalog.pg_collation c JOIN pg_catalog.pg_namespace n ON n.oid = c.collnamespace
    WHERE n.nspname = 'public'
)
SELECT kind, owner, detail::text FROM facts ORDER BY kind, owner, detail::text
