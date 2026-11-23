-- Статусы разных инструментов для каждого коммита.
SELECT p.slug, rev.revision, r.tool, o.status, count(o.id) AS total
FROM projects p
JOIN revisions rev ON rev.project_id = p.id
JOIN runs r ON r.revision_id = rev.id
LEFT JOIN observations o ON o.run_id = r.id
GROUP BY p.slug, rev.revision, r.tool, o.status
ORDER BY p.slug, rev.revision, r.tool, o.status;

-- Проверенные области без замечаний, только для полных прогонов.
SELECT r.id AS run_id, o.code, o.scope, count(f.fingerprint) AS findings_total
FROM runs r
JOIN observations o ON o.run_id = r.id
LEFT JOIN findings f ON f.observation_id = o.id
WHERE r.errors = 0 AND o.status = 'pass'
GROUP BY r.id, o.id
HAVING count(f.fingerprint) = 0
ORDER BY r.id, o.code, o.scope;

-- Отдельные попытки с неполным покрытием.
SELECT r.id AS run_id, p.slug, rev.revision, r.tool, r.errors, o.code, o.scope
FROM runs r
JOIN revisions rev ON rev.id = r.revision_id
JOIN projects p ON p.id = rev.project_id
LEFT JOIN observations o ON o.run_id = r.id AND o.status = 'unavailable'
WHERE r.errors > 0 OR o.id IS NOT NULL
ORDER BY r.id, o.code, o.scope;
