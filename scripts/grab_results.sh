#!/usr/bin/env bash
# Grab aggressive RCE verification results from the Finland VPS
# Run this locally after the screen session finishes.
#
# Check if it's done first:
#   ssh finland "cat ~/cve_rce_status.txt"
#   ssh finland "screen -ls | grep cve-rce"

set -euo pipefail

FINLAND="finland"
REMOTE_DB="$FINLAND:~/helvetiscan/data/domains.db"
LOCAL_DB="data/domains.db"
DELTA_DB="data/cve_rce_delta.db"
REMOTE_LOG="$FINLAND:~/cve_rce_verify.log"

echo "=== Checking remote status ==="
ssh "$FINLAND" "cat ~/cve_rce_status.txt 2>/dev/null || echo 'Still running...'"
ssh "$FINLAND" "tail -3 ~/cve_rce_verify.log 2>/dev/null"

echo ""
echo "=== Fetching verification delta ==="
ssh "$FINLAND" "sqlite3 ~/helvetiscan/data/domains.db \".backup '$HOME/cve_rce_delta.db'\""
rsync -avz --progress "$FINLAND":~/cve_rce_delta.db "$DELTA_DB"

echo ""
echo "=== Merging into local DB ==="
sqlite3 "$LOCAL_DB" "
ATTACH DATABASE '$DELTA_DB' AS remote;

-- Upsert cve_verifications from remote
INSERT OR REPLACE INTO cve_verifications
SELECT * FROM remote.cve_verifications;

-- Show merge stats
SELECT 'merged' as action, changes() as rows;

DETACH DATABASE remote;
"

echo ""
echo "=== Post-merge stats ==="
sqlite3 "$LOCAL_DB" "
SELECT verified, COUNT(*) as cnt
FROM cve_verifications
WHERE cve_id IN (
  SELECT cve_id FROM cve_catalog
  WHERE severity = 'CRITICAL'
    AND technology IN ('wordpress','drupal','joomla','laravel','craft cms',
                       'redis','docker','exchange','magento','mongodb','rdp')
)
GROUP BY verified;
"

echo ""
echo "=== Top confirmed RCE domains ==="
sqlite3 "$LOCAL_DB" "
SELECT v.domain, v.cve_id, c.technology, c.cvss_score, v.check_method,
       substr(v.proof, 1, 80) as proof_preview
FROM cve_verifications v
JOIN cve_catalog c ON c.cve_id = v.cve_id
WHERE v.verified = 1
  AND c.severity = 'CRITICAL'
  AND c.technology IN ('wordpress','drupal','joomla','laravel','craft cms',
                       'redis','docker','exchange','magento','mongodb','rdp')
ORDER BY c.cvss_score DESC, v.domain
LIMIT 50;
"

echo ""
echo "=== Aggressive PoC confirmations ==="
sqlite3 "$LOCAL_DB" "
SELECT domain, cve_id, check_method, proof
FROM cve_verifications
WHERE verified = 1
  AND check_method IN ('apache_traversal_poc','php_cgi_source_poc',
                       'proftpd_site_cpfr','vsftpd_backdoor','docker_containers_probe')
ORDER BY cve_id, domain;
"

echo ""
echo "Done. Delta DB saved at $DELTA_DB"
