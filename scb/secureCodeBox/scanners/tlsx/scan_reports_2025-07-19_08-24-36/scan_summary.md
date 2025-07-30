# Scan Summary Report
**Generated:** Sat Jul 19 08:24:49 UTC 2025
**Target:** google.com
**Scan Prefix:** mega-scan-2025-07-19_08-24-36

## Scan Results

| Scanner | Status | Findings | File |
|---------|--------|----------|------|

## MinIO Access

To access findings in MinIO:
1. Start port-forward: `kubectl port-forward -n securecodebox-system svc/securecodebox-operator-minio 9000:9000`
2. Configure mc client: `mc alias set myminio http://localhost:9000 securecodebox securecodebox123`
3. Browse bucket: `mc ls myminio/securecodebox/findings/`
