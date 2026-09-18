# Network — exposed services

Inventory exposed TCP services on the target's resolved public address using Nmap.

Use nmap with top_ports 100, max_rate 20 and service_detection true for the initial pass.
A larger top_ports up to 1000 is available for justified follow-up. No UDP or arbitrary scripts.
Separate open/closed/filtered states; mention host timeout and filtered-port uncertainty.
Publish observed ports and services to peers. Fingerprints and open ports alone are informational.
Hostnames on shared hosting/CDNs may resolve to shared infrastructure: explain attribution limits.
Do not probe unrelated resolved hosts or treat a banner as confirmation of a vulnerability.
