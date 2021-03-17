# combo-meal

A tool to nmap, sslscan/ssylze and nikto in one place.

Main feature is in sslscan/ssylze, where the result will have weak elements, such as TLSv1.0 and cipher suites using 3DES, outlined and ready to be used as evidence for an issue writeup. Data is pulled from various sites to identify weak cipher suites and stored in a local file. If an existing data file exists, data will not be pulled (for when on a network that requires a proxy to reach external sites). If data needs to be refreshed, delete file prior to running script. 