# Needlecraft 
## git clone
```
git clone --recursive https://github.com/H4CK-7H3-P14N37/needlecraft.git
```
## setup
### add API keys to .env or add them to /etc/environment
```
cp env.example .env
nano .env
```

## installation
```
make install
```

## run assessment
```
exercism scan ips_list.txt report_for_name -u -l -p
```

## run just sslscan
```
exercism sslscan test_urls.txt test
```

## run a info search
```
exercism search 1.1.1.1
```

## report on attack surface
```
salvare genreport reports/test/test_attack_surface_ports_2024-03-19T17:24:41.020656.csv \
reports/test/test_attack_surface_ciphers_2024-03-19T16:44:26.688714.csv \
reports/test/test_attack_surface_certs_2024-03-19T16:44:26.688695.csv \
reports/test Test test_scope.txt
```

## OR

## import the results into the database
```
TBD
```
