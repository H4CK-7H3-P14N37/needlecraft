<<<<<<< HEAD
# Needlecraft 
## git clone
```
git clone --recursive https://github.com/H4CK-7H3-P14N37/needlecraft.git
```
## setup
### NOTE: add API keys to exercism.example
```
nano scripts/exercism
```

## installation
```
make install
```

## run assessment
```
exercism scan ips_list.txt customer_name -u -l -p
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
salvare genreport /data/needlecraft/reports/test/test_attack_surface_ports_2024-03-19T17:24:41.020656.csv /data/needlecraft/reports/test/test_attack_surface_ciphers_2024-03-19T16:44:26.688714.csv /data/needlecraft/reports/test/test_attack_surface_certs_2024-03-19T16:44:26.688695.csv /data/needlecraft/reports/test Test /root/needlecraft/test_scope.txt
```

## OR

## import the results into the database
```
TBD
```
=======
# api_classes
This exists as a repo that can be used as a submodule to other repos to expand on basic, re-useable functions
>>>>>>> 07eece5bca281c2e7cf12291825e0fc6f571db99
