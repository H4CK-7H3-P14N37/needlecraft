#!/usr/bin/env python3
import os
import json
import base64
import datetime
import argparse
from needlecraft.voodoo import Voodoo
from needlecraft.mail_api import MailAPI
from needlecraft.pincushion import PinCushionScan,PinCushionHTTP,PinCushionSSLSCAN,PinCushionInternetDB,PinCushionRecon
from needlecraft.doc_gen_api import OSSReportGen
from needlecraft.config import load_config,get_api_key,save_api_key

def zip_folder(input_folder_path):
    voodoo_obj = Voodoo()
    output_filename = input_folder_path.rstrip('/')
    filename = voodoo_obj.zip_dir(input_folder_path, output_filename)
    del voodoo_obj
    return filename

def print_search_report(search_term, short):
    voodoo_obj = Voodoo()
    results = voodoo_obj.ascii_results_table(search_term, short)
    del voodoo_obj
    return results

def print_scan_report(customer_name, cidr_list, udp, pdns, tls, json_output, urls, internetdb):
    filepath_list = []
    voodoo_obj = Voodoo()
    pincushion_obj = PinCushionScan(
        **{
            "CUSTOMER": customer_name
        }
    )
    (
        attack_surface_ports_filename,
        attack_surface_url_filename,
        open_ports_list,
        http_url_list
    ) = pincushion_obj.save_report(cidr_list, udp, pdns)
    screenshots_file_list = []
    tls_cipher_results_list = []
    certs_results_list = []
    if urls and http_url_list:
        pincushionhttp_obj = PinCushionHTTP(
            **{
                "CUSTOMER": customer_name
            }
        )
        screenshots_file_list = pincushionhttp_obj.run_screenshot_list(http_url_list)
        del pincushionhttp_obj
        if tls:
            pincushionsslscan_obj = PinCushionSSLSCAN(
                **{
                    "CUSTOMER": customer_name
                }
            )
            tls_cipher_results_list,certs_results_list,_,_ = pincushionsslscan_obj.run_sslscan_list(http_url_list)
            del pincushionsslscan_obj
    internetdb_table = None
    internetdb_results = []
    if internetdb:
        pincushioninternetdb_obj = PinCushionInternetDB(
            **{
                "CUSTOMER": customer_name
            }
        )
        with open(cidr_list, "r") as f:
            ip_list = f.read().splitlines()
        internetdb_results, internetdb_filename, internetdb_table = pincushioninternetdb_obj.mass_internetdb_lookup(ip_list)
        if internetdb_filename:
            filepath_list.append(internetdb_filename)
        del pincushioninternetdb_obj
    if attack_surface_ports_filename:
        filepath_list.append(attack_surface_ports_filename)
    if attack_surface_url_filename:
        filepath_list.append(attack_surface_url_filename)
    if screenshots_file_list:
        filepath_list.extend(screenshots_file_list)
    results = voodoo_obj.generate_ascii_table(f"{customer_name} - File Paths", "\n".join(filepath_list))
    if open_ports_list:
        results += voodoo_obj.generate_ascii_table(f"{customer_name} - Ports", "\n".join(open_ports_list))
    if http_url_list:
        results += voodoo_obj.generate_ascii_table(f"{customer_name} - URLs", "\n".join(http_url_list))
    if tls_cipher_results_list:
        results += voodoo_obj.generate_ascii_table(f"{customer_name} - SSL/TLS Cipher Issues", "\n".join(tls_cipher_results_list))
    if certs_results_list:
        results += voodoo_obj.generate_ascii_table(f"{customer_name} - Certificate Issues", "\n".join(certs_results_list))
    if internetdb_table:
        results += voodoo_obj.generate_ascii_table(f"{customer_name} - InternetDB", internetdb_table)
    zipped_results = zip_folder(pincushion_obj.base_dir)
    # json option here
    if json_output:
        tmp_dict = {}
        if open_ports_list:
            tmp_dict.update({
                "Ports Found": open_ports_list
            })
        if http_url_list:
            tmp_dict.update({
                "URLs Found": http_url_list
            })
        if tls_cipher_results_list:
            tmp_dict.update({
                "SSL/TLS/Cipher Issues": tls_cipher_results_list
            })
        if certs_results_list:
            tmp_dict.update({
                "Certificate Issues": certs_results_list
            })
        if screenshots_file_list:
            tmp_dict.update({
                "Site Screenshots": []
            })
            for screenshot_file in screenshots_file_list:
                with open(screenshot_file, "rb") as image_file:
                    encoded_string = base64.b64encode(image_file.read())
                    tmp_dict["Site Screenshots"].append({
                        os.path.basename(screenshot_file) : f"data:image/png;base64, {encoded_string.decode()}"
                    })
        if internetdb_results:
            tmp_dict.update({
                "InternetDB Results": internetdb_results
            })
        if tmp_dict:
            json_report_filename = os.path.join(
                pincushion_obj.base_dir,
                f"{pincushion_obj.customer_name}_json_report_{datetime.datetime.now().isoformat()}.json"
                )
            with open(json_report_filename, "w") as json_f:
                json.dump(tmp_dict, json_f, indent=4, ensure_ascii=True)


    del pincushion_obj
    del voodoo_obj
    return results,zipped_results

def screenshot_urls(customer_name, urls_filename):
    with open(urls_filename, "r", encoding="utf-8") as f:
        http_url_list = f.read().splitlines()
    urls_with_http = []
    if http_url_list:
        for url in http_url_list:
            urls_with_http.append(f"http://{url}/")
            urls_with_http.append(f"https://{url}/")

    screenshots_file_list = []
    if urls_with_http:
        pincushionhttp_obj = PinCushionHTTP(
            **{
                "CUSTOMER": customer_name
            }
        )
        screenshots_file_list = pincushionhttp_obj.run_screenshot_list(urls_with_http)
        del pincushionhttp_obj
    return screenshots_file_list

def print_sslscan_report(customer_name, domains_filename):
    with open(domains_filename, "r", encoding="utf-8") as f:
        http_url_list = f.read().splitlines()
    voodoo_obj = Voodoo()
    pincushionsslscan_obj = PinCushionSSLSCAN(
        **{
            "CUSTOMER": customer_name
        }
    )
    tls_cipher_results_list,certs_results_list,_,_ = pincushionsslscan_obj.run_sslscan_list(http_url_list)
    results = voodoo_obj.generate_ascii_table(f"{customer_name} - Bad Ciphers", "\n".join(tls_cipher_results_list)) 
    results += voodoo_obj.generate_ascii_table(f"{customer_name} - Bad Certs", "\n".join(certs_results_list)) 
    del voodoo_obj
    del pincushionsslscan_obj
    return results

def spongebob(text_here):
    voodoo_obj = Voodoo()
    response = voodoo_obj.spongemocktext(text_here)
    del voodoo_obj
    return response

def screencap_onion_site(onion_url, customer_name="tor_sites"):
    pincushionhttp_obj = PinCushionHTTP(
        **{
            "CUSTOMER": customer_name
        }
    )
    onion_site_filename = pincushionhttp_obj.get_screenshot(onion_url)
    del pincushionhttp_obj
    return onion_site_filename

def generate_openssh_config(ansible_ini, openssh_config, inigroups):
    if not inigroups:
        inigroups = [
            "work",
            "cloudblade",
            "cloudlab",
            "homelab",
            "homelab_other",
            "homelab-ts",
        ]
    else:
        inigroups = [g.strip() for g in args.inigroups.split(",")]
    voodoo_obj = Voodoo()
    filename = voodoo_obj.default_openssh_config(ansible_ini, inigroups, openssh_config)
    del voodoo_obj
    return filename

def mass_dnslookup(dns_filename):
    voodoo_obj = Voodoo()
    filename = voodoo_obj.get_dns_asn(dns_filename)
    del voodoo_obj
    return filename

def mass_internetdblookup(customer_name, idb_filename):
    pincushioninternetdb_obj = PinCushionInternetDB(
            **{
                "CUSTOMER": customer_name
            }
        )
    with open(idb_filename, "r") as f:
        cidr_list = f.read().splitlines()
    internetdb_results, internetdb_filename, internetdb_table = pincushioninternetdb_obj.mass_internetdb_lookup(cidr_list)
    voodoo_obj = Voodoo()
    internetdb_table = voodoo_obj.generate_ascii_table(f"{customer_name} - InternetDB", internetdb_table)
    internetdb_table += voodoo_obj.generate_ascii_table(f"{customer_name} - InternetDB File", f"\n{internetdb_filename}\n")
    del pincushioninternetdb_obj
    del voodoo_obj
    return internetdb_results, internetdb_filename, internetdb_table

def recon_whois_domain(customer_name, domain_name):
    pincushionrecon_obj = PinCushionRecon(
            **{
                "CUSTOMER": customer_name
            }
        )
    whois_poc_results, whois_poc_filename, whois_poc_table = pincushionrecon_obj.whois_poc_lookup(domain_name)
    voodoo_obj = Voodoo()
    whois_poc_table = voodoo_obj.generate_ascii_table(f"{customer_name} - Recon WHOIS PoC", f"\n{whois_poc_table}\n")
    whois_poc_table += voodoo_obj.generate_ascii_table(f"{customer_name} - Recon WHOIS PoC File", f"\n{whois_poc_filename}\n")
    del pincushionrecon_obj
    del voodoo_obj
    return whois_poc_results, whois_poc_filename, whois_poc_table

def email_results(customer, email_to, email_body, email_attachments):
    MAIL_USERNAME = os.environ.get('GMAIL_EMAIL')
    MAIL_PASSWORD = os.environ.get('GMAIL_APP_PASSWORD')
    mail_obj = MailAPI(
        mail_username = MAIL_USERNAME,
        mail_password = MAIL_PASSWORD
    )
    return mail_obj.send_mail(
        f"Exercism Results: {customer} - {datetime.datetime.now().isoformat()}",
        email_body.replace("\n","<br>"),
        MAIL_USERNAME,
        email_to.split(","),
        [],
        [],
        attachments=[email_attachments]
    )

def print_reportgen(kwargs):
    voodoo_obj = Voodoo()
    report_obj = OSSReportGen(save_dir=os.path.abspath(os.getcwd()))
    report_obj.COMPANY_LOGO = "/data/needlecraft/redteam.png"
    port_findings_list = voodoo_obj.open_csv_file_as_list(kwargs.get('attack_surface_ports_file'))
    reject_ports_list = []
    open_ports_list = []
    for port_str in port_findings_list:
        if "closed" in port_str:
            reject_ports_list.append(port_str)
        else:
            open_ports_list.append(port_str)

    cert_ssl_findings_list = voodoo_obj.open_csv_file_as_list(kwargs.get('attack_surface_ciphers_file'))
    cert_ssl_findings_list += voodoo_obj.open_csv_file_as_list(kwargs.get('attack_surface_certs_file'))
    screenshot_list = voodoo_obj.dirlist_pngs(kwargs.get('attack_surface_screenshots_folder'))
    scope_list = voodoo_obj.open_file(kwargs.get('scope_filename'))
    now = datetime.datetime.now()
    plaintext_port_list = [21,23,25,43,53,67,69,70,79,80,88,102,110,119,123,137,143,161,162,179,194,389,502,513,514,520,554,1755,1883,2000,2404,3000,3005,3074,3671,3702,5060,5094,5222,5683,5900,6667,6881,7070,9100,10110,20000,34980,44818,47808,49152]
    report_filename = report_obj.attack_surface_generate_doc(
        REPORT_FOR=kwargs.get('company_name'),
        TTTLE_MONTH_YEAR=now.strftime("%B %Y"),
        START_DATE=now.strftime("%d %B %Y"),
        END_DATE=now.strftime("%d %B %Y"),
        RT_CONTACT_DATA=kwargs.get("contact_info"),
        SCOPE_EXTERNAL=scope_list,
        port_protocol_desc_list=open_ports_list,
        reject_protocol_desc_list=reject_ports_list,
        screenshot_http_file_list=screenshot_list,
        ssl_cipher_list=cert_ssl_findings_list,
        plain_text_port_list=plaintext_port_list,
    )
    del report_obj
    del voodoo_obj
    return report_filename



def exercism():
    # top-level parser
    parser = argparse.ArgumentParser(prog='Needle Craft')
    subparsers = parser.add_subparsers(help='sub-command help')

    # search subcommands
    parser_search = subparsers.add_parser('search', help='search help')
    parser_search.add_argument('search_term', help='input an IP, email address, or CVE to retrieve data on.')
    parser_search.add_argument('-s', '--short',action='store_true', help='short version of output for ASN, PDNS, InternetDB')

    # scanning subcommands
    parser_scan = subparsers.add_parser('scan', help='scan help')
    parser_scan.add_argument('cidr_list', help='List of IP Addresses or CIDRs')
    parser_scan.add_argument('customer_name', help='Customer name')
    parser_scan.add_argument('-u', '--udp',action='store_true', help='enable udp scanning')
    parser_scan.add_argument('-l', '--urls',action='store_true', help='screenshot urls')
    parser_scan.add_argument('-p', '--pdns',action='store_true', help='enable pdns lookup')
    parser_scan.add_argument('-t', '--tls',action='store_true', help='enable tls scanning')
    parser_scan.add_argument('-j', '--json',action='store_true', help='enable json output')
    parser_scan.add_argument('-idb', '--internetdb', action='store_true', help='internetdb results output')
    parser_scan.add_argument('-e', '--email', required=False, help='email results output')
    

    # spongebob subcommands
    parser_meme = subparsers.add_parser('meme', help='meme help')
    parser_meme.add_argument('meme_text', help='meme text')

    # screencap tor site
    parser_screencap = subparsers.add_parser('tor', help='tor help')
    parser_screencap.add_argument('tor_url', help='tor url')

    # convert ansible ini to openssh config
    parser_ansible = subparsers.add_parser('ansible', help='ansible parser help')
    parser_ansible.add_argument('ansible_ini', help='ansible ini file')
    parser_ansible.add_argument('openssh_config', help='openssh config output file')
    parser_ansible.add_argument('-g','--groups', help="Groups separated by comma to generate", required=False)

    # mass dns lookup
    parser_dnslookup = subparsers.add_parser('dns', help='dnslookup help')
    parser_dnslookup.add_argument('dns_file', help='dns file')

    # screenshot urls
    parser_screenshot = subparsers.add_parser('screenshot', help='screenshot help')
    parser_screenshot.add_argument('screenshot_urls', help='screenshot urls file')
    parser_screenshot.add_argument('customer_name', help='Customer name')

    # sslscan 
    parser_sslscan = subparsers.add_parser('sslscan', help='sslscan help')
    parser_sslscan.add_argument('sslscan_list', help='sslscan file')
    parser_sslscan.add_argument('customer_name', help='Customer name')

    # internetdb 
    parser_internetdb = subparsers.add_parser('internetdb', help='internetdb help')
    parser_internetdb.add_argument('internetdb_list', help='internetdb file')
    parser_internetdb.add_argument('customer_name', help='Customer name')

    # recon 
    parser_recon = subparsers.add_parser('recon', help='recon help')
    parser_recon.add_argument('recon_domain', help='recon domain')
    parser_recon.add_argument('customer_name', help='Customer name')
    
    # arguments
    args = parser.parse_args()
    args_dict = args.__dict__
    # Left for debugging later
    # print(args_dict)

    # catch helps
    if args_dict.get('search_term')=="help" or args_dict.get('cidr_list')=="help" or not args_dict:
        parser.print_help()
    
    # process searches
    elif 'search_term' in args_dict.keys():
        print(print_search_report(args.search_term, args.short))

    # process scanning
    elif 'cidr_list' in args_dict.keys():
        text_report, zip_file_path = print_scan_report(args.customer_name, args.cidr_list, args.udp, args.pdns, args.tls, args.json, args.urls, args.internetdb)
        print(text_report)
        print(f"Compressed Results: {zip_file_path}")
        if args.email:
            email_results(args.customer_name, args.email, text_report, zip_file_path)

    
    # sslscan scanning
    elif 'sslscan_list' in args_dict.keys():
        print(print_sslscan_report(args.customer_name, args.sslscan_list))
    
    # spongebob test
    elif 'meme_text' in args_dict.keys():
        print(spongebob(args.meme_text))
    
    # screencap tor url
    elif 'tor_url' in args_dict.keys():
        print(screencap_onion_site(args.tor_url))
    
    # generates openssh config
    elif 'ansible_ini' in args_dict.keys():
        print(generate_openssh_config(args.ansible_ini, args.openssh_config, args.groups))
    
    # mass dns lookup
    elif 'dns_file' in args_dict.keys():
        print(mass_dnslookup(args.dns_file))
    
    elif 'screenshot_urls' in args_dict.keys():
        print(screenshot_urls(args.customer_name, args.screenshot_urls))
    
    elif "internetdb_list" in args_dict.keys():
        _, _, internetdb_table = mass_internetdblookup(args.customer_name, args.internetdb_list)
        print(internetdb_table)
    
    elif "recon_domain" in args_dict.keys():
        _, _, whois_poc_table = recon_whois_domain(args.customer_name, args.recon_domain)
        print(whois_poc_table)
        


def salvare():
    # top-level parser
    parser = argparse.ArgumentParser(prog='Needlecraft Salvare')
    subparsers = parser.add_subparsers(help='sub-command help')

    # search subcommands
    parser_search = subparsers.add_parser('genreport', help='genreport help')
    parser_search.add_argument(
        'attack_surface_ports_file',
        help='input file with ports found')
    parser_search.add_argument(
        'attack_surface_ciphers_file',
        help='input file with ciphers found')
    parser_search.add_argument(
        'attack_surface_certs_file',
        help='input file with certs found')
    parser_search.add_argument(
        'attack_surface_screenshots_folder',
        help='input folder path with pngs')
    parser_search.add_argument(
        'company_name', 
        help='friendly name of the company the report is for')
    parser_search.add_argument(
        'scope_filename',
        help='filename/path to the scope list')
    

    # arguments
    args = parser.parse_args()
    args_dict = args.__dict__
    # Left for debugging later
    # print(args_dict)

    # catch helps
    if args_dict.get('attack_surface_ports_file') == "help" or not args_dict:
        parser.print_help()

    if args_dict.get('attack_surface_ports_file') and args_dict.get('attack_surface_ciphers_file') and args_dict.get(
            'attack_surface_certs_file') and args_dict.get('attack_surface_screenshots_folder'):
        print_reportgen(args_dict)
    else:
        parser.print_help()

def config():
    parser = argparse.ArgumentParser(description="Needlecraft Config")
    parser.add_argument("env_name", help="Environmental variable name")
    parser.add_argument("env_value", help="API key to store")

    args = parser.parse_args()
    if args.env_name and args.env_value:
        save_api_key(args.env_name, args.env_value)
        print(f"Saved API key for {args.env_name}!")
    else:
        parser.print_help()