#!/usr/bin/env python3
import os
import argparse
import datetime
from ..api_classes.doc_gen_api import OSSReportGen
from ..api_classes.voodoo import Voodoo

CONTACT_STR_LIST = [
    "Leon Denard\nRed Team Lead\nldenard@redteam-test.com"
]

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
        RT_CONTACT_DATA=CONTACT_STR_LIST,
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


if __name__ == "__main__":
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

