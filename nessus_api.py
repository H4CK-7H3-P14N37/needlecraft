import re
import csv
import pandas
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class NessusScannerClass:
    def __init__(
            self, 
            url, 
            access_key, 
            secret_key
        ) -> None:
        self.access_key = access_key
        self.secret_key = secret_key
        self.base_url = url
        self.http_header = {
            "X-ApiKeys": "accessKey={}; secretKey={}".format(
                self.access_key, 
                self.secret_key
            )
        }
        if self.base_url.endswith("/"):
            self.base_url = self.base_url[:-1]
    
    def _get(self, url):
        response = requests.get("{}{}".format(self.base_url, url), headers=self.http_header, verify=False)
        return response.json()
    
    def _gettext(self, url):
        response = requests.get("{}{}".format(self.base_url, url), headers=self.http_header, verify=False)
        return response.text
    
    def _post(self, url, payload):
        response = requests.post("{}{}".format(self.base_url, url), headers=self.http_header, json=payload, verify=False)
        return response.json()
    
    def get_policies(self):
        response = self._get("/policies")
        return response
    
    def get_policy_by_name(self, policy_name):
        policies = self.get_policies()
        policy_list = policies.get('policies')
        if policy_list:
            policy_matches = [p for p in policy_list if p.get('name')==policy_name]
            if policy_matches:
                return policy_matches[0]
        return {}
    
    def get_scans(self):
        response = self._get("/scans")
        return response
    
    def get_scan_by_name(self, scan_name):
        scans = self.get_scans()
        scans_list = scans.get('scans')
        if scans_list:
            scans_matches = [p for p in scans_list if p.get('name')==scan_name]
            if scans_matches:
                return scans_matches[0]
        return {}
    
    def get_scan_by_id(self, scan_id):
        scan_response = self._get("/scans/{}".format(scan_id))
        return scan_response
    
    def get_scan_status(self, scan_id):
        scan_response = self.get_scan_by_id(scan_id)
        if scan_response:
            scan_info = scan_response.get('info')
            if scan_info:
                scan_status = scan_info.get('status')
                return scan_status
        return
    
    def get_folders(self):
        response = self._get("/folders")
        return response
    
    def get_folder_by_name(self, folder_name):
        folders = self.get_folders()
        folders_list = folders.get('folders')
        if folders_list:
            folder_matches = [p for p in folders_list if p.get('name')==folder_name]
            if folder_matches:
                return folder_matches[0]
        return {}
    
    def get_scan_templates(self):
        templates = self._get("/editor/scan/templates")
        return templates
    
    def get_scan_template_by_name(self, scan_template_name):
        scan_templates = self.get_scan_templates()
        scan_templates_list = scan_templates.get('templates')
        if scan_templates_list:
            template_matches = [p for p in scan_templates_list if p.get('name')==scan_template_name]
            if template_matches:
                return template_matches[0]
        return {}
    
    def get_scanners(self):
        scanners = self._get("/scanners")
        return scanners
    
    def get_scanner_by_name(self, scanner_name):
        scanners = self.get_scanners()
        scanners_list = scanners.get('scanners')
        if scanners_list:
            scanner_matches = [p for p in scanners_list if p.get('name')==scanner_name]
            if scanner_matches:
                return scanner_matches[0]
        return {}
    
    def create_folder(self, folder_name):
        response = self._post("/folders", {"name": folder_name})
        return response

    def create_scan(
        self, 
        template_uuid, 
        scan_name, 
        scan_type, 
        folder_id, 
        policy_id, 
        scanner_id, 
        host_ip_str):
        """
        stuff here
        """
        payload = {
            "uuid": template_uuid,
            "settings": {
                "name": scan_name,
                "description": "",
                "emails": "",
                "enabled": "true",
                "launch": scan_type,
                "folder_id": folder_id,
                "policy_id": policy_id,
                "scanner_id": scanner_id,
                "text_targets": host_ip_str,
                "agent_group_id": []
            }
        }
        create_response = self._post("/scans", payload)
        return create_response
    
    def get_scan_export_formats(self, scan_id):
        scan_format_types = self._get("/scans/{}/export/formats".format(scan_id))
        return scan_format_types
    
    def export_request(self, scan_id, format_type, history_id=None):
        payload = {
            "format": format_type,
            "reportContents.formattingOptions.page_breaks": True,
            "reportContents.hostSections.scan_information": True,
            "reportContents.hostSections.host_information": True,
            "reportContents.vulnerabilitySections.synopsis": True,
            "reportContents.vulnerabilitySections.description": True,
            "reportContents.vulnerabilitySections.see_also": True,
            "reportContents.vulnerabilitySections.solution": True,
            "reportContents.vulnerabilitySections.risk_factor": True,
            "reportContents.vulnerabilitySections.cvss3_base_score": True,
            "reportContents.vulnerabilitySections.cvss3_temporal_score": True,
            "reportContents.vulnerabilitySections.cvss_base_score": True,
            "reportContents.vulnerabilitySections.cvss_temporal_score": True,
            "reportContents.vulnerabilitySections.stig_severity": True,
            "reportContents.vulnerabilitySections.references": True,
            "reportContents.vulnerabilitySections.exploitable_with": True,
            "reportContents.vulnerabilitySections.plugin_information": True,
            "reportContents.vulnerabilitySections.plugin_output": True
        }
        uri = "/scans/{}/export".format(scan_id)
        if history_id:
            uri = "{}?={}".format(uri, history_id)
        export_request_response = self._post(uri, payload)
        return export_request_response
    
    def export_status(self, scan_id, file_id):
        export_status_response = self._get("/scans/{}/export/{}/status".format(scan_id, file_id))
        return export_status_response
    
    def export_download(self, scan_id, file_id):
        export_status_response = self._gettext("/scans/{}/export/{}/download".format(scan_id, file_id))
        return export_status_response
    
    def format_line_returns(self, desc_str):
        desc_str = desc_str.replace("\n\n", "||||").replace("\n"," ").replace("||||","\n\n").replace(" - ","\n - ").strip()
        desc_str = re.sub("[ ]{3,8}", " ", desc_str)
        return desc_str

    def export_csv_to_dict(self, csv_str):
        # Note: Nessus terminates lines with ^M or \r\n. So we give 
        # the csv module the dialect of excel so it understands
        reader_list = csv.DictReader(csv_str.split("\r\n"), dialect='excel')
        response = []
        for row in reader_list:
            # Note: we update the descriptions, etc. to
            # make the line returns make sense by forming
            # proper paragraphs and spacing. 
            desc = row.get("Description")
            if desc:
                new_desc = self.format_line_returns(desc)
                row.update({"Description":new_desc})
            synopsis = row.get("Synopsis")
            if synopsis:
                new_synopsis = self.format_line_returns(synopsis)
                row.update({"Synopsis":new_synopsis})
            plugin_output = row.get("Plugin Output")
            if plugin_output:
                new_plugin_output = self.format_line_returns(plugin_output)
                row.update({"Plugin Output":new_plugin_output})
            solution = row.get("Solution")
            if solution:
                new_solution = self.format_line_returns(solution)
                row.update({"Solution":new_solution})
            response.append(row)
        return response
    
    def export_excel_to_dict(self, excel_filename):
        df_dict = pandas.read_excel(excel_filename)
        reader_list = df_dict.to_dict('records')
        response = []
        for row in reader_list:
            # Note: we update the descriptions, etc. to
            # make the line returns make sense by forming
            # proper paragraphs and spacing. 
            desc = row.get("Description")
            if desc:
                if not str(desc) == 'nan':
                    new_desc = self.format_line_returns(str(desc))
                    row.update({"Description":new_desc})
            synopsis = row.get("Synopsis")
            if synopsis:
                if not str(synopsis) == 'nan':
                    new_synopsis = self.format_line_returns(str(synopsis))
                    row.update({"Synopsis":new_synopsis})
            plugin_output = row.get("Plugin Output")
            if plugin_output:
                if not str(plugin_output) == 'nan':
                    new_plugin_output = self.format_line_returns(str(plugin_output))
                    row.update({"Plugin Output":new_plugin_output})
            solution = row.get("Solution")
            if solution:
                if not str(solution) == 'nan':
                    new_solution = self.format_line_returns(str(solution))
                    row.update({"Solution":new_solution})
            response.append(row)
        return response
