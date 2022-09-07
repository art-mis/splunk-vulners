from __future__ import absolute_import, division, print_function, unicode_literals

import os
import sys
import json
import csv
from requests import get, post

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.searchcommands import dispatch, EventingCommand, Configuration, Option, validators

from splunk.clilib import cli_common as cli

@Configuration()
class GetVulnersDataCommand(EventingCommand):

    token_name = 'vulners_api_token'
    token_realm = 'vulners_api_token_realm'
    
    osname_field = Option(require=True, validate=validators.Fieldname())
    osversion_field = Option(require=True, validate=validators.Fieldname()) 
    package_field = Option(require=True, validate=validators.Fieldname())
    host_field = Option(require=False, validate=validators.Fieldname(), default='host')
    vuln_field = Option(require=False, default='vulnId')
    score_field = Option(require=False, default='score')
    vulners_scorefield = Option(require=False, default='vulnersScore')
    title_field =  Option(require=False, default='title')
    severity_field = Option(require=False, default='severityText')

    cfg = cli.getConfStanza('vulners','setup')
    vulners_endpoint = cfg.get('endpoint')

    VULNERS_LINKS = {
        'pkgChecker': vulners_endpoint+'/api/v3/audit/audit/',
        'cveChecker': vulners_endpoint+'/api/v3/search/id/'
    }

    DEFAULT_HEADERS = {
        'User-agent': 'Vulners-Splunk-scan/0.0.5',
        'Content-type': 'application/json'
    }

    def get_encrypted_api_token(self, search_command):
       secrets = search_command.service.storage_passwords
       return next(secret for secret in secrets if (secret.realm == self.token_realm and secret.username == self.token_name)).clear_password
    
    def get_audit_info(self, osname='', osversion='', packages=tuple(), token=''):
        """
        Get OS name, its version and a list of installed packages and perform the actual request to Vulners API.
        """

        payload = {
            'os': osname,
            'version': osversion,
            'package': packages,
            'apiKey': token
        }

        res = post(self.VULNERS_LINKS.get('pkgChecker'), headers=self.DEFAULT_HEADERS, data=json.dumps(payload))

        if res.status_code == 200 and res.json().get('result') == "OK":
            result = dict()
            all_cve = list()
            for pkg, info in res.json()['data'].get('packages', {}).items():
                cvelist = []
                for vuln_name, desc in info.items():
                    cvelist.append(sum(map(lambda x: x.get("cvelist", []), desc), []))
                cvelist = list(set(sum(cvelist, [])))
                if len(cvelist):
                    result[pkg] = {"cve": cvelist}
                    all_cve += cvelist
            result['all_cve'] = all_cve
            return result
        else:
            return {}

    def get_cve_info(self, cve_list=[], token=''):
        cve_info = dict()
        payload = {
            'id': cve_list,
            'apiKey': token
        }

        res = post(self.VULNERS_LINKS.get('cveChecker'), headers=self.DEFAULT_HEADERS, data=json.dumps(payload))

        if res.status_code == 200 and res.json().get('result') == "OK":
            res = res.json()
            for cve, info in res['data'].get('documents', {}).items():
                score = info.get('cvss', {}).get('score')
                vulnersScore = info.get('enchantments', {}).get('vulnersScore')
                title = info.get('title')
                severity = info.get('cvss2', {}).get('severity')
                cve_info[cve] = {
                    "score": score,
                    "vulnersScore": vulnersScore,
                    "title": title,
                    "severityText": severity
                }
            return cve_info
        else:
            return {}

    def transform(self, records):

        sys.path.append(os.path.join(os.environ['SPLUNK_HOME'],'etc','apps','SA-VSCode','bin'))
        import splunk_debug as dbg
        dbg.enable_debugging(port=5000,timeout=25)
        dbg.set_breakpoint()

        hostfield = self.host_field
        osfield = self.osname_field
        osversionfield = self.osversion_field
        packagefield = self.package_field
        vulnfield = self.vuln_field
        scorefield = self.score_field
        v_scorefield = self.vulners_scorefield
        titlefield =  self.title_field
        severityfield = self.severity_field

        token = self.get_encrypted_api_token(self)

        SPLUNK_HOME = os.environ['SPLUNK_HOME']

        LOG_FILENAME = os.path.join(SPLUNK_HOME, 'var', 'log', 'vulners-lookup', 'VulnersLookup.log')
        LOG_DIRNAME = os.path.dirname(LOG_FILENAME)
        if not os.path.exists(LOG_DIRNAME):
            os.makedirs(LOG_DIRNAME)

        VULNERS_CSV = os.path.join(SPLUNK_HOME, 'etc', 'apps', 'vulners-lookup', 'lookups', 'vulners.csv')
        LOOKUP_DIRNAME = os.path.dirname(VULNERS_CSV)
        if not os.path.exists(LOOKUP_DIRNAME):
            os.makedirs(LOOKUP_DIRNAME)

        csv_lookup_outfile = open(VULNERS_CSV, 'w')
        csv_header = [ hostfield,osfield,osversionfield,packagefield,vulnfield,scorefield,v_scorefield,titlefield,severityfield ]
        w = csv.DictWriter(csv_lookup_outfile, fieldnames=csv_header)
        w.writeheader()

        content_list = list()
        for record in records:
            content_list.append(record)

        hosts = dict()
        os_version_packages = dict()
        for request in content_list:
            hostname, osname, osversion, package = request[hostfield], request[osfield], request[osversionfield], request[packagefield]
            if hostname not in hosts:
                hosts[hostname] = {osfield: osname, osversionfield: osversion, packagefield: []}
            hosts[hostname][packagefield].append(package)
            if osname not in os_version_packages:
                os_version_packages[osname] = dict()
            if osversion not in os_version_packages[osname]:
                os_version_packages[osname][osversion] = {packagefield: []}
            if package not in os_version_packages[osname][osversion][packagefield]:
                os_version_packages[osname][osversion][packagefield].append(package)
        
        all_cve = list()

        for osname, os_details in os_version_packages.items():
            for osversion, package_info in os_details.items():
                packages = package_info[packagefield]
                res = self.get_audit_info(osname, osversion, packages, token)
                all_cve += res.get('all_cve', [])
                res.pop('all_cve')
                os_version_packages[osname][osversion]['res'] = res

        for hostname, host_info in hosts.items():
            osname = host_info[osfield]
            osversion = host_info[osversionfield]
            packages = host_info[packagefield]

        cve_info = self.get_cve_info(all_cve, token)
        for hostname, host_info in hosts.items():
            osname = host_info[osfield]
            osversion = host_info[osversionfield]
            for pkg in host_info[packagefield]:
                if pkg not in os_version_packages[osname][osversion]['res']:
                    result = {
                        hostfield: hostname,
                        osfield: osname,
                        osversionfield: osversion,
                        packagefield: pkg,
                        vulnfield: "",
                        scorefield: "",
                        v_scorefield: "",
                        titlefield: "",
                        severityfield: ""

                    }
                    yield result
                    w.writerow(result)
                else:
                    for pkg_res_name,pkg_res_data in os_version_packages[osname][osversion]['res'].items():
                        if pkg == pkg_res_name:
                            cvelist = pkg_res_data.get("cve", [])
                            for cve in cvelist:
                                result = {
                                    hostfield: hostname,
                                    osfield: osname,
                                    osversionfield: osversion,
                                    packagefield: pkg
                                }
                                result[vulnfield] = cve
                                result[scorefield] = cve_info[cve].get('score')
                                result[v_scorefield] = cve_info[cve].get('vulnersScore')
                                result[titlefield] = cve_info[cve].get('title')
                                result[severityfield] = cve_info[cve].get('severityText')
                                yield result
                                w.writerow(result)

        csv_lookup_outfile.close()

dispatch(GetVulnersDataCommand, sys.argv, sys.stdin, sys.stdout, __name__)