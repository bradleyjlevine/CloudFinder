import argparse
import json
import requests
import os
from io import BytesIO
from collections import defaultdict
from zipfile import ZipFile
from bs4 import BeautifulSoup
import ipaddress
import sys

sys.tracebacklimit=1

# Get command-line options
parser=argparse.ArgumentParser(description="CloudFinder, for finding IPs in the Clouds.  CloudFinder 2023.")

parser.add_argument(
    "ip",
    help="IP address to find.",
)

parser.add_argument(
    "-p",
    "--pull",
    choices = ["all","none","gcp","aws","azure","oci","linode","digital_ocean","cloudflare","flastly","github","akamai","ibm","o365","zscaler"],
    dest = "update",
    action= "store",
    default = "all",
    help = "You must select one of the choices. (default = all)")

args = parser.parse_args()

clouds = defaultdict()

def get_gcp():
    urls = {"google": "https://www.gstatic.com/ipranges/goog.json", 
            "gcp": "https://www.gstatic.com/ipranges/cloud.json"}
    
    for url in urls.keys():
        with requests.Session() as session:
            j = session.get(
                url = urls[url]
            )

            if 200 >= j.status_code < 300:
                j = json.loads(j.text)

            if url == "google" and "prefixes" in j.keys():
                clouds.update({url:defaultdict()})

                for ip in j["prefixes"]:
                    if "ipv4Prefix" in ip.keys():
                        clouds[url].update({ip["ipv4Prefix"]:{
                                         "description": "IP Address Owned by Google",
                                         "region": None,
                                         "service": None,
                                         "type": 4}
                                    })
                    elif "ipv6Prefix" in ip.keys():
                        clouds[url].update({ip["ipv6Prefix"]:{
                                         "description": "IP Address Owned by Google",
                                         "region": None,
                                         "service": None,
                                         "type": 6}
                                    })
            elif url == "gcp":
                clouds.update({url:defaultdict()})

                for ip in j["prefixes"]:
                    if "ipv4Prefix" in ip.keys():
                        clouds[url].update({ip["ipv4Prefix"]:{
                                         "description": "IP Address Used by GCP",
                                         "region": ip["scope"],
                                         "service": ip["service"],
                                         "type": 4}
                                    })
                    elif "ipv6Prefix" in ip.keys():
                        clouds[url].update({ip["ipv6Prefix"]:{
                                         "description": "IP Address Used by GCP",
                                         "region": ip["scope"],
                                         "service": ip["service"],
                                         "type": 6}
                                    })
                        
def get_aws():
    urls = {"aws": "https://ip-ranges.amazonaws.com/ip-ranges.json"}
    
    for url in urls.keys():
        with requests.Session() as session:
            j = session.get(
                url = urls[url]
            )

            if 200 >= j.status_code < 300:
                j = json.loads(j.text)

            if url == "aws" and "prefixes" in j.keys():
                clouds.update({url:defaultdict()})

                for ip in j["prefixes"]:
                    if "ip_prefix" in ip.keys():
                        clouds[url].update({ip["ip_prefix"]:{
                                         "description": "IP Address Used by AWS",
                                         "region": ip["region"],
                                         "service": ip["service"],
                                         "type": 4}
                                    })
                        
def get_cloudflare():
    urls = {"cloudflare-v4": "https://www.cloudflare.com/ips-v4/#",
            "cloudflare-v6": "https://www.cloudflare.com/ips-v6/#"}
    
    for url in urls.keys():
        with requests.Session() as session:
            t = session.get(
                url = urls[url]
            )

            if 200 >= t.status_code < 300:
                t = t.text

            if url == "cloudflare-v4":
                clouds.update({url:defaultdict()})

                for ip in t.split("\n"):
                    clouds[url].update({ip.strip():{
                                        "description": "IP Address Used by Cloudflare",
                                        "region": None,
                                        "service": None,
                                        "type": 4}
                                })
            elif url == "cloudflare-v6":
                clouds.update({url:defaultdict()})

                for ip in t.split("\n"):
                    clouds[url].update({ip.strip():{
                                        "description": "IP Address Used by Cloudflare",
                                        "region": None,
                                        "service": None,
                                        "type": 6}
                                })

def get_fastly():
    urls = {"fastly": "https://api.fastly.com/public-ip-list"}
    
    for url in urls.keys():
        with requests.Session() as session:
            j = session.get(
                url = urls[url]
            )

            if 200 >= j.status_code < 300:
                j = json.loads(j.text)

            if url == "fastly" and "addresses" in j.keys():
                clouds.update({url:defaultdict()})

                for ip in j["addresses"]:
                    clouds[url].update({ip:{
                                        "description": "IP Address Used by Fastly",
                                        "region": None,
                                        "service": None,
                                        "type": 4}
                                })
            
            if url == "fastly" and "ipv6_addresses" in j.keys():
                if url not in clouds.keys():
                    clouds.update({url:defaultdict()})

                for ip in j["ipv6_addresses"]:
                    clouds[url].update({ip:{
                                        "description": "IP Address Used by Fastly",
                                        "region": None,
                                        "service": None,
                                        "type": 6}
                                }) 
                    
def get_oci():
    urls = {"oci": "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json"}

    for url in urls.keys():
        with requests.Session() as session:
            j = session.get(
                url=urls[url]
            )

            if 200 >= j.status_code < 300:
                j = json.loads(j.text)

            if url =="oci" and "regions" in j.keys():
                clouds.update({url:defaultdict()})

                for n in range(len(j["regions"])):
                    if "region" in j["regions"][n].keys() and "cidrs" in j["regions"][n].keys():
                        for m in range(len(j["regions"][n]["cidrs"])):
                            clouds[url].update({j["regions"][n]["cidrs"][m]["cidr"]:{
                                    "description": "IP Address Used by Oracle for OCI or other services.",
                                    "region": j["regions"][n]["region"],
                                    "service": j["regions"][n]["cidrs"][m]["tags"],
                                    "type": None}
                            }) 
                    
def get_linode():
    urls = {"linode": "https://geoip.linode.com/"}

    for url in urls.keys():
            with requests.Session() as session:
                t = session.get(
                    url = urls[url]
                )

                if 200 >= t.status_code < 300:
                    t = t.text

                if url == "linode":
                    clouds.update({url:defaultdict()})

                lines = t.split("\n")
                lines = lines[3:]

                for line in lines:
                    line = line.strip()

                    if len(line)>4:
                        cols = line.split(",")
                        
                        clouds[url].update({cols[0]:{
                                            "description": "IP Address Used by Linode",
                                            "region": ",".join(cols[2:4]),
                                            "service": None,
                                            "type": None}
                                    })
                        
def get_github():
    urls = {"github": "https://api.github.com/meta"}
    
    for url in urls.keys():
        with requests.Session() as session:
            j = session.get(
                url = urls[url]
            )

            if 200 >= j.status_code < 300:
                j = json.loads(j.text)

            if url == "github" and "hooks" in j.keys():
                clouds.update({url:defaultdict()})

                for service in j.keys():
                    if "ssh_keys" not in service and "ssh_key_fingerprints" not in service and "verifiable_password_authentication" not in service and "domains" not in service:
                        for ip in j[service]:
                            clouds[url].update({ip:{
                                                "description": "IP Address Used by Github",
                                                "region": None,
                                                "service": service,
                                                "type": None}
                                        })   

def get_digital_ocean():
    urls = {"digital_ocean": "https://digitalocean.com/geo/google.csv"}
    
    for url in urls.keys():
        with requests.Session() as session:
            t = session.get(
                url = urls[url],
                allow_redirects = True
            )

            if 200 >= t.status_code < 300:
                t = t.text

            lines = t.split("\n")

            clouds.update({url:defaultdict()})

            for line in lines:
                line = line.strip()
                cols = line.split(",")

                if len(line)>4:
                    clouds[url].update({cols[0]:{
                            "description": "IP Address Used by DigitalOcean",
                            "region": ",".join(cols[2:4]),
                            "service": None,
                            "type": None}
                    })   

def get_akamai():
    urls = {"akamai": "https://techdocs.akamai.com/property-manager/pdfs/akamai_ipv4_ipv6_CIDRs-txt.zip"}

    for url in urls.keys():
            with requests.Session() as session:
                z = session.get(
                    url = urls[url],
                    allow_redirects = True,
                    timeout=60,
                    headers={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0"}
                )

                if 200 >= z.status_code < 300:
                    clouds.update({url:defaultdict()})
                    with ZipFile(BytesIO(z.content)) as zipfile:
                        for file in zipfile.namelist():
                            if file == "akamai_ipv4_CIDRs.txt" or file == "akamai_ipv6_CIDRs.txt":
                                for line in zipfile.open(file).readlines():
                                    line=line.decode("utf-8").strip()
                                    if len(line)>4:
                                        clouds[url].update({line:{
                                                "description": "IP Address Used by Akamai",
                                                "region": None,
                                                "service": None,
                                                "type": None}
                                        })

def get_azure():
    url0 = "https://azservicetags.azurewebsites.net/"

    with requests.Session() as session:
        r = session.get(
            url=url0,
            timeout=60,
            headers={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0"}
        )

        if 200 >= r.status_code < 300:
            soup = BeautifulSoup(r.content, features="html.parser").body.table.tbody

            urls_pre = [tr.find_all("td")[2].a["href"] for tr in soup.find_all("tr")]
            
            urls = list()

            for url in urls_pre:
                if "Public" in url:
                    urls.append({"name": "azure-public", "url": url, "dname": "Public"})
                elif "China" in url:
                    urls.append({"name": "azure-china", "url" : url, "dname": "China" })
                elif "Government" in url:
                    urls.append({"name": "azure-gov", "url" : url, "dname": "Goverment"})
                elif "Germany" in url:
                    urls.append({"name": "azure-germany", "url": url, "dname": "Germany"})

            for url in urls:
                j = session.get(
                    url=url["url"],
                    timeout=60,
                    allow_redirects=True
                )

                if 200 >= j.status_code < 300:
                    clouds.update({url["name"]:defaultdict()})

                    j = json.loads(j.text)

                    if "cloud" in j.keys() and "values" in j.keys():
                        for m in range(len(j["values"])):
                            if "properties" in j["values"][m].keys():
                                for n in range(len(j["values"][m]["properties"]["addressPrefixes"])):
                                        clouds[url["name"]].update({j["values"][m]["properties"]["addressPrefixes"][n]:{
                                                "description": "IP Address Used by Azure " + url["dname"],
                                                "region": j["values"][m]["properties"]["region"],
                                                "service": j["values"][m]["properties"]["systemService"],
                                                "type": None}
                                        })

def get_ibm():
    urls = {"ibm": "https://raw.githubusercontent.com/dprosper/cidr-calculator/main/data/datacenters.json"}

    for url in urls.keys():
        with requests.Session() as session:
            j = session.get(
                url=urls[url],
                timeout=60,
            )

            if 200 >= j.status_code < 300:
                clouds.update({url:defaultdict()})

                j = json.loads(j.text)

                if "data_centers" in j.keys():
                    for n in range(len(j["data_centers"])):
                        for service in j["data_centers"][n].keys():
                            if "key" not in service and "name" not in service and "city" not in service and "state" not in service and "country" not in service and "geo_region" not in service:
                                if isinstance(j["data_centers"][n][service], list):
                                    for o in range(len(j["data_centers"][n][service])):
                                        if isinstance(j["data_centers"][n][service][o], dict) and "cidr_blocks" in j["data_centers"][n][service][o].keys():
                                            for ip in range(len(j["data_centers"][n][service][o]["cidr_blocks"])):
                                                if ipaddress.ip_interface(j["data_centers"][n][service][o]["cidr_blocks"][ip]).is_global:
                                                    clouds[url].update({j["data_centers"][n][service][o]["cidr_blocks"][ip]:{
                                                    "description": "IP Address Used by IBM Cloud",
                                                    "region": j["data_centers"][n]["name"],
                                                    "service": service,
                                                    "type": None}
                                                })

def get_o365():
    urls = {"o365": "https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7"}

    for url in urls.keys():
        with requests.Session() as session:
            j = session.get(
                url=urls[url],
                timeout=60
            )

            if 200 >= j.status_code < 300:
                j = json.loads(j.text)

                clouds.update({url:defaultdict()})

                for m in range(len(j)):
                    if "ips" in j[m].keys():
                        for n in range(len(j[m]["ips"])):
                            clouds[url].update({j[m]["ips"][n]:{
                                "description": "IP Address Used by Microsoft O365",
                                "region": None,
                                "service": ",".join([j[m]["serviceArea"], j[m]["serviceAreaDisplayName"]]),
                                "type": None}
                            })            

def get_zscaler():
    urls = {"zscaler": "https://config.zscaler.com/api/zscaler.net/cenr/json",
            "zscaler-hubs": "https://config.zscaler.com/api/zscaler.net/hubs/cidr/json/required"}

    for url in urls.keys():
        with requests.Session() as session:
            j = session.get(
                url=urls[url],
                timeout=60
            )

            if 200 >= j.status_code < 300:
                j = json.loads(j.text)

                clouds.update({url:defaultdict()})

                if "zscaler" in url and "zscaler.net" in j.keys():
                    for contient in j["zscaler.net"].keys():
                        for city in j["zscaler.net"][contient]:
                            for m in range(len(j["zscaler.net"][contient][city])):
                                if "range" in j["zscaler.net"][contient][city][m].keys():
                                    services = ""

                                    if len(j["zscaler.net"][contient][city][m]["vpn"]):
                                        services += "vpn"
                                    
                                    if len(j["zscaler.net"][contient][city][m]["gre"]):
                                        if len(services):
                                            services += ",gre"
                                        else:
                                            services += "gre"

                                    clouds[url].update({j["zscaler.net"][contient][city][m]["range"]:{
                                        "description": "IP Address Used by Zscaler",
                                        "region": ",".join([contient,city]),
                                        "service": services,
                                        "type": None}
                                    })
                if "zscaler-hubs" in url and "cloudName" in j.keys() and "hubPrefixes" in j.keys():
                    for ip in j["hubPrefixes"]:
                        clouds[url].update({ip:{
                            "description": "IP Address Used by Zscaler",
                            "region": None,
                            "service": "Used by various Zscaler services (i.e. ZIA Virtual Service Edge, ZIA Private Service Edge, Zscaler Client Connector, DLP)",
                            "type": None}
                            })

def lookup_ip(ip):
    for cloud in clouds.keys():
        for subnet in clouds[cloud].keys():
            subnet_addr = ipaddress.ip_network(subnet)
            ip_addr = ipaddress.ip_address(ip)

            if ip_addr in subnet_addr:
                print(json.dumps(clouds[cloud][subnet],
                                 indent = 4))

if __name__ == "__main__":
    CWD = os.getcwd()
    
    if not os.path.exists(os.path.join(CWD,"Clouds")):
        os.mkdir("Clouds")

    cache = [f for f in os.listdir(os.path.join(CWD,"Clouds")) if os.path.isfile(os.path.join(CWD,"Clouds",f)) ]
    
    for file in cache:
        cloud, ext = file.split(".")

        with open(os.path.join(CWD,"Clouds",file), "r") as file:
            if ext == "json":
                clouds.update(defaultdict(None, {cloud: json.load(file)}))
    
    if args.update == "all" or args.update == "gcp":
        get_gcp()
        
        if "google" in clouds.keys():
            with open(os.path.join(CWD,"Clouds","google.json"), "w") as file:
                json.dump(clouds["google"], file)
        
        if "gcp" in clouds.keys():
            with open(os.path.join(CWD,"Clouds","gcp.json"), "w") as file:
                json.dump(clouds["gcp"], file)

    if args.update == "all" or args.update == "aws":
        get_aws()

        if "aws" in clouds.keys():
            with open(os.path.join(CWD,"Clouds","aws.json"), "w") as file:
                json.dump(clouds["aws"], file)

    if args.update == "all" or args.update == "cloudflare":
        get_cloudflare()

        if "cloudflare-v4" in clouds.keys():
            with open(os.path.join(CWD,"Clouds","cloudflare-v4.json"), "w") as file:
                json.dump(clouds["cloudflare-v4"], file)

        if "cloudflare-v6" in clouds.keys():
            with open(os.path.join(CWD,"Clouds","cloudflare-v6.json"), "w") as file:
                json.dump(clouds["cloudflare-v6"], file)

    if args.update == "all" or args.update == "fastly":
        get_fastly()

        if "fastly" in clouds.keys():
            with open(os.path.join(CWD,"Clouds","fastly.json"), "w") as file:
                json.dump(clouds["fastly"], file)

    if args.update == "all" or args.update == "oci":
        get_oci()

        if "oci" in clouds.keys():
            with open(os.path.join(CWD,"Clouds","oci.json"), "w") as file:
                json.dump(clouds["oci"], file)

    if args.update == "all" or args.update == "linode":
        get_linode()

        if "linode" in clouds.keys():
            with open(os.path.join(CWD,"Clouds","linode.json"), "w") as file:
                json.dump(clouds["linode"], file)

    if args.update == "all" or args.update == "github":
        get_github()

        if "github" in clouds.keys():
            with open(os.path.join(CWD,"Clouds","github.json"), "w") as file:
                json.dump(clouds["github"], file)

    if args.update == "all" or args.update == "digital_ocean":
        get_digital_ocean()

        if "digital_ocean" in clouds.keys():
            with open(os.path.join(CWD,"Clouds","digital_ocean.json"), "w") as file:
                json.dump(clouds["digital_ocean"], file)

    if args.update == "all" or args.update == "akamai":
        get_akamai()

        if "akamai" in clouds.keys():
            with open(os.path.join(CWD,"Clouds","akamai.json"), "w") as file:
                json.dump(clouds["akamai"], file)

    if args.update == "all" or args.update == "azure":
        get_azure()

        if "azure-public" in clouds.keys():
            with open(os.path.join(CWD,"Clouds","azure-public.json"), "w") as file:
                json.dump(clouds["azure-public"], file)

        if "azure-china" in clouds.keys():
            with open(os.path.join(CWD,"Clouds","azure-china.json"), "w") as file:
                json.dump(clouds["azure-china"], file)

        if "azure-gov" in clouds.keys():
            with open(os.path.join(CWD,"Clouds","azure-gov.json"), "w") as file:
                json.dump(clouds["azure-gov"], file)

        if "azure-germany" in clouds.keys():
            with open(os.path.join(CWD,"Clouds","azure-germany.json"), "w") as file:
                json.dump(clouds["azure-germany"], file)

    if args.update == "all" or args.update == "ibm":
        get_ibm()

        if "ibm" in clouds.keys():
            with open(os.path.join(CWD,"Clouds","ibm.json"), "w") as file:
                json.dump(clouds["ibm"], file)

    if args.update == "all" or args.update == "o365":
        get_o365()

        if "o365" in clouds.keys():
            with open(os.path.join(CWD,"Clouds","o365.json"), "w") as file:
                json.dump(clouds["o365"], file)

    if args.update == "all" or args.update == "zscaler":
        get_zscaler()

        if "zscaler" in clouds.keys():
            with open(os.path.join(CWD,"Clouds","zscaler.json"), "w") as file:
                json.dump(clouds["zscaler"], file)
        
        if "zscaler-hubs" in clouds.keys():
            with open(os.path.join(CWD,"Clouds","zscaler-hubs.json"), "w") as file:
                json.dump(clouds["zscaler-hubs"], file)

    print("="*10 + "/" + args.ip + "\\" + "="*10)
    lookup_ip(args.ip)
    