import argparse
import json
import requests
import os
from collections import defaultdict
import ipaddress
import sys

sys.tracebacklimit=0

# Get command-line options
parser=argparse.ArgumentParser(description="CloudFinder, for finding IPs in the Clouds.  CloudFinder 2023.")

parser.add_argument(
    "ip",
    help="IP address to find.",
)

parser.add_argument(
    "-p",
    "--pull",
    choices = ["all","none","gcp","aws","azure","oci","linode","digital ocean","cloudflare","flastly"],
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

    print(args.ip)
    lookup_ip(args.ip)
    