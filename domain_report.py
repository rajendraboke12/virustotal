import requests
import yaml
from pprint import pprint

with open("/home/rajendra/Desktop/info.yml", 'r') as ymlfile:
    info = yaml.load(ymlfile)

def get_domain_report(inward_arr,var_arr):
    outward_arr=[]
    for i in inward_arr:
        if (var_arr[0] in i):
            domainname=i[var_arr[0]]
            url = 'https://www.virustotal.com/vtapi/v2/domain/report'
            params = {'apikey': info[0]["apikey"],'domain':domainname}
            response = requests.get(url, params=params)
            resp = response.json()
            try:
                if "detected_communicating_samples" in resp:
                    for j in resp["detected_communicating_samples"]:
                        try:
                            j["$name"]=info[0]["name"]
                        except:
                            j["$name"]= ""
                        try:
                            j["$phone_no"]=info[0]["phone_no"]
                        except:
                            j["$phone_no"]= 0
                        try:
                            j["$whois"]=resp["whois"]
                        except:
                            j["$whois"]=""
                        try:
                            j["$Alexa domain info"]=resp["Alexa domain info"]
                        except:
                            j["$Alexa domain info"]=""
                    outward_arr.append(resp["detected_communicating_samples"])
                else:
                    outward_arr.append([])

            except:
                pass
    return outward_arr

inward_arr = [{"domain":"netmonastery.com"},{"domain":"google.com"},{"domain":"gmail.com"}]
var_arr = ["domain"]
outward_arr=get_domain_report(inward_arr,var_arr)
pprint(outward_arr)
