import requests
import yaml
from pprint import pprint
import os

path=os.environ["WORKDIR"]
with open(path+"/lookup_plugins/virustotal/info.yml", 'r') as ymlfile:
    info = yaml.load(ymlfile)

def get_domain_report(inward_arr,var_arr):
    for i in inward_arr:
        if (var_arr[0] in i):
            domainname=i[var_arr[0]]
            url = 'https://www.virustotal.com/vtapi/v2/domain/report'
            params = {'apikey': info["apikey"],'domain':domainname}
            response = requests.get(url, params=params)
            resp = response.json()
            try:
                i["$name"]=info["name"].upper()
            except:
                i["$name"]= ""
            try:
                i["$phone_no"]=info["phone_no"]
            except:
                i["$phone_no"]= 0
            try:
                i["$Alexa domain info"]=info["Alexa domain info"]
            except:
                i["$Alexa domain info"]= ""
            try:
                i["$BitDefender category"]=info["BitDefender category"]
            except:
                i["$BitDefender category"]= ""
            try:
                i["$BitDefender domain info"]=info["BitDefender domain info"]
            except:
                i["$BitDefender domain info"]= ""
            try:
                i["$Dr.Web category"]=info["Dr.Web category"]
            except:
                i["$Dr.Web category"]= ""
            for j in resp:
                if(isinstance(resp[j], unicode)):
                    i["$"+str(j)]=resp[j]
    outward_arr=inward_arr
    return outward_arr

inward_arr = [{"domain":"netmonastery.com"},{"domain":"google.com"},{"domain":"gmail.com"}]
var_arr = ["domain"]
outward_arr=get_domain_report(inward_arr,var_arr)
pprint(outward_arr)
