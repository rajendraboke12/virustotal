import requests
from pprint import pprint

def fun1(inward_arr,var_arr):
    for i in inward_arr:
        if (var_arr[0] in i):
            domainname=i[var_arr[0]]
            url = 'https://www.virustotal.com/vtapi/v2/domain/report'
            params = {'apikey':'6ef5a259eabefa228a1852942416eff30a84a56105c835d37f2f4acd8a93c5fd',
              'domain':domainname}
            response = requests.get(url, params=params)
            resp = response.json()
            try:
                i["$whois"]=resp["whois"]
            except:
                i["$whois"]= 0
            try:
                i["$whois_timestamp"]=resp["whois_timestamp"]
            except:
                i["$whois_timestamp"]= 0
            try:
                i["$categories"]=resp["categories"]
            except:
                i["$categories"]= 0
            try:
                i["$response_code"]=resp["response_code"]
            except:
                i["$response_code"]= 0
    return inward_arr

inward_arr = [{"domain":"netmonastery.com"},{"domain":"google.com"},{"domain":"gmail.com"}]
var_arr = ["domain"]
inward_arr=fun1(inward_arr,var_arr)
pprint(inward_arr)
