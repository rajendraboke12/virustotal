import requests
from pprint import pprint

def get_ip_report(inward_arr,var_arr):
    for i in inward_arr:
        if (var_arr[0] in i):
            ip=i[var_arr[0]]
            url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
            params = {'apikey':'6ef5a259eabefa228a1852942416eff30a84a56105c835d37f2f4acd8a93c5fd',
              'ip':ip}
            response = requests.get(url, params=params)
            resp = response.json()
            try:
                i["$country"]=resp["country"]
            except:
                i["$country"]= 0
    return inward_arr

inward_arr = [{"ip":"216.58.199.165"}]
var_arr = ["ip"]
inward_arr=get_ip_report(inward_arr,var_arr)
pprint(inward_arr)
