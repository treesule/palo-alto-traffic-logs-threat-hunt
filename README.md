# palo-alto-traffic-logs-threat-hunt

<b>Longest duration</b>

index=pan dest_zone=OUTSIDE src_zone!=OUTSIDE  
| lookup microsoft_ip_range.csv ip as dest_ip OUTPUT matched | search matched = none 
| lookup webscraping-servers.csv webscrapers as src_ip OUTPUT matched | search matched = none 
| lookup sourcenat-ips.csv device-ip as src_ip OUTPUT matched | search matched = none 
| lookup aws-ip-ranges.csv aws-ipaddress as All_Traffic.dest OUTPUT aws-service , aws-region | search NOT aws-service IN (AMAZON,S3)
| lookup google-ip-ranges.csv google-ipaddress as All_Traffic.dest OUTPUT google-service , google-region | search NOT google-service IN (Google Cloud)
| stats sum(duration) AS total_duration BY src_ip, dest_ip
| table src_ip dest_ip dest_location dest_name total_duration | sort -total_duration



![image](https://user-images.githubusercontent.com/78724598/182010478-d733551f-ec1c-426d-8e6f-d95c463dfaed.png)
