def detect_suspicious_powershell(es, start_time):
    alerts = []
   
    query = {
        "query": {
            "bool": {
                "must": [
                    {"match": {"winlog.event_id": 4688}},
                    {"query_string": {"query": "*powershell* AND (*-enc* OR *iex*)"}}
                ],
                "filter": [{"range": {"@timestamp": {"gt": start_time}}}]
            }
        },
        "size": 10
    }
    
    try:
        response = es.search(index="winlogbeat-*", body=query)
        for hit in response['hits']['hits']:
            event_data = hit['_source'].get('winlog', {}).get('event_data', {})
            cmd = event_data.get('CommandLine', 'Hidden Command')
            
            alert_obj = {
                "id": hit['_id'],
                "message": f"[HIGH] Suspicious PowerShell command: {cmd}"
            }
            alerts.append(alert_obj)
            
    except Exception as e:
        print(f"Error in PowerShell rule: {e}")
        
    return alerts
