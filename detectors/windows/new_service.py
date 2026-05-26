#==================================================================================Windows_Rule======================================================================================

#================================================================================New_Service_Rule====================================================================================

def detect_new_service(es, start_time):
    # The detective's empty box to hold the alarms
    alerts = []
    
    # Prepare the question for the database
    # We are looking for "Event 7045" (service installation) that happened recently
    # Update: Searching using the new Logstash field "normalized_event_id"
    query = {
        "query": {
            "bool": {
                "must": [{"match": {"normalized_event_id": "7045"}}],
                "filter": [{"range": {"@timestamp": {"gt": start_time}}}]
            }
        },
        "size": 10 # Maximum number of installed services at a time
    }
    
    try:
        # Sends Query To Elasticsearch To Find Winlogbeat Logs
        response = es.search(index="winlogbeat-*", body=query)
        hits = response['hits']['hits']
        # Read through each log one by one
        for hit in hits:
            
            # grabing the Windows data and the service name
            event_data = hit['_source'].get('winlog', {}).get('event_data', {})
            service_name = event_data.get('ServiceName', 'Unknown Service')
            
            # Build the alert message
            alert_obj = {
                 # We use the (hit['_id']) as the alert ID so we don't accidentally ring the alarm twice for the same event
                "id": hit['_id'],
                "message": f"[MEDIUM] New Service Installed: {service_name}"
            }
            alerts.append(alert_obj)
            
    except Exception as e:
        print(f"Error in New Service rule: {e}")
        
    return alerts
