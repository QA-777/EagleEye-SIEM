#==================================================================================Windows_Rule=======================================================================================

#================================================================================Log_Cleared_Rule=====================================================================================
def detect_log_clear(es, start_time):
    # The detective's empty box to hold the alarms
    alerts = []
    
    # Prepare the question for the database
    # We are looking for "Event 1102, 104" (cleared log) that happened recently
    # Update: Searching using the new Logstash field "normalized_event_id" (String format)
    query = {
        "query": {
            "bool": {
                # We use "terms" (plural) because we are searching for a list of event IDs
                "must": [{"terms": {"normalized_event_id": ["1102", "104"]}}],
                "filter": [{"range": {"@timestamp": {"gt": start_time}}}]
            }
        },
        "size": 10 # Maximum number of logs at a time
    }
    
    try:
        # Sends Query To Elasticsearch To Find Winlogbeat Logs
        response = es.search(index="winlogbeat-*", body=query)
        
        # Read through each log one by one
        hits = response['hits']['hits']
        for hit in hits:
            
            # Check the time to see exactly when the logs get erased
            timestamp = hit['_source'].get('@timestamp')
            
            # Build the alert message
            alert_obj = {
                # We use the (hit['_id']) as the alert ID so we don't accidentally ring the alarm twice for the same event
                "id": hit['_id'],
                "message": f"[HIGH] Event Log Cleared at {timestamp}"
            }
            alerts.append(alert_obj)
            
    except Exception as e:
        print(f"Error in Log Clear rule: {e}")
        
    return alerts
