from datetime import datetime
import time
import json
from elasticsearch import Elasticsearch
from elasticsearch import helpers


print(".___________________________________________________________.")
print("|                                                           |")
print("|       OneFirewall Alliance LTD - Malicious IP export      |")
print("|                            v0.6                           |")
print("|___________________________________________________________|")


seconds_to_read = 60*10 # Read 10 Min range
es = Elasticsearch(['http://localhost:9200'])

def get_data_poc_traffic():
    delay_1 = 60*5 # Buffer
    time_now = datetime.fromtimestamp(int(time.time()) - (delay_1))
    time_early = datetime.fromtimestamp(int(time.time()) - (delay_1 + seconds_to_read))

    time_now_str = time_now.strftime('%Y-%m-%dT%H:%M:%S.000Z')
    time_early_str = time_early.strftime('%Y-%m-%dT%H:%M:%S.000Z')

    print("From:\t", time_early_str)
    print("To:\t", time_now_str)


    res = es.search(
                        index="poc_traffic",
                        body=
                            {
                              "query": {
                                "bool": {
                                  "must": [
                                    {
                                      "range": {
                                          "ofa.live_score": {"gte": 100}
                                      }
                                    },
                                    {
                                      "range": {
                                        "@timestamp" : {
                                          "gte" : time_early_str,
                                          "lt" :  time_now_str
                                        }
                                      }
                                    }
                                  ]
                                }
                              }
                            }
                    )

    json_array = []
    for f in res['hits']['hits']:
        json_array.append(f)

    return json_array

def update_from_ofa(poc_traffic_array):
    arr = []
    with open('./malicious_traffic.csv', 'a') as a_writer:
        a_writer.write("IPv4,Live_Score\n")
        for poc_traffic_events in poc_traffic_array:
            a_writer.write(poc_traffic_events['_source']['ofa']['ip'] + "," + str(poc_traffic_events['_source']['ofa']['live_score']) + "\n")



json_array = get_data_poc_traffic()
update_from_ofa(json_array)
print(len(json_array))
