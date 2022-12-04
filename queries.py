from elasticsearch import Elasticsearch
import requests
import json
import sys

es = Elasticsearch(["http://elastic:EKX7gbOuJ1lRrN0e5MTU@localhost:9200"])

index = "flows-newindex"


# search index 'index_name' for the request 'bdy'
def searchBdy(bdy, index_name):
    try:
        hits=es.search(index=index_name, body=bdy)
        H=hits['hits']['hits']
        print("# hits: ", len(H))
        for h in H:
            print('>> ',h['_score'], " ", h['_id'])
    except:
        print("error:", sys.exc_info()[0])
        hits=[]
    return hits

# search index 'index_name' for the request of type aggregation 'agg'
def searchAgg(agg, index_name):
    try:
        hits=es.search(index=index_name, body=agg)
        H=hits['aggregations']
        A=H['aggregationQuery']['buckets']
        print("# aggs: ", len(A))
        for h in A:
            print('>> ',h['key'], " ", h['doc_count'])
    except:
        print("error:", sys.exc_info()[0])
        H=[]                
    return H


"""
# 1&3
print('Questions 1&3\n')
agg={
  "aggs": {
    "aggregationQuery": {
      "terms": {
        "field": "protocolName.keyword"
      }
    }
  }
}
searchAgg(agg, index)
"""

"""
# 2
print('Question 2 pour IP\n')
def match_Protocol(protocol):
    bdy_match_all={"query": {"match": {"protocolName" : protocol}}}    
    hits = searchBdy(bdy_match_all, index)
    return hits

match_Protocol("ip")
"""



# # 4
# print('Question 4\n')
# aggProtocols={
#   "aggs": {
#     "aggregationQuery": {
#       "terms": {
#         "field": "protocolName.keyword"
#       }
#     }
#   }
# }
# hits=es.search(index=index, body=aggProtocols)
# H=hits['aggregations']
# A=H['aggregationQuery']['buckets']
# for h in A:
#     print('Protocol:' + h["key"])
#     agg={
#       "size": 0,
#       "query": {
#         "match": {
#           "protocolName" : h["key"]
#           }
#       },
#       "aggs": {
#         "sourceQuery": {
#           "avg": {
#             "field": "totalSourceBytes"
#           }
#         },
#         "destinationQuery": {
#           "avg": {
#             "field": "totalDestinationBytes"
#           }
#         }
#       }
#     }
#     result = es.search(index=index, body=agg, scroll='1m', size='10000')
#     print("Source average: ")
#     print(result['aggregations']['sourceQuery']['value'])
#     print("Destination average: ")
#     print(result['aggregations']['destinationQuery']['value'])



# # Question 5
# print('Question 5\n')
# aggProtocols={
# "aggs": {
#     "aggregationQuery": {
#       "terms": {
#         "field": "protocolName.keyword"
#       }
#     }
#   }
# }
# hits=es.search(index=index, body=aggProtocols)
# H=hits['aggregations']
# A=H['aggregationQuery']['buckets']
# for h in A:
#     print('Protocol:' + h["key"])
#     agg={
#       "size": 0,
#       "query": {
#         "match": {
#           "protocolName" : h["key"]
#           }
#       },
#       "aggs": {
#         "sourceQuery": {
#           "sum": {
#             "field": "totalSourceBytes"
#           }
#         },
#         "destinationQuery": {
#           "sum": {
#             "field": "totalDestinationBytes"
#           }
#         }
#       }
#     }
#     result = es.search(index=index, body=agg, scroll='1m', size='10000')
#     print("Source sum total: ")
#     print(result['aggregations']['sourceQuery']['value'])
#     print("Destination sum total: ")
#     print(result['aggregations']['destinationQuery']['value'])

  
# # Question 6
# print('Question 6\n')
# aggProtocols={
# "aggs": {
#     "aggregationQuery": {
#       "terms": {
#         "field": "protocolName.keyword"
#       }
#     }
#   }
# }
# hits=es.search(index=index, body=aggProtocols)
# H=hits['aggregations']
# A=H['aggregationQuery']['buckets']
# for h in A:
#     print('Protocol:' + h["key"])
#     agg={
#       "size": 0,
#       "query": {
#         "match": {
#           "protocolName" : h["key"]
#           }
#       },
#       "aggs": {
#         "sourceQuery": {
#           "sum": {
#             "field": "totalSourcePackets"
#           }
#         },
#         "destinationQuery": {
#           "sum": {
#             "field": "totalDestinationPackets"
#           }
#         }
#       }
#     }
#     result = es.search(index=index, body=agg, scroll='1m', size='10000')
#     print("Source sum total of packets: ")
#     print(result['aggregations']['sourceQuery']['value'])
#     print("Destination sum total of packets: ")
#     print(result['aggregations']['destinationQuery']['value'])



# # Question 7 & 9
# print('Questions 7&9\n')
# agg={
#   "aggs": {
#     "aggregationQuery": {
#       "terms": {
#         "field": "appName.keyword"
#       }
#     }
#   }
# }
# searchAgg(agg, index)


# # Question 8
# print('Question 8 pour FTP\n')
# def match_Protocol(protocol):
#     bdy_match_all={"query": {"match": {"appName" : protocol}}}    
#     hits = searchBdy(bdy_match_all, index)
#     return hits

# match_Protocol("FTP")


# # 10
# print('Question 10\n')
# aggApps={
#   "aggs": {
#     "aggregationQuery": {
#       "terms": {
#         "field": "appName.keyword"
#       }
#     }
#   }
# }
# hits=es.search(index=index, body=aggApps)
# H=hits['aggregations']
# A=H['aggregationQuery']['buckets']
# for h in A:
#     print('App type: ' + h["key"])
#     agg={
#       "size": 0,
#       "query": {
#         "match": {
#           "appName" : h["key"]
#           }
#       },
#       "aggs": {
#         "sourceQuery": {
#           "avg": {
#             "field": "totalSourceBytes"
#           }
#         },
#         "destinationQuery": {
#           "avg": {
#             "field": "totalDestinationBytes"
#           }
#         }
#       }
#     }
#     result = es.search(index=index, body=agg, scroll='1m', size='10000')
#     print("Source average: ")
#     print(result['aggregations']['sourceQuery']['value'])
#     print("Destination average: ")
#     print(result['aggregations']['destinationQuery']['value'])


# # 11
# print('Question 11\n')
# aggApps={
#   "aggs": {
#     "aggregationQuery": {
#       "terms": {
#         "field": "appName.keyword"
#       }
#     }
#   }
# }
# hits=es.search(index=index, body=aggApps)
# H=hits['aggregations']
# A=H['aggregationQuery']['buckets']
# for h in A:
#     print('App type: ' + h["key"])
#     agg={
#       "size": 0,
#       "query": {
#         "match": {
#           "appName" : h["key"]
#           }
#       },
#       "aggs": {
#         "sourceQuery": {
#           "sum": {
#             "field": "totalSourceBytes"
#           }
#         },
#         "destinationQuery": {
#           "sum": {
#             "field": "totalDestinationBytes"
#           }
#         }
#       }
#     }
#     result = es.search(index=index, body=agg, scroll='1m', size='10000')
#     print("Source sum total: ")
#     print(result['aggregations']['sourceQuery']['value'])
#     print("Destination sum total: ")
#     print(result['aggregations']['destinationQuery']['value'])



# # 12
# print('Question 12\n')
# aggApps={
#   "aggs": {
#     "aggregationQuery": {
#       "terms": {
#         "field": "appName.keyword"
#       }
#     }
#   }
# }
# hits=es.search(index=index, body=aggApps)
# H=hits['aggregations']
# A=H['aggregationQuery']['buckets']
# for h in A:
#     print('App type: ' + h["key"])
#     agg={
#       "size": 0,
#       "query": {
#         "match": {
#           "appName" : h["key"]
#           }
#       },
#       "aggs": {
#         "sourceQuery": {
#           "sum": {
#             "field": "totalSourcePackets"
#           }
#         },
#         "destinationQuery": {
#           "sum": {
#             "field": "totalDestinationPackets"
#           }
#         }
#       }
#     }
#     result = es.search(index=index, body=agg, scroll='1m', size='10000')
#     print("Source sum total of packets: ")
#     print(result['aggregations']['sourceQuery']['value'])
#     print("Destination sum total of packets: ")
#     print(result['aggregations']['destinationQuery']['value'])
