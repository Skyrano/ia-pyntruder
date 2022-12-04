from elasticsearch import Elasticsearch
import requests
import json
import matplotlib.pyplot as plt

es = Elasticsearch(["http://elastic:EKX7gbOuJ1lRrN0e5MTU@localhost:9200"])

index = "flows-newindex"
flows_packets = {}


body={
    "query": {
        "match_all": {}
    }
}
result = es.search(index=index, body=body, scroll='2m', size='10000')
sid = result['_scroll_id']
scroll_size = int(result['hits']['total']['value'])
print(scroll_size)

# Start scrolling
while (scroll_size > 0):
  print("Scrolling...")
  result = es.scroll(scroll_id = sid, scroll = '2m')
  # Update the scroll ID
  sid = result['_scroll_id']
  # Get the number of results that we returned in the last scroll
  scroll_size = len(result['hits']['hits'])
  print("scroll size: " + str(scroll_size))
  packetsNumber = 0
  for flow in result['hits']['hits']:
    packetsNumber = flow['_source']['totalSourcePackets']+flow['_source']['totalDestinationPackets']
    if packetsNumber in flows_packets.keys():
      flows_packets[packetsNumber] += 1
    else:
      flows_packets[packetsNumber] = 1

sortedDict={}
for i in sorted(flows_packets):
   sortedDict[i]=flows_packets[i]

fig, (ax1, ax2) = plt.subplots(2, 1)

ax1.loglog(list(sortedDict.keys()),list(sortedDict.values()))

ax2.plot(list(sortedDict.keys()),list(sortedDict.values()))

plt.tight_layout()
plt.show()