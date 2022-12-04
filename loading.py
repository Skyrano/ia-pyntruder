from lxml import etree
from elasticsearch import Elasticsearch
import os

es = Elasticsearch(["http://elastic:EKX7gbOuJ1lRrN0e5MTU@localhost:9200"])

es.indices.delete(index='flows-normalized', ignore=[400, 404])

request_body = {
    "settings" : {
        "number_of_shards": 1,
        "number_of_replicas": 0
    }
}
res = es.indices.create(index = "flows-normalized", body = request_body)

filename =r"C:\Users\alist\OneDrive\Documents\Travail\IA Detection Intrusion\TP1\TRAIN_ENSIBS\TestbedThuJun17-1bisFlows.xml"
list_of_files=[]

for root, dirs, files in os.walk(path):
	for file in files:
		list_of_files.append(os.path.join(root,file))

for filename in list_of_files:
    print("Loading file: " + filename)
    tree = etree.parse(filename)
    root = tree.getroot()
    bulk_data = []
    i = 0
    send = 0
    for flow in root:
        i += 1
        send += 1
        flowParse = {}
        for value in flow:
            flowParse[value.tag] = value.text
            if value.tag in ["totalDestinationBytes", "totalDestinationPackets", "totalSourceBytes", "totalSourcePackets"]:
                flowParse[value.tag] = int(value.text)
        flowParse["origin"] = flow.tag
        op_dict = {
            "index": {
                "_index": INDEX_NAME        
                }
        }
        bulk_data.append(op_dict)
        bulk_data.append(flowParse)
        if send > 10000:
            # bulk index the data (10k objects)
            print("bulk indexing...")
            res = es.bulk(index = INDEX_NAME, body = bulk_data, refresh = True)
            send = 0
            bulk_data = []

