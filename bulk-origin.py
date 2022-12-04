#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Sep 24 17:50:40 2018

@author: pfm
From: https://qbox.io/blog/building-an-elasticsearch-index-with-python
"""

import csv, json
import timeit
from elasticsearch import Elasticsearch

ES_HOST = {"host" : "localhost", "port" : 9200}
INDEX_NAME = 'contacts'
TYPE_NAME = 'ab_entry'
ID_FIELD = 'id'

def sequential_indexing():
    es = Elasticsearch(hosts = [ES_HOST])
    if es.indices.exists(index = INDEX_NAME):
        print("deleting '%s' index..." % (INDEX_NAME))
        res = es.indices.delete(index = INDEX_NAME)
        print(" response: '%s'" % (res))
        
    # since we are running locally, use one shard and no replicas
    '''request_body = {
        "settings" : {
            "number_of_shards": 1,
            "number_of_replicas": 0
        }
    }
    print("creating '%s' index..." % (INDEX_NAME))
    res = es.indices.create(index = INDEX_NAME, body = request_body)
    print(" response: '%s'" % (res))'''

    # Read the data into a (elastic search) bulk structure
    with open("contacts.csv") as f:
        reader = csv.reader(f)
        header=next(reader) # skip header)
        header = [item.lower() for item in header]
        idx=0
        for row in reader:
            data_dict = {}
            for i in range(len(row)):
                data_dict[header[i]] = row[i]
            es.index(index=INDEX_NAME, doc_type=TYPE_NAME, id=idx, document=data_dict)
            idx+=1
    
    # sanity check
    res = es.search(index = INDEX_NAME, size=2, query={"match_all": {}})
    #print(" #response: '%s'" % (res))
    print("#results:", res['hits']['total'])
    
def bulk_indexing():
    # Read the data into a (elastic search) bulk structure
    with open("contacts.csv") as f:
        reader = csv.reader(f)
        header=next(reader) # skip header)
        header = [item.lower() for item in header]
        bulk_data = [] 
        for row in reader:
            data_dict = {}
            for i in range(len(row)):
                data_dict[header[i]] = row[i]
            op_dict = {
                "index": {
                    "_index": INDEX_NAME, 
                    "_type": TYPE_NAME, 
                    "_id": data_dict[ID_FIELD]
                }
            }
            bulk_data.append(op_dict)
            bulk_data.append(data_dict)
    
    
    # create ES client, create index (delete it first if it exists)
    es = Elasticsearch(hosts = [ES_HOST])
    if es.indices.exists(index = INDEX_NAME):
        print("deleting '%s' index..." % (INDEX_NAME))
        res = es.indices.delete(index = INDEX_NAME)
        print(" response: '%s'" % (res))
        
    
    # bulk index the data (10k objects)
    print("bulk indexing...")
    res = es.bulk(index = INDEX_NAME, body = bulk_data, refresh = True)
    
    # sanity check
    res = es.search(index = INDEX_NAME, size=2, query={"match_all": {}})
    #print(" #response: '%s'" % (res))
    
    print("#results:", res['hits']['total'])


elapsedTime_SI = timeit.timeit('sequential_indexing()', globals=globals(), number=1)
elapsedTime_BI = timeit.timeit('bulk_indexing()', globals=globals(), number=1)

print('Elapsed time for sequential indexing:', elapsedTime_SI)
print('Elapsed time for bulk indexing:',elapsedTime_BI)
