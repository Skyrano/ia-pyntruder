from elasticsearch import Elasticsearch
import requests


# getting the ElasticSearch (and Lucene) version
def getESVersion():
	es = Elasticsearch()
	print(es.info()['version'])
	return es.info()

# testing if the ElasticSearch local server is on
def testESServer():
    response = requests.get('http://localhost:9200') 
    if response.status_code != 200:
        print("ElasticSearch server not accessible!")
        return False
    else:
        print("so far so good!")
        return True
		
# Indexing some data
from elasticsearch import Elasticsearch
import requests
import json
import sys

es = Elasticsearch([{'host': 'localhost', 'port': 9200}])

# indexing an object (doc) stored as a dict in variable 'data', 
# with key value being 'idx'
def indexUBSComp(idx, data):
	response = requests.get('http://localhost:9200') 
	if response.status_code != 200: 
		print("ElasticSearch server not accessible")
	else:
		es.index(index='ubs-comp', doc_type='component', id=idx, document=data)
		print(idx, " indexed ")

# test is elastic search server is on
if testESServer():
    getESVersion()

# indexing some data (UBS component)
#
IUTV={'id':'iutv', 'cursus':'DUTINFO, DUTSTID, DUTGEA, DUTTC', \
	'site':'vannes', 'numb_etud':1250, 'univ':'ubs'} 	
indexUBSComp('iutv', IUTV)

IUTL={'id':'iutl', 'cursus':'DUTGTE, DUTHSE, DUTGIM, DUTQLIO, DUTGCGP', \
	'site':'lorient', 'numb_etud':800, 'univ':'ubs'} 	
indexUBSComp('iutl', IUTL)

# ...

ENSIBS={'id':'ensibs', 'cursus':'INGEINFO, INGECYBER, iINGEMECATRO, INGEGI',\
 'site':'vannes, lorient', 'numb_etud':450, 'univ':'ubs'} 	
indexUBSComp('ensibs', ENSIBS)
UFR_SSI={'id':'ufr-ssi', 'cursus':'LICINFO, LICMATH, LICPHY, LICELEC, LICBIO, MASTINFO, MATSMATH, MASTBIO, MASTELEC, MASTMECA', \
	'site':'vannes, lorient', 'numb_etud':2250, 'univ':'ubs'} 	
indexUBSComp('ufr-ssi', UFR_SSI)
UFR_LLSHS={'id':'ufr-llshs', 'cursus':'LICHIST, LICLITT, LICSCSOC, MASTHIST, MASTSCSOC, MASTLITT', 'site':'lorient', 'numb_etud':2300, 'univ':'ubs'} 	
indexUBSComp('ufr-llshs', UFR_LLSHS)
UFR_DSEG={'id':'ufr-dseg', 'cursus':'LICDROIT, LICGEST, LICMARK, LICECO, MASTDROIT, MASTECO, MASTMARK, MASTGEST', 'site':'vannes', 'numb_etud':2350, 'univ':'ubs'} 	
indexUBSComp('ufr-dseg', UFR_DSEG)


# search index 'index_name' for the request 'bdy'
def searchBdy(bdy, index_name='ubs-comp'):
	try:
		hits=es.search(index=index_name, query=bdy)
		H=hits['hits']['hits']
		print("# hits: ", len(H))
		for h in H:
			print('>> ',h['_score'], " ", h['_source']['id'], h['_source']['numb_etud'])
	except:
		print("error:", sys.exc_info()[0])
		hits=[]				
	return hits
	
# match all
print('match all')
bdy_match_all={"query": {"match_all": {}}}	
searchBdy(bdy_match_all)

# and
print('must (and)')
bdy_must={
    "bool": {
      "must": [
        { "match": { "site": "vannes" } },
        { "match": { "cursus": "DUTINFO, LICINFO, MASTINFO, INGEINFO" } } # or
      ]
    }
}
searchBdy(bdy_must)

# or
print('should (or)')
bdy_should={
    "bool": {
      "should": [
        { "match": { "site": "vannes" } },
        { "match": { "cursus": "DUTINFO, LICINFO, MASTINFO, INGEINFO" } }
      ]
    }
}
searchBdy(bdy_should)

# filter with range
print('filter with range')
bdy_filter_range={
    "bool": {
      "must": { "match_all": {} },
      "filter": {
        "range": {
          "numb_etud": {
            "gte": 500,
            "lte": 1500
          }
        }
      }
    }
}
searchBdy(bdy_filter_range)


# search index 'index_name' for the request of type aggregation 'agg'
def searchAgg(agg, index_name='ubs-comp'):
	try:
		hits=es.search(index=index_name, body=agg)
		H=hits['aggregations']
		A=H['group_by_site']['buckets']
		print("# aggs: ", len(A))
		for h in A:
			print('>> ',h['key'], " ", h['doc_count'])
	except:
		print("error:", sys.exc_info()[0])
		H=[]				
	return H

	
# aggregate
print('aggregate')
agg={
  "size": 0,
  "aggs": {
    "group_by_site": {
      "terms": {
        "field": "site.keyword"
      }
    }
  }
}
searchAgg(agg)
	
