#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Sep 24 17:50:40 2018
Modified the 14/02/2022

@author: pfm, modified by Alistair Rameau
From: https://qbox.io/blog/building-an-elasticsearch-index-with-python
"""

import os
import csv, json
import time
from lxml import etree
from elasticsearch import Elasticsearch
from datetime import datetime

ES_HOST = {"host" : "localhost", "port" : 9200}
INDEX_NAME = 'flows-normalized'
ID_FIELD = 'id'

#Elasticsearch credentials
#On ajoute un timeout assez long et la possibilité de retry pour ne pas avoir de chargement interrompu, car le travail avec les VM s'est avéré assez gourmand en ressources.
es = Elasticsearch(["http://elastic:EKX7gbOuJ1lRrN0e5MTU@localhost:9200"], timeout=30, max_retries=10, retry_on_timeout=True)

#répertoire contenant les fichiers des flows, à mettre à jour avant de lancer le script
path =r"C:\Users\alist\OneDrive\Documents\Travail\IA Detection Intrusion\TP1\TRAIN_ENSIBS"
list_of_files=[]

#nombre de clés dans la normalisation
NUMBER_OF_KEYS = 15

#nombre de flows envoyés en même temps
BULK_SIZE = 10000

#liste des champs non traités par notre normalisation, normalement reste vide
CHAMPS_NON_TRAITES = []

#taille de notre vecteur normalisé
NORMALIZATION_ARRAY_LENGHT = 164

DICT_INFO = {
            "index": {
                "_index": INDEX_NAME
                }
            }

#transforme un dictionnaire en tableau "à plat"
def dictToArray(flowDict):
    normalArray = []
    for i in range(NUMBER_OF_KEYS):
        if isinstance(flowDict[str(i)], list):
            normalArray.extend(flowDict[str(i)])
        else:
            normalArray.append(flowDict[str(i)])
    return normalArray

#normalise un flow donné en une suite de flows
def normalization(flow):
    normalDict = {}
    normalDict["0"] = [float(0),float(0),float(0),float(0)]
    normalDict["1"] = float(0)
    normalDict["2"] = [float(0),float(0),float(0),float(0)]
    normalDict["3"] = float(0)
    normalDict["4"] = [float(0),float(0),float(0),float(0)]
    normalDict["5"] = float(0)
    normalDict["6"] = float(0)
    normalDict["7"] = float(0)
    normalDict["8"] = float(0)
    normalDict["9"] = float(0)
    normalDict["10"] = float(0)
    normalDict["11"] = [float(0),float(0),float(0),float(0),float(0)]
    normalDict["12"] = [float(0),float(0),float(0),float(0),float(0)]
    normalDict["13"] = [float(0)] * 64
    normalDict["14"] = [float(0)] * 64

    for key in flow.keys():
        if key == "source":
            split = flow[key].split(".")
            normalDict["0"] = [ float(split[0]), float(split[1]), float(split[2]), float(split[3]) ]
        elif key == "sourcePort":
            normalDict["1"] = float(flow[key])
        elif key == "destination":
            split = flow[key].split(".")
            normalDict["2"] = [ float(split[0]), float(split[1]), float(split[2]), float(split[3]) ]
        elif key == "destinationPort":
            normalDict["3"] = float(flow[key])
        elif key == "direction":
            directionArray = [float(0),float(0),float(0),float(0)]
            if flow[key] == "L2L":
                 directionArray = [float(1),float(0),float(0),float(0)]
            elif flow[key] == "L2R":
                 directionArray = [float(0),float(1),float(0),float(0)]
            elif flow[key] == "R2L":
                 directionArray = [float(0),float(0),float(1),float(0)]
            elif flow[key] == "R2R":
                 directionArray = [float(0),float(0),float(0),float(1)]
            normalDict["4"] = directionArray
        elif key == "startDateTime":
            timeArray = [float(0),float(0),float(0),float(0)]
            timeArray[0] = float(flow[key].timetuple().tm_wday)
            timeArray[1] = float(flow[key].timetuple().tm_hour)
            timeArray[2] = float(flow[key].timetuple().tm_min)
            timeArray[3] = float(flow[key].timetuple().tm_sec)
            normalDict["5"] = timeArray
        elif key == "stopDateTime":
            timeArray = [float(0),float(0),float(0),float(0)]
            timeArray[0] = float(flow[key].timetuple().tm_wday)
            timeArray[1] = float(flow[key].timetuple().tm_hour)
            timeArray[2] = float(flow[key].timetuple().tm_min)
            timeArray[3] = float(flow[key].timetuple().tm_sec)
            normalDict["6"] = timeArray
        elif key == "totalSourceBytes":
            normalDict["7"] = float(flow[key])
        elif key == "totalDestinationBytes":
            normalDict["8"] = float(flow[key])
        elif key == "totalSourcePackets":
            normalDict["9"] = float(flow[key])
        elif key == "totalDestinationPackets":
            normalDict["10"] = float(flow[key])
        elif key == "sourceTCPFlagsDescription":
            flags = [float(0),float(0),float(0),float(0),float(0)]
            if not("N/A" in flow[key]):
                if "F" in flow[key]:
                    flags[0] = float(1)
                if "S" in flow[key]:
                    flags[1] = float(1)
                if "P" in flow[key]:
                    flags[2] = float(1)
                if "A" in flow[key]:
                    flags[3] = float(1)
                if "R" in flow[key]:
                    flags[4] = float(1)
            normalDict["11"] = flags
        elif key == "destinationTCPFlagsDescription":
            flags = [float(0),float(0),float(0),float(0),float(0)]
            if not("N/A" in flow[key]):
                if "F" in flow[key]:
                    flags[0] = float(1)
                if "S" in flow[key]:
                    flags[1] = float(1)
                if "P" in flow[key]:
                    flags[2] = float(1)
                if "A" in flow[key]:
                    flags[3] = float(1)
                if "R" in flow[key]:
                    flags[4] = float(1)
            normalDict["12"] = flags
        elif key == "sourcePayloadAsBase64":
            charArray = [float(0)] * 64
            for charRaw in flow[key]:
                char = ord(charRaw)
                if char >= 65 and char <= 90:
                    charArray[char - 65] += 1
                elif char >= 97 and char <= 122:
                    charArray[char - 97 + 26] += 1
                elif char >= 48 and char <= 57:
                    charArray[char - 48 + 52] += 1
                elif char == '+':
                    charArray[62] += 1
                elif char == '/':
                    charArray[63] += 1
            normalDict["13"] = charArray
        elif key == "destinationPayloadAsBase64":
            charArray = [float(0)] * 64
            for charRaw in flow[key]:
                char = ord(charRaw)
                if char >= 65 and char <= 90:
                    charArray[char - 65] += 1
                elif char >= 97 and char <= 122:
                    charArray[char - 97 + 26] += 1
                elif char >= 48 and char <= 57:
                    charArray[char - 48 + 52] += 1
                elif char == '+':
                    charArray[62] += 1
                elif char == '/':
                    charArray[63] += 1
            normalDict["14"] = charArray
        elif key == "appName":
            pass
        elif key == "protocolName":
            pass
        elif key == "Tag":
            pass
        elif key == "origin":
            pass
        elif key == "sensorInterfaceId":
            pass
        elif key == "startTime":
            pass
        elif key == "sourcePayloadAsUTF":
            pass
        elif key == "destinationPayloadAsUTF":
            pass
        else:
            if key not in CHAMPS_NON_TRAITES:
                print("Un champ n'est pas traité : " + key)
                CHAMPS_NON_TRAITES.append(key)
    return dictToArray(normalDict)


#on supprime l'index si il existe déjà (et donc tous ses flows)
res = es.indices.delete(index = INDEX_NAME)

#on recréé l'index
request_body = {
    "settings" : {
        "number_of_shards": 1,
        "number_of_replicas": 0
    }
}
res = es.indices.create(index = INDEX_NAME, body = request_body)

#on vérifie la liste des fichiers dans le répertoire contenant les flows
for root, dirs, files in os.walk(path):
	for file in files:
		list_of_files.append(os.path.join(root,file))

print("Bulk indexing with size : " + str(BULK_SIZE))


for filename in list_of_files:
    print("Loading file: " + filename)
    tree = etree.parse(filename)
    root = tree.getroot()
    bulk_data = []
    send = 0
    #on prend chaque flows dans le fichier
    for flow in root:
        send += 1
        flowParse = {}
        #et on ajoute chacun de ses tags sous la forme appropriée à un dictionnaire
        for value in flow:
            if value.tag in ["totalDestinationBytes", "totalDestinationPackets", "totalSourceBytes", "totalSourcePackets"]:
                flowParse[value.tag] = int(value.text)
            elif value.tag in ["startDateTime", "stopDateTime"]:
                flowParse[value.tag] = datetime.strptime(value.text, "%Y-%m-%dT%H:%M:%S")
            elif value.text != None:
                flowParse[value.tag] = value.text
            else:
                flowParse[value.tag] = ""
        #on rajoute une information sur le fichier d'origine du flow
        flowParse["origin"] = flow.tag
        #on et calcule puis ajoute la charge au dictionnaire décrivant le flow
        flowParse["normalization"] = normalization(flowParse)
        #on ajoute le flow à la liste des flows à envoyer
        bulk_data.append(DICT_INFO)
        bulk_data.append(flowParse)
        if send > BULK_SIZE:
            #et on indexe par paquets de 10000 flows (par défaut)
            print("Bulk indexing...")
            res = es.bulk(index = INDEX_NAME, body = bulk_data, request_timeout=30)
            send = 0
            bulk_data = []

print("Champs non traités : ")
print(CHAMPS_NON_TRAITES)