#created by Alistair Rameau
from elasticsearch import Elasticsearch
import requests
import json
import sys
import random
import numpy as np
import matplotlib.pyplot as plt
from sklearn.datasets import load_digits
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import RandomForestClassifier
from sklearn import metrics
from random import *
from lxml import etree
from datetime import datetime

#Elasticsearch credentials
#On ajoute un timeout assez long et la possibilité de retry pour ne pas avoir de chargement interrompu, car le travail avec les VM s'est avéré assez gourmand en ressources.
es = Elasticsearch(["http://elastic:EKX7gbOuJ1lRrN0e5MTU@localhost:9200"], timeout=30, max_retries=10, retry_on_timeout=True)

#path vers les 2 fichiers contenant les flows inconnus, à mettre à jour avant de lancer le script
pathHTTPWeb =r"C:\Users\alist\OneDrive\Documents\Travail\IA Detection Intrusion\TP1\benchmark_HTTPWeb_test\benchmark_HTTPWeb_test.xml"
pathSSH =r"C:\Users\alist\OneDrive\Documents\Travail\IA Detection Intrusion\TP1\benchmark_SSH_test\benchmark_SSH_test.xml"

list_of_files=[]

INDEX = "flows-normalized"

#nombre de clés dans la normalisation
NUMBER_OF_KEYS = 15

#liste des champs non traités par notre normalisation, normalement reste vide
CHAMPS_NON_TRAITES = []

#tableaux d'entrainement des protocoles, divisés en 2 sous-tableaux (pour les flows d'attaques et les flows normaux)
HTTPWebTrainingArray = []
HTTPWebTrainingArray.append([])
HTTPWebTrainingArray.append([])

SSHTrainingArray = []
SSHTrainingArray.append([])
SSHTrainingArray.append([])


#transforme un tag (string) en un entier (1 pour une attaque, 0 pour un flow normal)
def tagToInt(tag):
    if tag == "Normal":
        return 0
    if tag == "Attack":
        return 1
    else:
        print("There was a problem while reading the tag value")
        return 0

#tranforme un tableau de tableaux en un tableau plat avec uniquement des valeurs brutes
def flattenArray(Array):
    retArray = []
    for array in Array:
        retArray.append(array[1])
    return retArray

#enregistre les résultats donnés dans un fichier de sortie
def resultsToFile(appname, method, version, predict, proba):
    res=dict()
    res['preds']= predict.tolist() # list of predicted labels, using numpy method
    res['probs']= list(proba)  # list of list of probas/scores (1 proba/score per class)
    res['names']=['RAMEAU','KERGOSIEN']     # list of team member names
    res['appName']= appname    # "SSH" ou "HTTPWeb"
    res['method']= method   # methode name
    res['version'] = version    # submission version number (1, 2 ou 3)
    filename = "RAMEAU_KERGOSIEN_"+appname+"_"+version+".res"
    print("opening file "+ filename)
    f = open(filename,"w")
    print("writing in file...")
    f.write(json.dumps(res))
    print("closing file...")
    f.close()

#normalise un fichier donné pour en extraire une liste de flows normalisés
def normalizeFlowFile(filename):
    print("Loading file: " + filename)
    normalizedArray = []
    tree = etree.parse(filename)
    root = tree.getroot()
    for flow in root:
        flowParse = {}
        for value in flow:
            if value.tag in ["totalDestinationBytes", "totalDestinationPackets", "totalSourceBytes", "totalSourcePackets"]:
                flowParse[value.tag] = int(value.text)
            elif value.tag in ["startDateTime", "stopDateTime"]:
                flowParse[value.tag] = datetime.strptime(value.text, "%Y-%m-%dT%H:%M:%S")
            elif value.text != None:
                flowParse[value.tag] = value.text
            else:
                flowParse[value.tag] = ""
        normalizedArray.append(normalization(flowParse))
    print("Champs non traités : ")
    print(CHAMPS_NON_TRAITES)
    return normalizedArray

def computeKNNClassifiers(TrainingArray, TestArray):
    print("Training the KNN classifier with " + str(len(TrainingArray[0])) + " values")
    clf_knn = KNeighborsClassifier(n_neighbors=1)
    clf_knn.fit(TrainingArray[0], TrainingArray[1])
    print("Predicting with the KNN classifier " + str(len(TestArray)) + " values")
    pred_knn = clf_knn.predict(TestArray)
    print("Predicting probabilities with the KNN classifier " + str(len(TestArray)) + " values")
    pred_proba_knn = clf_knn.predict_proba(TestArray)
    flat_pred_proba_knn = flattenArray(pred_proba_knn)
    print("\n")
    return pred_knn, flat_pred_proba_knn

def computeBayesClassifiers(TrainingArray, TestArray):
    print("Training the Bayes classifier with " + str(len(TrainingArray[0])) + " values")
    clf_nb = GaussianNB()
    clf_nb.fit(TrainingArray[0], TrainingArray[1])
    print("Predicting with the Bayes classifier " + str(len(TestArray)) + " values")
    pred_nb = clf_nb.predict(TestArray)
    print("Predicting probabilities with the Bayes classifier " + str(len(TestArray)) + " values")
    pred_proba_nb = clf_nb.predict_proba(TestArray)
    flat_pred_proba_nb = flattenArray(pred_proba_nb)
    print("\n")
    return pred_nb, flat_pred_proba_nb

def computeRandomForestClassifiers(TrainingArray, TestArray):
    print("Training the Random Forest classifier with " + str(len(TrainingArray[0])) + " values")
    clf_forest = RandomForestClassifier()
    clf_forest.fit(TrainingArray[0], TrainingArray[1])
    print("Predicting with the Random Forest classifier " + str(len(TestArray)) + " values")
    pred_forest = clf_forest.predict(TestArray)
    print("Predicting probabilities with the Random Forest classifier " + str(len(TestArray)) + " values")
    pred_proba_forest = clf_forest.predict_proba(TestArray)
    flat_pred_proba_forest = flattenArray(pred_proba_forest)
    print("\n")
    return pred_forest, flat_pred_proba_forest

def computeRandomForestClassifiersMaxedDepth(TrainingArray, TestArray):
    print("Training the Random Forest classifier with " + str(len(TrainingArray[0])) + " values")
    clf_forest = RandomForestClassifier(max_depth=3)
    clf_forest.fit(TrainingArray[0], TrainingArray[1])
    print("Predicting with the Random Forest classifier " + str(len(TestArray)) + " values")
    pred_forest = clf_forest.predict(TestArray)
    print("Predicting probabilities with the Random Forest classifier " + str(len(TestArray)) + " values")
    pred_proba_forest = clf_forest.predict_proba(TestArray)
    flat_pred_proba_forest = flattenArray(pred_proba_forest)
    print("\n")
    return pred_forest, flat_pred_proba_forest

#transforme un dictionnaire en un tableau
def dictToArray(flowDict):
    normalArray = []
    for i in range(NUMBER_OF_KEYS):
        if isinstance(flowDict[str(i)], list):
            normalArray.extend(flowDict[str(i)])
        else:
            normalArray.append(flowDict[str(i)])
    return normalArray

#normalise un flow donné en une suite de floats
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

#-------------------- HTTPWeb --------------------
print('App type: HTTPWeb')
query={
    "query": {
    "match": {
        "appName" : "HTTPWeb"
        }
    }
}
result = es.search(index=INDEX, body=query, scroll='2m', size='10000')
sid = result['_scroll_id']
scroll_size = int(result['hits']['total']['value'])
print("Total hits: " + str(scroll_size))

# Start scrolling
while scroll_size > 0 and len(result['hits']['hits']) > 0:
    scroll_size = len(result['hits']['hits'])
    print("Scrolling " + str(scroll_size) + " elements")
    for flow in result['hits']['hits']:
        HTTPWebTrainingArray[0].append(flow['_source']['normalization'])
        HTTPWebTrainingArray[1].append(tagToInt(flow['_source']['Tag']))
    # Update the scroll ID
    sid = result['_scroll_id']
    result = es.scroll(scroll_id = sid, scroll = '2m')


#-------------------- SSH --------------------
print('App type: SSH')
query={
    "query": {
    "match": {
        "appName" : "SSH"
        }
    }
}
result = es.search(index=INDEX, body=query, scroll='2m', size='10000')
sid = result['_scroll_id']
scroll_size = int(result['hits']['total']['value'])
print("Total hits: " + str(scroll_size))

# Start scrolling
while scroll_size > 0 and len(result['hits']['hits']) > 0:
    scroll_size = len(result['hits']['hits'])
    print("Scrolling " + str(scroll_size) + " elements")
    for flow in result['hits']['hits']:
        SSHTrainingArray[0].append(flow['_source']['normalization'])
        SSHTrainingArray[1].append(tagToInt(flow['_source']['Tag']))
    # Update the scroll ID
    sid = result['_scroll_id']
    result = es.scroll(scroll_id = sid, scroll = '2m')



print("\n----------HTTPWeb----------")
#first we normalise the flows of the file containing the unknown flows
unknownflowsHTTPWeb = normalizeFlowFile(pathHTTPWeb)
#then we try to predict those flows by the traning the differents algorithms with the values in the Elasticsearch database, with different algorithms
predict_forest_HTTPWeb, predict_proba_forest_HTTPWeb = computeRandomForestClassifiers(HTTPWebTrainingArray, unknownflowsHTTPWeb)
#and to finish we put the results in a file
resultsToFile("HTTPWeb", "Random_Forest", "1", predict_forest_HTTPWeb, predict_proba_forest_HTTPWeb)
#same for the others protocols
predict_forestmaxed_HTTPWeb, predict_proba_forestmaxed_HTTPWeb = computeRandomForestClassifiersMaxedDepth(HTTPWebTrainingArray, unknownflowsHTTPWeb)
resultsToFile("HTTPWeb", "Random_Forest", "2", predict_forestmaxed_HTTPWeb, predict_proba_forestmaxed_HTTPWeb)
predict_bayes_HTTPWeb, predict_proba_bayes_HTTPWeb = computeBayesClassifiers(HTTPWebTrainingArray, unknownflowsHTTPWeb)
resultsToFile("HTTPWeb", "Bayes_Gaussian_NB", "3", predict_bayes_HTTPWeb, predict_proba_bayes_HTTPWeb)
#Not using KNN for the final results because it takes too much time and resources
#predict_knn_HTTPWeb, predict_proba_knn_HTTPWeb = computeKNNClassifiers(HTTPWebTrainingArray, unknownflowsHTTPWeb)
#resultsToFile("HTTPWeb", "KNN", "1", predict_knn_HTTPWeb, predict_proba_knn_HTTPWeb)


print("\n----------SSH----------")
#first we normalise the flows of the file containing the unknown flows
unknownflowsSSH = normalizeFlowFile(pathSSH)
#then we try to predict those flows by the traning the differents algorithms with the values in the Elasticsearch database, with different algorithms
predict_forest_SSH, predict_proba_forest_SSH = computeRandomForestClassifiers(SSHTrainingArray, unknownflowsSSH)
#and to finish we put the results in a file
resultsToFile("SSH", "Random_Forest", "1", predict_forest_SSH, predict_proba_forest_SSH)
#same for the others protocols
predict_forestmaxed_SSH, predict_proba_forestmaxed_SSH = computeRandomForestClassifiersMaxedDepth(SSHTrainingArray, unknownflowsSSH)
resultsToFile("SSH", "Random_Forest", "2", predict_forestmaxed_SSH, predict_proba_forestmaxed_SSH)
predict_bayes_SSH, predict_proba_bayes_SSH = computeBayesClassifiers(SSHTrainingArray, unknownflowsSSH)
resultsToFile("SSH", "Bayes_Gaussian_NB", "3", predict_bayes_SSH, predict_proba_bayes_SSH)
