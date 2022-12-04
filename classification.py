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

#Elasticsearch credentials
#On ajoute un timeout assez long et la possibilité de retry pour ne pas avoir de chargement interrompu, car le travail avec les VM s'est avéré assez gourmand en ressources.
es = Elasticsearch(["http://elastic:EKX7gbOuJ1lRrN0e5MTU@localhost:9200"], timeout=30, max_retries=10, retry_on_timeout=True)

INDEX = "flows-normalized"

#tableaux contenant les différents flows en fonction de leur type (attaque ou normal) et de leur protocole
HTTPWebArrayAttack = []
HTTPWebArrayAttackChunks = []
HTTPWebArrayNormal = []
HTTPWebArrayNormalChunks = []

SSHArrayAttack = []
SSHArrayAttackChunks = []
SSHArrayNormal = []
SSHArrayNormalChunks = []

SMTPArrayAttack = []
SMTPArrayAttackChunks = []
SMTPArrayNormal = []
SMTPArrayNormalChunks = []

FTPArrayAttack = []
FTPArrayAttackChunks = []
FTPArrayNormal = []
FTPArrayNormalChunks = []


result_dict = {}

#tranforme un tableau de tableaux en un tableau plat avec uniquement des valeurs brutes
def flattenArray(Array):
    retArray = []
    for array in Array:
        retArray.append(array[1])
    return retArray

#divise un tableau en un tableau de tableaux (division en 5)
def divideInChunks(fullList):
    chunksize = len(fullList)//5
    chunksArray = []
    chunksArray.append(fullList[0:chunksize])
    chunksArray.append(fullList[chunksize:chunksize*2])
    chunksArray.append(fullList[chunksize*2:chunksize*3])
    chunksArray.append(fullList[chunksize*3:chunksize*4])
    chunksArray.append(fullList[chunksize*4:])
    return chunksArray

#fusionne les listes données un une seule
def mergeLists(listAttackChunks, listNormalChunks):
    listMerged = []
    for i in range(5):
        listMerged.append([[], []])
        for attackFlow in listAttackChunks[i]:
            listMerged[i][0].append(attackFlow)
            listMerged[i][1].append(1)
        for normalFlow in listNormalChunks[i]:
            listMerged[i][0].append(normalFlow)
            listMerged[i][1].append(0)
    return listMerged

def computeKNNClassifiers(TrainingArray):
    F1_knn = np.zeros(5)
    Prec_knn = np.zeros(5)
    Rec_knn = np.zeros(5)
    Auc_knn = np.zeros(5)
    print("Training the KNN classifier with " + str(len(TrainingArray[0][0])+len(TrainingArray[1][0])+len(TrainingArray[2][0])+len(TrainingArray[3][0])+len(TrainingArray[4][0])) + " values: ")
    for i in range(5):
        clf_knn = KNeighborsClassifier(n_neighbors=1)
        clf_knn.fit(TrainingArray[i][0]+TrainingArray[(i+1)%5][0]+TrainingArray[(i+2)%5][0]+TrainingArray[(i+3)%5][0], TrainingArray[i][1]+TrainingArray[(i+1)%5][1]+TrainingArray[(i+2)%5][1]+TrainingArray[(i+3)%5][1])
        print("Predicting with the KNN classifier")
        pred_knn = clf_knn.predict(TrainingArray[(i+4)%5][0])
        print("Predicting probabilities with the KNN classifier")
        pred_proba_knn = clf_knn.predict_proba(TrainingArray[(i+4)%5][0])
        print("Evaluation of the KNN classifier")
        F1_knn[i]=metrics.f1_score(TrainingArray[(i+4)%5][1], pred_knn, average='macro')
        Prec_knn[i]=metrics.precision_score(TrainingArray[(i+4)%5][1], pred_knn, average='macro')
        Rec_knn[i]=metrics.recall_score(TrainingArray[(i+4)%5][1], pred_knn, average='macro')
        roc = metrics.roc_curve(TrainingArray[(i+4)%5][1], flattenArray(pred_proba_knn))
        Auc_knn[i] = metrics.auc(roc[0], roc[1])
        print(str(i+1) + " - KNN F1=", F1_knn[i])
        print(str(i+1) + " - KNN PREC=", Prec_knn[i])
        print(str(i+1) + " - KNN REC=", Rec_knn[i])
        print(str(i+1) + " - KNN Roc AUC=", Auc_knn[i])
        plt.plot(roc[0], roc[1])
    print("Mean values: ")
    print("Mean KNN F1=", F1_knn.mean())
    print("Mean KNN PREC=", Prec_knn.mean())
    print("Mean KNN REC=", Rec_knn.mean())
    print("Mean KNN Roc AUC=", Auc_knn.mean())
    print("Variation of KNN F1=", np.std(F1_knn))
    print("Variation of KNN PREC=", np.std(Prec_knn))
    print("Variation of KNN REC=", np.std(Rec_knn))
    print("Variation of KNN Roc AUC=", np.std(Auc_knn))
    print("\n")
    plt.xlabel("False positive rate")
    plt.ylabel("True positive rate")
    plt.title("Roc curves for KNN classifier")
    plt.grid()
    plt.show()
    return [ F1_knn.mean(),  Prec_knn.mean(), Rec_knn.mean(), Auc_knn.mean() ]

def computeBayesClassifiers(TrainingArray):
    F1_nb = np.zeros(5)
    Prec_nb = np.zeros(5)
    Rec_nb = np.zeros(5)
    Auc_nb = np.zeros(5)
    print("Training the Bayes classifier with " + str(len(TrainingArray[0][0])+len(TrainingArray[1][0])+len(TrainingArray[2][0])+len(TrainingArray[3][0])+len(TrainingArray[4][0])) + " values: ")
    for i in range(5):
        clf_nb = GaussianNB()
        clf_nb.fit(TrainingArray[i][0]+TrainingArray[(i+1)%5][0]+TrainingArray[(i+2)%5][0]+TrainingArray[(i+3)%5][0], TrainingArray[i][1]+TrainingArray[(i+1)%5][1]+TrainingArray[(i+2)%5][1]+TrainingArray[(i+3)%5][1])
        print("Predicting with the Bayes classifier")
        pred_nb = clf_nb.predict(TrainingArray[(i+4)%5][0])
        print("Predicting probabilities with the KNN classifier")
        pred_proba_nb = clf_nb.predict_proba(TrainingArray[(i+4)%5][0])
        print("Evaluation of the Bayes classifier")
        F1_nb[i]=metrics.f1_score(TrainingArray[(i+4)%5][1], pred_nb, average='macro')
        Prec_nb[i]=metrics.precision_score(TrainingArray[(i+4)%5][1], pred_nb, average='macro')
        Rec_nb[i]=metrics.recall_score(TrainingArray[(i+4)%5][1], pred_nb, average='macro')
        roc = metrics.roc_curve(TrainingArray[(i+4)%5][1], flattenArray(pred_proba_nb))
        Auc_nb[i] = metrics.auc(roc[0], roc[1])
        print(str(i+1) + " - Bayes F1=", F1_nb[i])
        print(str(i+1) + " - Bayes PREC=", Prec_nb[i])
        print(str(i+1) + " - Bayes REC=", Rec_nb[i])
        print(str(i+1) + " - Bayes Roc AUC=", Auc_nb[i])
        plt.plot(roc[0], roc[1])
    print("Mean values: ")
    print("Mean Bayes F1=", F1_nb.mean())
    print("Mean Bayes PREC=", Prec_nb.mean())
    print("Mean Bayes REC=", Rec_nb.mean())
    print("Mean Bayes Roc AUC=", Auc_nb.mean())
    print("Variation of Bayes F1=", np.std(F1_nb))
    print("Variation of Bayes PREC=", np.std(Prec_nb))
    print("Variation of Bayes REC=", np.std(Rec_nb))
    print("Variation of Bayes Roc AUC=", np.std(Auc_nb))
    print("\n")
    plt.xlabel("False positive rate")
    plt.ylabel("True positive rate")
    plt.title("Roc curves for Gaussian NB classifier")
    plt.grid()
    plt.show()
    return [ F1_nb.mean(),  Prec_nb.mean(), Rec_nb.mean(), Auc_nb.mean() ]


def computeRandomForestClassifiers(TrainingArray):
    F1_forest = np.zeros(5)
    Prec_forest = np.zeros(5)
    Rec_forest = np.zeros(5)
    Auc_forest= np.zeros(5)
    print("Training the Random Forest classifier with " + str(len(TrainingArray[0][0])+len(TrainingArray[1][0])+len(TrainingArray[2][0])+len(TrainingArray[3][0])+len(TrainingArray[4][0])) + " values: ")
    for i in range(5):
        clf_forest = RandomForestClassifier()
        clf_forest.fit(TrainingArray[i][0]+TrainingArray[(i+1)%5][0]+TrainingArray[(i+2)%5][0]+TrainingArray[(i+3)%5][0], TrainingArray[i][1]+TrainingArray[(i+1)%5][1]+TrainingArray[(i+2)%5][1]+TrainingArray[(i+3)%5][1])
        print("Predicting with the Random Forest classifier")
        pred_forest = clf_forest.predict(TrainingArray[(i+4)%5][0])
        print("Predicting probabilities with the Random Forest classifier")
        pred_proba_forest = clf_forest.predict_proba(TrainingArray[(i+4)%5][0])
        print("Evaluation of the Random Forest classifier")
        F1_forest[i]=metrics.f1_score(TrainingArray[(i+4)%5][1], pred_forest, average='macro')
        Prec_forest[i]=metrics.precision_score(TrainingArray[(i+4)%5][1], pred_forest, average='macro')
        Rec_forest[i]=metrics.recall_score(TrainingArray[(i+4)%5][1], pred_forest, average='macro')
        roc = metrics.roc_curve(TrainingArray[(i+4)%5][1], flattenArray(pred_proba_forest))
        Auc_forest[i] = metrics.auc(roc[0], roc[1])
        print(str(i+1) + " - Random Forest F1=", F1_forest[i])
        print(str(i+1) + " - Random Forest PREC=", Prec_forest[i])
        print(str(i+1) + " - Random Forest REC=", Rec_forest[i])
        print(str(i+1) + " - Random Forest Roc AUC=", Auc_forest[i])
        plt.plot(roc[0], roc[1])
    print("Mean values: ")
    print("Mean Random Forest F1=", F1_forest.mean())
    print("Mean Random Forest PREC=", Prec_forest.mean())
    print("Mean Random Forest REC=", Rec_forest.mean())
    print("Mean Random Forest Roc AUC=", Auc_forest.mean())
    print("Variation of Random Forest F1=", np.std(F1_forest))
    print("Variation of Random Forest PREC=", np.std(Prec_forest))
    print("Variation of Random Forest REC=", np.std(Rec_forest))
    print("Variation of Random Forest Roc AUC=", np.std(Auc_forest))
    print("\n")
    plt.xlabel("False positive rate")
    plt.ylabel("True positive rate")
    plt.title("Roc curves for Random Forest classifier")
    plt.grid()
    plt.show()
    return [ F1_forest.mean(),  Prec_forest.mean(), Rec_forest.mean(), Auc_forest.mean() ]

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
        if flow['_source']['Tag'] == "Attack":
            HTTPWebArrayAttack.append(flow['_source']['normalization'])
        elif flow['_source']['Tag'] == "Normal":
            HTTPWebArrayNormal.append(flow['_source']['normalization'])

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
        if flow['_source']['Tag'] == "Attack":
            SSHArrayAttack.append(flow['_source']['normalization'])
        elif flow['_source']['Tag'] == "Normal":
            SSHArrayNormal.append(flow['_source']['normalization'])

    # Update the scroll ID
    sid = result['_scroll_id']
    result = es.scroll(scroll_id = sid, scroll = '2m')



#-------------------- SMTP --------------------
print('App type: SMTP')
query={
    "query": {
    "match": {
        "appName" : "SMTP"
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
        if flow['_source']['Tag'] == "Attack":
            SMTPArrayAttack.append(flow['_source']['normalization'])
        elif flow['_source']['Tag'] == "Normal":
            SMTPArrayNormal.append(flow['_source']['normalization'])

    # Update the scroll ID
    sid = result['_scroll_id']
    result = es.scroll(scroll_id = sid, scroll = '2m')    



#-------------------- FTP --------------------
print('App type: FTP')
query={
    "query": {
    "match": {
        "appName" : "FTP"
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
        if flow['_source']['Tag'] == "Attack":
            FTPArrayAttack.append(flow['_source']['normalization'])
        elif flow['_source']['Tag'] == "Normal":
            FTPArrayNormal.append(flow['_source']['normalization'])

    # Update the scroll ID
    sid = result['_scroll_id']
    result = es.scroll(scroll_id = sid, scroll = '2m')    


# on divise les listes en 5 pour avoir la même proportion flow attack/normal dans les listes d'apprentissage
print("Creating chunks from fetched arrays...")
#dividing attack flows
HTTPWebArrayAttackChunks = divideInChunks(HTTPWebArrayAttack)
SSHArrayAttackChunks = divideInChunks(SSHArrayAttack)
SMTPArrayAttackChunks = divideInChunks(SMTPArrayAttack)
FTPArrayAttackChunks = divideInChunks(FTPArrayAttack)

#dividing normal flows
HTTPWebArrayNormalChunks = divideInChunks(HTTPWebArrayNormal)
SSHArrayNormalChunks = divideInChunks(SSHArrayNormal)
SMTPArrayNormalChunks = divideInChunks(SMTPArrayNormal)
FTPArrayNormalChunks = divideInChunks(FTPArrayNormal)

#we can now merge our chunks in 5 lists for each protocol with each having the same proportion of normal and attack flows
#yeah sometimes I add comments in english, I don't know why myself
print("Merging chunks in proportional lists...\n")
HTTPWebTrainingArray = mergeLists(HTTPWebArrayAttackChunks, HTTPWebArrayNormalChunks)
SSHTrainingArray = mergeLists(SSHArrayAttackChunks, SSHArrayNormalChunks)
SMTPTrainingArray = mergeLists(SMTPArrayAttackChunks, SMTPArrayNormalChunks)
FTPTrainingArray = mergeLists(FTPArrayAttackChunks, FTPArrayNormalChunks)

print("\n----------HTTPWeb----------")
result_dict["KNN HTTPWeb"] = computeKNNClassifiers(HTTPWebTrainingArray)
result_dict["Bayes HTTPWeb"] = computeBayesClassifiers(HTTPWebTrainingArray)
result_dict["RandomForest HTTPWeb"] = computeRandomForestClassifiers(HTTPWebTrainingArray)
print()

print("\n----------SSH----------")
result_dict["KNN SSH"] = computeKNNClassifiers(SSHTrainingArray)
result_dict["Bayes SSH"] = computeBayesClassifiers(SSHTrainingArray)
result_dict["RandomForest SSH"] = computeRandomForestClassifiers(SSHTrainingArray) 
print()
exit()

print("\n----------SMTP----------")
result_dict["KNN SMTP"] = computeKNNClassifiers(SMTPTrainingArray)
result_dict["Bayes SMTP"] = computeBayesClassifiers(SMTPTrainingArray)
result_dict["RandomForest SMTP"] = computeRandomForestClassifiers(SMTPTrainingArray)
print()

print("\n----------FTP----------")
result_dict["KNN FTP"] = computeKNNClassifiers(FTPTrainingArray)
result_dict["Bayes FTP"] = computeBayesClassifiers(FTPTrainingArray)
result_dict["RandomForest FTP"] = computeRandomForestClassifiers(FTPTrainingArray)
print()

#Affichage final des différents résultats pour comparaison
print(result_dict)