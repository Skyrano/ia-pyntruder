import json
import numpy as np
import glob, os, sys, ast

from matplotlib.backends.backend_pdf import PdfPages

LABS = [0,1]

NB_SSH = 295
NB_HTTPWeb = 191486
ERR = 0

def testTags(pred):
    global ERR
    err = 0
    for p in pred:
        if not p in LABS:
          print("error tag:", p)
          err += 1
    ERR += err
    if err == 0:
        print("check Tags --> OK")
        
def reshapeProb(probs):
    out=[]
    for p in probs:
        out.append(p[0])
    return np.array(out)


import re
def checkResultFile(fname):
    global ERR
    print('processing file', fname)
    file=open(fname,"rt")
    R=file.read()
    file.close()
    #print(R)
    res = json.loads(R)
    pred = res['preds']
    testTags(pred)
    probs=res['probs']
    names=res['names']
    version=res['version']
    nm=""
    if len(names)>2:
        print("Err: the max number of contributors in teams is 2:")
        ERR +=1 
    else:
        print("Number of contributors in team --> OK")
    if int(version)>3:
        print("Err: the max number of submission is 3 (version should be <=3):")
        ERR +=1 
    else:
        print("Version number --> OK")
    for n in names:
       nm += n
    names = nm+'_'
    method=res['method']
    appName=str.strip(res['appName'])
    
    if appName == 'SSH':
        if NB_SSH == len(pred):
            print('length of pred:',len(pred), '--> OK')
        else:
            print('length of pred:',len(pred), 'ERROR', NB_SSH, 'predictions expected for ', appName) 
            ERR += 1
        if NB_SSH == len(probs):
            print('length of probs:',len(probs), '--> OK')
        else:
            print('length of probs:',len(probs), 'ERROR', NB_SSH, 'probabilities expected for ', appName) 
            ERR += 1
    elif appName == 'HTTPWeb':
        if NB_HTTPWeb == len(pred):
            print('length of pred:',len(pred), '--> OK')
        else:
            print('length of pred:',len(pred), 'ERROR', NB_HTTPWeb, 'predictions expected for ', appName) 
            ERR += 1
        if NB_HTTPWeb == len(probs):
            print('length of probs:',len(probs), '--> OK')
        else:
            print('length of probs:',len(probs), 'ERROR', NB_HTTPWeb, 'probabilities expected for ', appName) 
            ERR += 1
    else:
        print('error field appName:', appName, ': HTTPWeb or SSH expected')
        ERR += 1

    if len(np.shape(pred))>1:
        print('ERR shape list of labels: should be 1D')
    else:
        print('shape list of labels --> OK')
    if len(np.shape(probs))>1:
        print('ERR shape list of probas: should be 1D')
    else:
        print('shape list of probas --> OK')
    return ERR
            
if __name__ == '__main__':
    if len(sys.argv)<2:
        print("usage: checkResultFile <fileName>")
    else:
        err = checkResultFile(sys.argv[1])
    
    if err == 0:
        print("So far so good!!!")
    else:
        print("Please correct the error(s) before submitting")
    
    

