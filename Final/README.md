# README 

### Authors Yoann KERGOSIEN, Alistair RAMEAU

Ce projet a pour but de tester l'utilisation de l'intelligence artificielle dans le cadre de la détection d'intrusions.

Description des différents fichiers :

- *bulk.py* : 

Ce fichier permet de charger un dossier dans Elasticsearch.

Utilisation : Mettre à jour le path vers le dossier contenant les fichiers des flows à charger, mettre à jour les credentials (adresse et port) pour se connecter à Elasticsearch et ensuite lancer la commande **python3 bulk.py**.

- *classification.py* : 

Ce fichier permet de tester les différents algorithmes avec les données chargées dans Elasticsearch.

Utilisation : Mettre à jour les credentials (adresse et port) pour se connecter à Elasticsearch et ensuite lancer la commande **python3 classification.py**.

- *finalTest.py* : 

Ce fichier permet de prédire la classe de flows inconnus à l'aide des données chargées dans Elasticsearch.

Utilisation : Mettre à jour les paths vers les 2 fichiers des flows inconnus, mettre à jour les credentials (adresse et port) pour se connecter à Elasticsearch et ensuite lancer la commande **python3 finalTest.py**.


Sources utilisées pour ce projet :

- Cours et code donné par M. Marteau, UBS
- Documentation de l'API Python d'Elasticsearch et de la bibliothèque Sklearn
