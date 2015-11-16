# -*- coding: utf-8 -*-
#!/usr/bin/python
#===========================================
#Script GET SINKHOLE ACTIVITY - GRAPHS
#Société : BVA
#auteur : Arnaud Zobec
#date : 16-11-2015
#version : 001.000
#===========================================
import requests
from lxml import etree
import pygal
# Remove SSL Warnings if there is
requests.packages.urllib3.disable_warnings()

if __name__ == "__main__":

	# Déclaration des variables
	hostname= "xx.xx.xx.xx"
	httpskey="YOURKEY"
	critical_counter = 0
	high_counter = 0
	medium_counter = 0
	low_counter = 0
	informational_counter = 0
	caption = "Sinkhole-BLG-Last-30Days"
	un = 1
	URL = 'https://'+hostname+'/api/?type=report&reporttype=custom&reportname='+caption+'&key='+httpskey+''
	malware_suspicion = dict()

	try:
		r = requests.get(URL, verify = False)
		if r.status_code == requests.codes.ok:
			dataXML = r.text
			tree = etree.XML(dataXML)
			for entry in tree.xpath("/response/report/result/entry"):
				#GET name and IP and add it into the dict
				if not entry.find("srcuser").text:
					#Si pas de srcuser dans l'entry
					if malware_suspicion.has_key(entry.find("src").text) == False:
						#if doesn't exist
						malware_suspicion[entry.find("src").text] = [1,""]
					else:
						malware_suspicion[entry.find("src").text][0] = malware_suspicion[entry.find("src").text][0]+1
				else:
					if malware_suspicion.has_key(entry.find("src").text) == False:
						malware_suspicion[entry.find("src").text] = [1,entry.find("srcuser").text]
					else:
						malware_suspicion[entry.find("src").text][0] = malware_suspicion[entry.find("src").text][0]+1
						if malware_suspicion[entry.find("src").text][1] == "":
							malware_suspicion[entry.find("src").text][1] = entry.find("srcuser").text
	
			#print (malware_suspicion)

	except requests.exceptions.Timeout:
		print(">>> Requete TimeOut")
	except requests.exceptions.TooManyRedirects:
		print(">>> TooManyRedirects")
	except requests.exceptions.RequestException:
		pass
	


	#Bar Graph creation
	line_chart = pygal.Bar()
	line_chart.title = "Users contacting Sinkhole Interface (Last 30 days)"

	#Check in the dictionnary
	for key in malware_suspicion:
		line_chart.add(key, [{'value':malware_suspicion[key][0],'label':malware_suspicion[key][1]}])
	line_chart.render_to_file('/usr/share/web-graphs/images/line_chart.svg')

	#Generating instantly the graph : 
	#line_chart.render_in_browser() 