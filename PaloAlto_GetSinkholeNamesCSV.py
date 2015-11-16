# -*- coding: utf-8 -*-
#!/usr/bin/python
#===========================================
#Script GET SINKHOLE Activity - CSV
#Société : BVA
#auteur : Arnaud Zobec
#date : 30-10-2015
#version : 002.000
#===========================================
import requests
from lxml import etree
import pygal
#import dns.reversename
# Remove SSL Warnings if there is
requests.packages.urllib3.disable_warnings()

if __name__ == "__main__":

	# Déclaration des variables
	hostname= "xx.xx.xx.xx"
	httpskey="YOURKEY"
	critical_counter = 0
	caption = "Sinkhole-BLG-Last-30Days"
	un = 1
	URL = 'https://'+hostname+'/api/?type=report&reporttype=custom&reportname='+caption+'&key='+httpskey+''
	malware_suspicion = dict()
	infected_file = open("Infected_users.csv","wb")
	infected_file.write("Names,IP,WeeklyDay,Day,Year\n")
	

	#POUR BLG
	try:
		r = requests.get(URL, verify = False)
		if r.status_code == requests.codes.ok:
			dataXML = r.text
			tree = etree.XML(dataXML)
			for entry in tree.xpath("/response/report/result/entry"):
				if entry.find("srcuser").text:
					infected_file.write(entry.find("srcuser").text+","+entry.find("src").text+","+entry.find("day-of-receive_time").text+"\n")
					#TODO REVERSEDNS
					#machine_name = dns.reversename.from_address(entry.find("src").text)
					#print machine_name
					critical_counter=critical_counter+1
	except requests.exceptions.Timeout:
		print(">>> Requete TimeOut")
	except requests.exceptions.TooManyRedirects:
		print(">>> TooManyRedirects")
	except requests.exceptions.RequestException:
		pass

	infected_file.close()
	print ("Infections : "+str(critical_counter))