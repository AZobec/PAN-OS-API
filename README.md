#Scripts for PAN-OS API - Monitor
##Python Scripts
I had to monitor my Sinkhole interface from a PaloAlto Network appliance.

First of all, I had to create a Sinkhole Interface (https://live.paloaltonetworks.com/t5/Configuration-Articles/How-to-Configure-DNS-Sinkhole/ta-p/58891)

Then I had to generate a custom report (Last 30 Days for an example)
![Custom Report](http://i.imgur.com/FdGAzKQ.png)

At least, I created two scripts : 
- PaloAltoSinkholeGraphs.py : Get the report in a web-graph (or a svg) using PyGal
- PaloAlto_GetSinkholeNamesCSV.py : Get the report in a CSV

##Perl Scripts
Some perl scripts to get informations from a PaloAlto Network appliance.

I used them to get informations into my cacti in my company.

I hope they will be useful.

Be careful, in some scripts, I don't handle with exceptions. I will correct that in future commits.

# /!\WARNING/!\

In the GetSeverity script, i had to create a scheduled report on the PAN appliance, that gives us all the informations we need.
