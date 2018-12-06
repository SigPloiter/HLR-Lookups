#!/usr/bin/env python

import sys
import requests
import re
import json
import os
import getpass
import time

'''This script is used to automate hlr-lookup process and extract important data from it
	it uses the http api proivded by hlr-lookups application (curl), this script works for Qtel, Zain KW, Etisalat UAE,DU UAE, jawal palestine'''


def hlrLookup(argv,username,passwd):
		try:
			#Zain Kuwait
			if argv[1:5] == '9659':
				response_msc = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=NT7&storage=CURL-TEST&username="+username+"&password="+passwd)
				response_imsi = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=IP1&storage=CURL-TEST&username="+username+"&password="+passwd)
				
				mccmnc = response_imsi.json()['results'][0]['mccmnc']
				
				if type(response_imsi.json()['results'][0]['msin']) != None:
					msin = response_imsi.json()['results'][0]['msin']
					imsi_ver = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=IP1&storage=CURL-TEST&username="+username+"&password="+passwd)
					msin_ver = imsi_ver.json()['results'][0]['msin']
					print "[*] Checking for Home Routing/SMS FW..."

					#Checking for home routing/sms FW
					if msin == msin_ver:
						print "[+] Target IMSI: " + mccmnc + msin
					else:
						print "[!] Possible Implementation of Home Routing Detected: IMSI is Scrambled {"+mccmnc + msin+", "+mccmnc + msin_ver+"}"

				else:
					print "[-] Target IMSI is Null"

				if type(response_imsi.json()['results'][0]['msin']) != None:
					msc = response_msc.json()['results'][0]['servingmsc']
					msc_2 = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=NT7&storage=CURL-TEST&username="+username+"&password="+passwd)
					msc_ver = msc_2.json()['results'][0]['servingmsc']

					if msc == msc_ver:
						print "[+] Target Serving MSC: "+ msc
					else:
						print "[!] Different MSC GT returned: Further Scanning Required {"+msc+", "+msc_ver+"}"

				if type(response_imsi.json()['results'][0]['msin']) != None:
					hlr = response_imsi.json()['results'][0]['servinghlr']
					print "[+] Target's HLR: " + hlr

				network_name = response_imsi.json()['results'][0]['originalnetworkname']
				print "[+] Target's Operator: " + network_name

	
				

				print "[*] Information Retrieved at " + time.asctime()
			###################################################################################
			#Etisalat UAE
			elif argv[1:6] == '97150' or argv[1:6] == '97154' or argv[1:6] == '97156':
				#response_msc = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=NT7&storage=CURL-TEST&username="+username+"&password="+passwd)
				response_imsi = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=IP1&storage=CURL-TEST&username="+username+"&password="+passwd)
				network_name = response_imsi.json()['results'][0]['originalnetworkname']
				
				
				mccmnc = response_imsi.json()['results'][0]['mccmnc']
				
				
				if type(response_imsi.json()['results'][0]['msin']) != None:
					msin = response_imsi.json()['results'][0]['msin']
					imsi_ver = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=IP1&storage=CURL-TEST&username="+username+"&password="+passwd)
					msin_ver = imsi_ver.json()['results'][0]['msin']

					msc = response_imsi.json()['results'][0]['servingmsc']
					msc_2 = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=IP1&storage=CURL-TEST&username="+username+"&password="+passwd)
					msc_ver = msc_2.json()['results'][0]['servingmsc']

					hlr = response_imsi.json()['results'][0]['servinghlr']
					hlr2 = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=IP1&storage=CURL-TEST&username="+username+"&password="+passwd)
					hlr_ver = hlr2.json()['results'][0]['servinghlr']
					
					print "[*] Checking for Home Routing/SMS FW..."


					#Checking for home routing/sms FW
					#IMSI
					if msin == msin_ver:
						print "[+] Target IMSI: " + mccmnc + msin
					else:
						print "[!] Possible Implementation of Home Routing Detected: IMSI is Scrambled {"+mccmnc + msin+", "+mccmnc + msin_ver+"}"
				

					#MSC
					if len(msc) < 12:
						print "[-] MSC info is hidden: " + msc
					else:
						if msc == msc_ver:
							print "[+] Target Serving MSC: "+ msc
						else:
							print "[!] Different MSC GT returned: Further Scanning Required {"+msc+", "+msc_ver+"}"
				

					#HLR
					if hlr == hlr_ver:
						print "[+] Target's HLR: " + str(hlr)
					else:
						print "[!] Different HLR GT returned: Further Scanning Required {"+hlr+", "+hlr_ver+"}"
				else:
					print "[-] No User info returned"
				
				print "[+] Target's Operator: " + network_name
				print "[*] Information Retrieved at " + time.asctime() 
			###################################################################################
			#DU UAE
			elif argv[1:6] == '97155' or argv[1:6] == '97152':
				response_msc = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=NT7&storage=CURL-TEST&username="+username+"&password="+passwd)
				response_imsi = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=IP1&storage=CURL-TEST&username="+username+"&password="+passwd)
				
				network_name = response_imsi.json()['results'][0]['originalnetworkname']
				mccmnc = response_imsi.json()['results'][0]['mccmnc']
			
				
				if type(response_imsi.json()['results'][0]['msin']) != None:
					msin = response_imsi.json()['results'][0]['msin']
					imsi_ver = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=IP1&storage=CURL-TEST&username="+username+"&password="+passwd)
					msin_ver = imsi_ver.json()['results'][0]['msin']
					msc = response_msc.json()['results'][0]['servingmsc']
					msc_2 = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=NT7&storage=CURL-TEST&username="+username+"&password="+passwd)
					msc_ver = msc_2.json()['results'][0]['servingmsc']
					hlr = response_imsi.json()['results'][0]['servinghlr']
					hlr2 = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=IP1&storage=CURL-TEST&username="+username+"&password="+passwd)
					hlr_ver = hlr2.json()['results'][0]['servinghlr'] 
					print "[*] Checking for Home Routing/SMS FW..."
					

					
				
					#Checking for home routing/sms FW
					#IMSI
					if msin == msin_ver:
						print "[+] Target IMSI: " + mccmnc + msin
					else:
						print "[!] Possible Implementation of Home Routing Detected: IMSI is Scrambled {"+mccmnc + msin+", "+mccmnc + msin_ver+"}"

					#MSC
					if (msc is None) or (msc_ver is None):
						print "[!] No value returned for MSC"
					elif len(msc) < 12:
						print "[-] MSC info is hidden: " + msc

					elif msc == msc_ver:
						print "[+] Target Serving MSC: "+ msc
					else:
						print "[!] Different MSC GT returned: Further Scanning Required {"+msc+", "+msc_ver+"}"

					#HLR
					if hlr == hlr_ver:
						print "[+] Target's HLR: " + str(hlr)
					else:
						print "[!] Different HLR GT returned: Further Scanning Required {"+hlr+", "+hlr_ver+"}"
				else:
					print "[-] No User info returned"

				print "[+] Target's Operator: " + network_name
				print "[*] Information Retrieved at " + time.asctime()

			###################################################################################
			#QTEL
			elif argv[1:5] == '9743' or argv[1:5] == '9744' or argv[1:5] == '9745' or argv[1:5] == '9746':
				response_msc = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=SV3&storage=CURL-TEST&username="+username+"&password="+passwd)
				response_imsi = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=IP1&storage=CURL-TEST&username="+username+"&password="+passwd)
								
				mccmnc = response_imsi.json()['results'][0]['mccmnc']
				
				if type(response_imsi.json()['results'][0]['msin']) != None:
					msin = response_imsi.json()['results'][0]['msin']
					imsi_ver = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=IP1&storage=CURL-TEST&username="+username+"&password="+passwd)
					msin_ver = imsi_ver.json()['results'][0]['msin']
					print "[*] Checking for Home Routing/SMS FW..."

					#Checking for home routing/sms FW
					if msin == msin_ver:
						print "[+] Target IMSI: " + mccmnc + msin
					else:
						print "[!] Possible Implementation of Home Routing Detected: IMSI is Scrambled {"+mccmnc + msin+", "+mccmnc + msin_ver+"}"

				else:
					print "[-] Target IMSI is Null"

				if type(response_imsi.json()['results'][0]['msin']) != None:
					msc = response_msc.json()['results'][0]['servingmsc']
					msc_2 = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=SV3&storage=CURL-TEST&username="+username+"&password="+passwd)
					msc_ver = msc_2.json()['results'][0]['servingmsc']

					if (msc is None) or (msc_ver is None):
						print "[!] No value returned for MSC"
					elif len(msc) < 12:
						print "[-] MSC info is hidden: " + msc

					elif msc == msc_ver:
						print "[+] Target Serving MSC: "+ msc
					else:
						print "[!] Different MSC GT returned: Further Scanning Required {"+msc+", "+msc_ver+"}"

				if type(response_imsi.json()['results'][0]['msin']) != None:
					hlr = response_imsi.json()['results'][0]['servinghlr']
					print "[+] Target's HLR: " + hlr

				network_name = response_imsi.json()['results'][0]['originalnetworkname']
				print "[+] Target's Operator: " + network_name


				print "[*] Information Retrieved at " + time.asctime()
			###################################################################################
			#Jawal Palestine
			elif argv[1:6] == '97259':

				response_msc = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=SV3&storage=CURL-TEST&username="+username+"&password="+passwd)
				response_imsi = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=IP1&storage=CURL-TEST&username="+username+"&password="+passwd)
				
				mccmnc = response_imsi.json()['results'][0]['mccmnc']
				
				if type(response_imsi.json()['results'][0]['msin']) != None:
					msin = response_imsi.json()['results'][0]['msin']
					imsi_ver = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=IP1&storage=CURL-TEST&username="+username+"&password="+passwd)
					msin_ver = imsi_ver.json()['results'][0]['msin']
					print "[*] Checking for Home Routing/SMS FW..."

					#Checking for home routing/sms FW
					if msin == msin_ver:
						print "[+] Target IMSI: " + mccmnc + msin
					else:
						print "[!] Possible Implementation of Home Routing Detected: IMSI is Scrambled {"+mccmnc + msin+", "+mccmnc + msin_ver+"}"

				else:
					print "[-] Target IMSI is Null"

				if type(response_imsi.json()['results'][0]['msin']) != None:
					msc = response_msc.json()['results'][0]['servingmsc']
					msc_2 = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=SV3&storage=CURL-TEST&username="+username+"&password="+passwd)
					msc_ver = msc_2.json()['results'][0]['servingmsc']

					if (msc is None) or (msc_ver is None):
						print "[!] No value returned for MSC"
					elif len(msc) < 12:
						print "[-] MSC info is hidden: " + msc

					elif msc == msc_ver:
						print "[+] Target Serving MSC: "+ msc
					else:
						print "[!] Different MSC GT returned: Further Scanning Required {"+msc+", "+msc_ver+"}"

				if type(response_imsi.json()['results'][0]['msin']) != None:
					hlr = response_imsi.json()['results'][0]['servinghlr']
					print "[+] Target's HLR: " + hlr

				network_name = response_imsi.json()['results'][0]['originalnetworkname']
				print "[+] Target's Operator: " + network_name


				print "[*] Information Retrieved at " + time.asctime()
			###################################################################################
			#Airtel India
			elif argv[1:6] == '91773':
				#response_msc = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=SV3&storage=CURL-TEST&username="+username+"&password="+passwd)
				response_imsi = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=IP1&storage=CURL-TEST&username="+username+"&password="+passwd)
				
				mccmnc = response_imsi.json()['results'][0]['mccmnc']
				
				if type(response_imsi.json()['results'][0]['msin']) != None:
					msin = response_imsi.json()['results'][0]['msin']
					imsi_ver = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=IP1&storage=CURL-TEST&username="+username+"&password="+passwd)
					msin_ver = imsi_ver.json()['results'][0]['msin']
					print "[*] Checking for Home Routing/SMS FW..."

					#Checking for home routing/sms FW
					if msin == msin_ver:
						print "[+] Target IMSI: " + mccmnc + msin
					else:
						print "[!] Possible Implementation of Home Routing Detected: IMSI is Scrambled {"+mccmnc + msin+", "+mccmnc + msin_ver+"}"

				else:
					print "[-] Target IMSI is Null"

				if type(response_imsi.json()['results'][0]['msin']) != None:
					msc = response_msc.json()['results'][0]['servingmsc']
					msc_2 = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=SV3&storage=CURL-TEST&username="+username+"&password="+passwd)
					msc_ver = msc_2.json()['results'][0]['servingmsc']

					if (msc is None) or (msc_ver is None):
						print "[!] No value returned for MSC"

					elif msc == msc_ver:
						print "[+] Target Serving MSC: "+ msc
					else:
						print "[!] Different MSC GT returned: Further Scanning Required {"+msc+", "+msc_ver+"}"

				if type(response_imsi.json()['results'][0]['msin']) != None:
					hlr = response_imsi.json()['results'][0]['servinghlr']
					print "[+] Target's HLR: " + hlr

				network_name = response_imsi.json()['results'][0]['originalnetworkname']
				print "[+] Target's Operator: " + network_name


				print "[*] Information Retrieved at " + time.asctime()

			#vodafone India
			elif argv[1:6] == '91976':

				response_msc = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=NT7&storage=CURL-TEST&username="+username+"&password="+passwd)
				response_imsi = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=IP1&storage=CURL-TEST&username="+username+"&password="+passwd)
				
				mccmnc = response_imsi.json()['results'][0]['mccmnc']
				
				if type(response_imsi.json()['results'][0]['msin']) != None:
					msin = response_imsi.json()['results'][0]['msin']
					imsi_ver = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=IP1&storage=CURL-TEST&username="+username+"&password="+passwd)
					msin_ver = imsi_ver.json()['results'][0]['msin']
					print "[*] Checking for Home Routing/SMS FW..."

					#Checking for home routing/sms FW
					if msin == msin_ver:
						print "[+] Target IMSI: " + mccmnc + msin
					else:
						print "[!] Possible Implementation of Home Routing Detected: IMSI is Scrambled {"+mccmnc + msin+", "+mccmnc + msin_ver+"}"

				else:
					print "[-] Target IMSI is Null"

				if type(response_imsi.json()['results'][0]['msin']) != None:
					msc = response_msc.json()['results'][0]['servingmsc']
					msc_2 = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=SV3&storage=CURL-TEST&username="+username+"&password="+passwd)
					msc_ver = msc_2.json()['results'][0]['servingmsc']

					if (msc is None) or (msc_ver is None):
						print "[!] No value returned for MSC"

					elif msc == msc_ver:
						print "[+] Target Serving MSC: "+ msc
					else:
						print "[!] Different MSC GT returned: Further Scanning Required {"+msc+", "+msc_ver+"}"

				if type(response_imsi.json()['results'][0]['msin']) != None:
					hlr = response_imsi.json()['results'][0]['servinghlr']
					print "[+] Target's HLR: %s" %hlr

				network_name = response_imsi.json()['results'][0]['originalnetworkname']
				print "[+] Target's Operator: %s" %network_name


				print "[*] Information Retrieved at " + time.asctime()

			#Reliance India
			elif argv[1:6] == '91969':

				response_msc = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=NT7&storage=CURL-TEST&username="+username+"&password="+passwd)
				response_imsi = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=IP1&storage=CURL-TEST&username="+username+"&password="+passwd)
				
				mccmnc = response_imsi.json()['results'][0]['mccmnc']
				
				if type(response_imsi.json()['results'][0]['msin']) != None:
					msin = response_imsi.json()['results'][0]['msin']
					imsi_ver = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=IP1&storage=CURL-TEST&username="+username+"&password="+passwd)
					msin_ver = imsi_ver.json()['results'][0]['msin']
					print "[*] Checking for Home Routing/SMS FW..."

					#Checking for home routing/sms FW
					if msin == msin_ver:
						print "[+] Target IMSI: " + mccmnc + msin
					else:
						print "[!] Possible Implementation of Home Routing Detected: IMSI is Scrambled {"+mccmnc + msin+", "+mccmnc + msin_ver+"}"

				else:
					print "[-] Target IMSI is Null"

				if type(response_imsi.json()['results'][0]['msin']) != None:
					msc = response_msc.json()['results'][0]['servingmsc']
					msc_2 = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=SV3&storage=CURL-TEST&username="+username+"&password="+passwd)
					msc_ver = msc_2.json()['results'][0]['servingmsc']

					if (msc is None) or (msc_ver is None):
						print "[!] No value returned for MSC"

					elif msc == msc_ver:
						print "[+] Target Serving MSC: "+ msc
					else:
						print "[!] Different MSC GT returned: Further Scanning Required {"+msc+", "+msc_ver+"}"

				if type(response_imsi.json()['results'][0]['msin']) != None:
					hlr = response_imsi.json()['results'][0]['servinghlr']
					print "[+] Target's HLR: %s" %hlr

				network_name = response_imsi.json()['results'][0]['originalnetworkname']
				print "[+] Target's Operator: %s" %network_name


				print "[*] Information Retrieved at " + time.asctime()
			###################################################################################
			#MTS Russia
			elif argv[1:3] == '79':

				response_msc = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=NT7&storage=CURL-TEST&username="+username+"&password="+passwd)
				response_imsi = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=IP1&storage=CURL-TEST&username="+username+"&password="+passwd)
				
				mccmnc = response_imsi.json()['results'][0]['mccmnc']
				
				if type(response_imsi.json()['results'][0]['msin']) != None:
					msin = response_imsi.json()['results'][0]['msin']
					imsi_ver = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=IP1&storage=CURL-TEST&username="+username+"&password="+passwd)
					msin_ver = imsi_ver.json()['results'][0]['msin']
					print "[*] Checking for Home Routing/SMS FW..."

					#Checking for home routing/sms FW
					if msin == msin_ver:
						print "[+] Target IMSI: " + mccmnc + msin
					else:
						print "[!] Possible Implementation of Home Routing Detected: IMSI is Scrambled {"+mccmnc + msin+", "+mccmnc + msin_ver+"}"

				else:
					print "[-] Target IMSI is Null"

				if type(response_imsi.json()['results'][0]['msin']) != None:
					msc = response_msc.json()['results'][0]['servingmsc']
					msc_2 = requests.get("https://www.hlr-lookups.com/api/?action=submitSyncLookupRequest&msisdn="+argv+"&route=NT7&storage=CURL-TEST&username="+username+"&password="+passwd)
					msc_ver = msc_2.json()['results'][0]['servingmsc']

					if (msc is None) or (msc_ver is None):
						print "[!] No value returned for MSC"

					elif msc == msc_ver:
						print "[+] Target Serving MSC: "+ msc
					else:
						print "[!] Different MSC GT returned: Further Scanning Required {"+msc+", "+msc_ver+"}"

				if type(response_imsi.json()['results'][0]['msin']) != None:
					hlr = response_imsi.json()['results'][0]['servinghlr']
					print "[+] Target's HLR: %s" %hlr

				network_name = response_imsi.json()['results'][0]['originalnetworkname']
				print "[+] Target's Operator: %s" %network_name


				print "[*] Information Retrieved at " + time.asctime()

		except Exception as e :
			'''if response_imsi.json()['success'] is False:
				print '[-]Error:  ', response_imsi.json()['errors']
			elif response_msc.json()['success'] is False:
				print '[-]Error:  ',response_imsi.json()['errors']'''
			print e
			#sys.exit(1)
		
	
	


if __name__=='__main__':

	if len(sys.argv) < 2:

		print "\nUsage: ./hlr-lookup.py <MSISDN>"
		print "Example: ./hlr-lookup.py +20123456789"
		sys.exit(1)

	elif  (len(sys.argv[1][1:]) != 11) and (len(sys.argv[1][1:]) != 12):
		print "[-] Wrong Format for MSISDN"
		print "[*] MSISDN should be 11 or 12 digits after the (+) sign"
		sys.exit(1)

	else:
		username = 'foravay-api-2e744af64e4e'
		passwd = '26jb-mhKq-Qd2W-Mv2!-4zFw-GmZ!'
		print "[*] Sending Request..."
		hlrLookup(sys.argv[1], username, passwd)
		
