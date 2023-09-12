#!/usr/bin/env python3

from core.banner import banner
from core.utils import getUniqueFilename
from core.parser import *
from core.output import *
from core.constants import *	
from core.colors import *

import jsonpickle
import requests,argparse,re
import sys,os
import json,yaml                                                    
from pathlib import Path
import urllib3
import csv
import shutil,datetime
from collections import defaultdict	
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  #Disable SSL Warnings
sys.stdout.reconfigure(line_buffering=True)                          #Enables tee command support
from urllib.parse import urljoin, urlencode, unquote
from termcolor import colored


def getArguments():
	parser = argparse.ArgumentParser("Automated AuthZ AuthN Test")
	parser.add_argument('-i','--ip',dest='IP',help="Target IP [Provide IP or URL]")
	parser.add_argument('-u','--url',dest='url',help="URL [Ex:http://host.com]")
	parser.add_argument('-f','--file',dest='swaggerFile',help="Swagger File Location")
	parser.add_argument('-v','--verbose',dest='verbose',action="store_true",help="Disable Verbose Output")
	parser.add_argument('-z','--authz',dest='authZCheck',action="store_true",help="Run AuthZ Check [Default False]")
	parser.add_argument('-n','--noauthn',dest='authNCheck',action="store_true",help="Disable Authentication Test")
	parser.add_argument('-s','--sessionID',dest='sessionID',help="Session ID of Low Privileged User for AuthZ Check")
	parser.add_argument('-o','--output',dest='outputDir',help="Output Directory (Default: Output is not saved)")
	parser.add_argument('-c','--csv',dest='csvDir',help="Output Directory for CSV File (Default: Output is not saved)")
	parser.add_argument('-y','--yaml',dest='isYaml',action="store_true",help="Use if Input file Is Yaml [Default: Json]")
	parser.add_argument('-po','--print-only',dest='printOnly',action="store_true",help="Parse the OpenAPI File and only print it")
	parser.add_argument('-pop','--print-only-processed',dest='printOnlyProcessed',action="store_true",help="Parse OpenAPI File, Replace PathVar and only print it")
	parser.add_argument('-p','--proxy',dest='proxy',help="Set Proxy [Ex: 127.0.0.1:8080]")
	parser.add_argument('-g','--global-path-variable',dest='globalPathVar',help="Replace All Path Variables in URL with this value")
	parser.add_argument('--skip',dest='skipConfirmation',action="store_true",help="Skip Details Confirmation")
	args = parser.parse_args()
	return args

def getSessionID(url,uname,upass):
	response = requests.post(url,auth=(uname, upass),verify=False)
	sess = response.json()
	return sess["value"]


def parseAndPrintAPIs(swaggerFile,isYaml,hostURL,globalPathVar,toProcess):
	responseDict = getSwaggerFromFile(swaggerFile,isYaml)
	APIList = convertAndGetAPIList(responseDict)
	for API in APIList:
		queryParams = API.get("queryParams", None)
		if queryParams:
			encodedQueryParams = urlencode(queryParams)
			url = hostURL + API['path'] + "?" + encodedQueryParams
		else:
			url = f"{hostURL}{API['path']}"

		if toProcess:                                         #if flag printOnlyProcessed
			url = buildPathVariables(url,globalPathVar)

		elif globalPathVar:                                   #If globalPathVar is given
			url = re.sub(r"\{[^}]+\}", globalPathVar, url)

		httpMethod = API['method'].upper() 
		print(f"[-]{GREEN} {httpMethod.ljust(7)} {ENDC}: {LIGHTRED} {url} {ENDC}")


def AuthenticationTest(hostURL,APIList,outputDir,csvDir,verbose,proxy,globalPathVar):
	unAuthenticatedList = []
	notFoundList = []
	validList = []              #APIs That Return 401
	headerDict={"Content-Type":"application/json","Authorization" : "Bearer 1234abcd-opaque-bearer-token-abcdlS7QF2hkqVho=="}
	proxies = {}

	if proxy:
		proxies = {
		'http' : proxy,
		'https': proxy,
		}


	done=1
	for API in APIList:
		rawURL = f"{hostURL}{API['path']}"
		url = buildPathVariables(rawURL,globalPathVar)
		httpMethod = API['method'] 
		queryParams = API.get("queryParams",None)
		requestBody = API.get("requestBody",None)      #For POST|PUT Requests

		if queryParams:
			encodedQueryParams = urlencode(queryParams)
			url = urljoin(url,"?" + encodedQueryParams)
			print(f"[-]{GREEN}PROGRESS: {done}/{len(APIList)} {ENDC}|{LIGHTRED} URL: {url}                                     {ENDC}",end="\r"),
		else:
			print(f"[-]{GREEN}PROGRESS: {done}/{len(APIList)} {ENDC}|{LIGHTRED} URL: {url}                                            {ENDC}",end="\r"),

		sys.stdout.flush()
		done+=1

		try:
			if httpMethod.upper() in ["POST","PUT"]:
				response = getattr(requests,httpMethod.lower())(url,verify=False,timeout=15,proxies=proxies,json=requestBody)
				response2 = getattr(requests,httpMethod.lower())(url,headers=headerDict,verify=False,timeout=20,proxies=proxies,json=requestBody)
			else:		
				response = getattr(requests,httpMethod.lower())(url,verify=False,timeout=20,proxies=proxies)
				response2 = getattr(requests,httpMethod.lower())(url,headers=headerDict,verify=False,timeout=20,proxies=proxies)

			if response.status_code == 404 and response2.status_code==404:
				notFoundList.append((httpMethod.upper(),url,response.status_code))
				# print(f"{RED}[-]Not Found:{ENDC} {YELLOW}{response.status_code} : {httpMethod.upper().ljust(6)} {ENDC}: {url}                  ")

			elif response.status_code != 401 or response2.status_code != 401:
				unAuthenticatedList.append((httpMethod.upper(),url,response.status_code))
				print(f"{RED}[-]UnAuthenticated:{ENDC} {YELLOW}{response.status_code} : {httpMethod.upper().ljust(6)} {ENDC}: {url}                  ")

			else:
				validList.append((httpMethod.upper(),url,response.status_code))

		except Exception as e:
			print("Exception on URL: " , httpMethod ," : " ,url , "\n[-]" , e)

	if verbose:
		printResults("UNAUTHENTICATED",unAuthenticatedList,notFoundList,validList)

	if outputDir:
		saveResultToFile(True,unAuthenticatedList,notFoundList,validList,outputDir)

	if csvDir:
		saveResultsToCSV(True,unAuthenticatedList,notFoundList,validList,csvDir)

	return unAuthenticatedList,notFoundList,validList


def AuthorizationTest(hostURL,APIList,sessionID,outputDir,csvDir,verbose,proxy,globalPathVar):
	getMethodSuccessList = []
	unAuthorizedList = []
	notFoundList = []
	validList = []              #APIs That Return 403
	headerDict={"Content-Type":"application/json","Authorization" : "Bearer " +sessionID}
	proxies = {}

	if proxy:
		proxies = {
		'http' : proxy,
		'https': proxy,
		}

	done=1
	for API in APIList:
		rawURL = f"{hostURL}{API['path']}"
		url = buildPathVariables(rawURL,globalPathVar)
		httpMethod = API['method'] 
		queryParams = API.get("queryParams",None)
		requestBody = API.get("requestBody",None)      #For POST|PUT Requests
		if queryParams:
			encodedQueryParams = urlencode(queryParams)
			url = urljoin(url,"?" + encodedQueryParams)
			print(f"[-]{GREEN}PROGRESS: {done}/{len(APIList)} {ENDC}|{LIGHTRED} URL: {url}                                     {ENDC}",end="\r"),
		else:
			print(f"[-]{GREEN}PROGRESS: {done}/{len(APIList)} {ENDC}|{LIGHTRED} URL: {url}                                            {ENDC}",end="\r"),

		sys.stdout.flush()
		done+=1

		try:
			if httpMethod.upper() in ["POST","PUT"]:
				response = getattr(requests,httpMethod.lower())(url,headers=headerDict,verify=False,timeout=15,proxies=proxies,json=requestBody)
			else:
				#Added the queryParams above only else params=queryParams
				response = getattr(requests,httpMethod.lower())(url,headers=headerDict,verify=False,timeout=15,proxies=proxies)

			if httpMethod.lower()=="get" and response.status_code == 200:
				getMethodSuccessList.append((httpMethod.upper(),url,response.status_code))

			elif response.status_code == 404:
				notFoundList.append((httpMethod.upper(),url,response.status_code))

			elif response.status_code != 403:
				unAuthorizedList.append((httpMethod.upper(),url,response.status_code))
				print(f"{RED}[-]UnAuthorized:{ENDC} {YELLOW}{response.status_code} : {httpMethod.upper().ljust(6)} {ENDC}: {url}                  ")

			else:
				validList.append((httpMethod.upper(),url,response.status_code))

		except Exception as e:
			print("Exception on URL: " , httpMethod ," : " ,url , "\n[-]" , e)

	print(f"                                                                                                {ENDC}",end="\r"),
	sys.stdout.flush()
	if verbose:
		printResults("UNAUTHORIZED",unAuthorizedList,notFoundList,validList,getMethodSuccessList)

	if outputDir:
		saveResultToFile(False,unAuthorizedList,notFoundList,validList,outputDir,getMethodSuccessList)

	if csvDir:
		saveResultsToCSV(False,unAuthorizedList,notFoundList,validList,csvDir,getMethodSuccessList)

	return unAuthorizedList,notFoundList,validList


def printResults(authZ_or_N,unauthNZ_List,notFoundList,validList,getMethodSuccessList=None):
	print(f'\n\n\n{UNDERLINE}_____________________\n|X| VERBOSE PRINT |X|{ENDC}')

	print(f"\n{RED}{UNDERLINE}| {authZ_or_N} APIs: {len(unauthNZ_List)} |{ENDC}")
	for API in unauthNZ_List:
		print(f"{YELLOW}{API[2]} : {API[0].ljust(6)}{ENDC} : {API[1]}")   #StatusCode,Method,URL

	print(f"\n{CYAN}{UNDERLINE}| NOT-FOUND APIs: {len(notFoundList)} |{ENDC}")
	for API in notFoundList:
		print(f"{YELLOW}{API[2]} : {API[0].ljust(6)}{ENDC} : {API[1]}")   #StatusCode,Method,URL

	if getMethodSuccessList:
		print(f"\n{PURPLE}{UNDERLINE}| GET APIs with ResponseCode 200: {len(getMethodSuccessList)}|{ENDC}")
		for API in getMethodSuccessList:
			print(f"{YELLOW}{API[2]} : {API[0].ljust(6)}{ENDC} : {API[1]}")   #StatusCode,Method,URL

	print(f"\n{PURPLE}{UNDERLINE}| SUCCESSFULL APIs: {len(validList)}|{ENDC}")
	for API in validList:
		print(f"{YELLOW}{API[2]} : {API[0].ljust(6)}{ENDC} : {API[1]}")   #StatusCode,Method,URL




def confirmDetails(IP,URL,swaggerFile,lowPrivSessionID,verbose,isYaml,outputDir,csvDir,proxy,authZCheck,authNCheck):
	if not os.path.exists(swaggerFile):
		print(f"[-]{LIGHTRED}Swagger File Not Found: {swaggerFile}{ENDC}")
		exit(0)
	if outputDir and not os.path.exists(outputDir):
		print(f"[-]{LIGHTRED}Invalid Output Directory for Text File: {outputDir}{ENDC}")
		exit(0)	
	if csvDir and not os.path.exists(csvDir):
		print(f"[-]{LIGHTRED}Invalid Output Directory for CSV File: {csvDir}{ENDC}")
		exit(0)

	print(f"{GREEN}[-] IP         :{ENDC}{YELLOW} {IP}{ENDC}")
	print(f"{GREEN}[-] URL        :{ENDC}{YELLOW} {URL}{ENDC}")
	print(f"{GREEN}[-] SwaggerFile:{ENDC}{YELLOW} {swaggerFile}{ENDC}")
	print(f"{GREEN}[-] AuthN-Check:{ENDC}{YELLOW} {authNCheck}{ENDC}")
	print(f"{GREEN}[-] AuthZ-Check:{ENDC}{YELLOW} {authZCheck}{ENDC}")
	print(f"{GREEN}[-] SessionID  :{ENDC}{YELLOW} {lowPrivSessionID}{ENDC} [Only Required for AuthZ Test]")
	print(f"{GREEN}[-] Verbose    :{ENDC}{YELLOW} {verbose}{ENDC}")
	print(f"{GREEN}[-] IsYaml     :{ENDC}{YELLOW} {isYaml}{ENDC}")
	print(f"{GREEN}[-] Proxy      :{ENDC}{YELLOW} {proxy}{ENDC}")
	print(f"{GREEN}[-] Output Dir :{ENDC}{YELLOW} {outputDir}{ENDC}")
	print(f"{GREEN}[-] Output CSV :{ENDC}{YELLOW} {csvDir}{ENDC}")

	print(f"{GREEN}[-] Make Sure to add Path Variables in pathVariables.json{ENDC}\n")
	ans = input("Running Automation with Above Details (Press Enter to continue or N to cancel): ")
	if ans.lower()=="n":
		print(f"{RED}[-]Exiting Program{ENDC}")
		exit()
	print()



def main():
	banner()
	#Fill Values after 'OR' for Hardcoded Input or Pass as Arguments	
	args       = getArguments()
	isYaml     = args.isYaml or False
	authZCheck = args.authZCheck or False
	IP         = args.IP or CONST_IP

	hostURL    = args.url or f"https://{IP}"
	if hostURL.endswith('/'):
		hostURL = hostURL[:-1]
	if not hostURL.startswith("http"):
		hostURL = "https://"+ hostURL

	swaggerFile= args.swaggerFile or CONST_SWAGGER_FILE_PATH
	lowPrivSessionID = args.sessionID or CONST_LOW_PRIV_TOKEN
	verbose    = True
	authNCheck = True
	outputDir =  os.path.abspath(".")
	csvDir = None
	printOnly = args.printOnly
	globalPathVar = args.globalPathVar or False
	proxy = args.proxy or False

	if args.verbose:         #If explicitly disabled verbose
		verbose = False

	if args.authNCheck:      #If explicitly disabled authN Check
		authNCheck = False

	if args.outputDir:
		outputDir = os.path.abspath(args.outputDir)

	if args.csvDir:	
		csvDir = os.path.abspath(args.csvDir)

	if args.printOnly:
		parseAndPrintAPIs(swaggerFile,isYaml,hostURL,globalPathVar,False)  #Doesnlt Call buildPathVariables()
		exit()

	if args.printOnlyProcessed:
		parseAndPrintAPIs(swaggerFile,isYaml,hostURL,globalPathVar,True)    #Calls buildPathVariables()
		exit()

	# lowPrivSessionID = getSessionID("session_url","username","password")
	if not args.skipConfirmation:
		confirmDetails(IP,hostURL,swaggerFile,lowPrivSessionID,verbose,isYaml,outputDir,csvDir,proxy,authZCheck,authNCheck)

	# responseDict = getSwaggerFromWeb(swaggerURL,webclientSessionID)
	responseDict = getSwaggerFromFile(swaggerFile,isYaml)
	APIList = convertAndGetAPIList(responseDict)

	if authNCheck:
		print(f"{PURPLE}{UNDERLINE}| AUTHN TEST WITH NO/GIBBRISH SESSION COOKIE | TOTAL-URLS: {len(APIList)} |{ENDC}\n")
		AuthenticationTest(hostURL,APIList,outputDir,csvDir,verbose,proxy,globalPathVar)

	if authZCheck:
		print(f"{PURPLE}{UNDERLINE}| AUTHZ TEST | TOTAL-URLS: {len(APIList)} |{ENDC}\n")
		AuthorizationTest(hostURL,APIList,lowPrivSessionID,outputDir,csvDir,verbose,proxy,globalPathVar)


main()
