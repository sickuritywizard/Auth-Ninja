#!/usr/bin/env python3

import jsonpickle
import requests,argparse,re
import sys,os
import json,yaml                                                    
from pathlib import Path
import urllib3
import csv
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  #Disable SSL Warnings
sys.stdout.reconfigure(line_buffering=True)                          #Enables tee command support

#COLORS
BLUE = '\033[94m';CYAN = '\033[96m';GREEN = '\033[92m';YELLOW = '\033[93m'; RED = "\033[0;31m";
LIGHTRED = '\033[91m';PURPLE = '\033[95m';BOLD = '\033[1m';UNDERLINE = '\033[4m';ENDC = '\033[0m'

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
	args = parser.parse_args()
	return args

def get_unique_Filename(fileName,ext):
	if not os.path.exists(fileName+ext):
		return fileName+ext
	else:
		fileName = fileName+"_{}"
		counter = 1
		while os.path.exists(fileName.format(counter)+ext):
			counter += 1
		fileName = fileName.format(counter)

	return fileName+ext


def getSwaggerFromWeb(swaggerFileURL,webclientSessionID):
	headers = {"Webclientsessionid" : webclientSessionID}
	response = requests.get(apiExplorerURL, headers=headers, verify=False)
	if response.status_code == 401:
		print(f"{RED}[-] Please Check WebClientSessionID, received 401 Unauthorized")
	return response.json()


def getSwaggerFromFile(filePath,yml=False):
	if yml:
		try:
			with open(filePath, "r") as stream:
				return yaml.safe_load(stream)
		except Exception as e:
			print("[-] Error Parsing YAML File --> ",e)
			exit(0)
	else:
		try:
			with open(filePath,"r") as filePtr:
				return json.load(filePtr)
		except Exception as e:
			print("[-] Error Parsing JSON File --> ",e)
			exit(0)


def getSessionID(url,uname,upass):
	response = requests.post(url,auth=(uname, upass),verify=False)
	sess = response.json()
	return sess["value"]


def parseAndPrintURLs(swaggerFile,isYaml,host,globalPathVar,toProcess):
	responseDict = getSwaggerFromFile(swaggerFile,isYaml)
	APIList = convertAndGetAPIList(responseDict)
	for API in APIList:
		url = f"{host}{API['path']}"

		if toProcess:                                         #if flag printOnlyProcessed
			url = buildURL(url,globalPathVar)

		elif globalPathVar:                                   #If globalPathVar is given
			url = re.sub(r"\{[^}]+\}", globalPathVar, url)

		httpMethod = API['method'].upper() 
		print(f"[-]{GREEN} {httpMethod.ljust(7)} {ENDC}: {LIGHTRED} {url} {ENDC}")


def convertAndGetAPIList(responseDict):
	pathDict = responseDict['paths']
	APIList = []

	for path, requestInfo in pathDict.items():
		for method,others in requestInfo.items():
			if method == "parameters":
				continue
			else:
				# APIList.append({"path":path,"method":method,"summary":others['description']})  //When u want description as well
				APIList.append({"path":path,"method":method})
				# print(method.upper().ljust(6) , " --> ", path)

	return APIList


def AuthenticationTest(host,APIList,outputDir,csvDir,verbose,proxy,globalPathVar):
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


	done=0
	for API in APIList:
		rawURL = f"{host}{API['path']}"
		url = buildURL(rawURL,globalPathVar)
		httpMethod = API['method'] 
		print(f"[-]{GREEN}PROGRESS: {done}/{len(APIList)} {ENDC}|{LIGHTRED} URL: {url}                              {ENDC}",end="\r"),
		sys.stdout.flush()
		done+=1

		try:
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
		printOtherResults("UNAUTHENTICATED",unAuthenticatedList,notFoundList,validList)

	if outputDir:
		saveResultToFile(True,unAuthenticatedList,notFoundList,validList,outputDir)

	if csvDir:
		saveResultsToCSV(True,unAuthenticatedList,notFoundList,validList,csvDir)

	return unAuthenticatedList,notFoundList,validList


def AuthorizationTest(host,APIList,sessionID,outputDir,csvDir,verbose,proxy,globalPathVar):
	getMethodSuccessList = []
	unAuthorizedList = []
	notFoundList = []
	validList = []              #APIs That Return 403
	headerDict={"Content-Type":"application/json","Authorization" : "Bearer " +sessionID}

	done=0
	for API in APIList:
		rawURL = f"{host}{API['path']}"
		url = buildURL(rawURL,globalPathVar)
		httpMethod = API['method'] 
		print(f"[-]{GREEN}PROGRESS: {done}/{len(APIList)} {ENDC}|{LIGHTRED} URL: {url}                              {ENDC}",end="\r"),
		sys.stdout.flush()
		done+=1

		try:
			response = getattr(requests,httpMethod.lower())(url,headers=headerDict,verify=False,timeout=15)

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

	if verbose:
		printOtherResults("UNAUTHORIZED",unAuthorizedList,notFoundList,validList,getMethodSuccessList)

	if outputDir:
		saveResultToFile(False,unAuthorizedList,notFoundList,validList,outputDir,getMethodSuccessList)

	if csvDir:
		saveResultsToCSV(False,unAuthorizedList,notFoundList,validList,csvDir,getMethodSuccessList)

	return unAuthorizedList,notFoundList,validList


def printOtherResults(authZ_or_N,unauthNZ_List,notFoundList,validList,getMethodSuccessList=None):
	print(f'\n{PURPLE}{UNDERLINE}| VERBOSE PRINT |{ENDC}{ENDC}')

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



def saveResultToFile(isAuthN,unauthNZ_List,notFoundList,validList,outputDir,getMethodSuccessList=None):
	os.chdir(outputDir)
	if isAuthN:
		fileName = get_unique_Filename("authN_Results-007",".txt")
	else:
		fileName = get_unique_Filename("authZ_Results-007",".txt")

	with open(fileName, "w") as file:
		if isAuthN:
			file.write(f"[-]UNAUTHENTICATED APIS: {len(unauthNZ_List)}\n")
		else:
			file.write(f"[-]UNAUTHORIZED APIS: {len(unauthNZ_List)}\n")

		for API in unauthNZ_List:
			file.write(f"{API[2]} : {API[0].ljust(6)} : {API[1]}\n")

		file.write(f"\n[-]NOT-FOUND APIS: {len(notFoundList)}\n")
		for API in notFoundList:
				file.write(f"{API[2]} : {API[0].ljust(6)} : {API[1]}\n")

		if getMethodSuccessList:
			file.write(f"\n[-]GET APIs with ResponseCode 200: {len(getMethodSuccessList)}\n")
			for API in getMethodSuccessList:
					file.write(f"{API[2]} : {API[0].ljust(6)} : {API[1]}\n")

		file.write(f"\n[-]SUCCESFULL APIS: {len(validList)}\n")
		for API in validList:
				file.write(f"{API[2]} : {API[0].ljust(6)} : {API[1]}\n")

	print(f"\n{GREEN}[-]Output Saved To: {outputDir}/{fileName}{ENDC}")

def saveResultsToCSV(isAuthN,unauthNZ_List,notFoundList,validList,csvDir,getMethodSuccessList=None):
	os.chdir(csvDir)

	header = ["SL","API","Method","ResponseCode"]
	slNo = 1
	if isAuthN:
		fileName = get_unique_Filename("authN_Results-007",".csv")
	else:
		fileName = get_unique_Filename("authZ_Results-007",".csv")

	with open(fileName,"w") as file:
		writer = csv.writer(file)
		writer.writerow(header)

		if isAuthN:
			writer.writerow(["[-]UnAuthenticated APIs"])
		else:
			writer.writerow(["[-]Unauthorized APIs"])

		for API in unauthNZ_List:
			writer.writerow([slNo, API[1], API[0],API[2]])   #API | Method | ResponseCode
			slNo+=1

		writer.writerows([[],["[-]NOT-FOUND APIS"]]) 
		for API in notFoundList:
			writer.writerow([slNo, API[1], API[0],API[2]])   #API | Method | ResponseCode
			slNo+=1

		if getMethodSuccessList:
			writer.writerows([[],["[-]GET APIs with ResponseCode 200"]]) 
			for API in getMethodSuccessList:
				writer.writerow([slNo, API[1], API[0],API[2]])   #API | Method | ResponseCode
				slNo+=1

		writer.writerows([[],["[-]SUCCESFULL APIS"]])
		for API in validList:
			writer.writerow([slNo, API[1], API[0],API[2]])   #API | Method | ResponseCode
			slNo+=1

	print(f"\n{GREEN}[-]Output Saved To: {csvDir}/{fileName}{ENDC}")


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

	print(f"{GREEN}[-] Make Sure to modify buildURL() in script to replace PATH variables:{ENDC}\n")
	ans = input("Running Automation with Above Details (Press Enter to continue or N to cancel): ")
	if ans.lower()=="n":
		print(f"{RED}[-]Exiting Program{ENDC}")
		exit()
	print()


def buildURL(url,globalPathVar):
	# url = url.replace("{namespace_id}","2731")           #Add more replacements as required
	# url = url.replace("{replaceThis}","withThis")

	#All Other Path Variables will be replaced with this
	globalPathVar = globalPathVar or "pradeep"        #pradeep if globalPathVar is not defined
	url = re.sub(r"\{[^}]+\}", globalPathVar, url)       #Replace /{anything} with /pradeep
	return url


def main():
	#Fill Values after 'OR' for Hardcoded Input or Pass as Arguments	
	args       = getArguments()
	isYaml     = args.isYaml or False
	authZCheck = args.authZCheck or False
	IP         = args.IP or "xx.xx.xx.xx"
	url        = args.url or f"https://{IP}"
	if url.endswith('/'):
		url = url[:-1]
	swaggerFile= args.swaggerFile or "/pathTo/swagger-api-v2.json"
	lowPrivSessionID = args.sessionID or "LowPrivSessionID" 
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
		parseAndPrintURLs(swaggerFile,isYaml,url,globalPathVar,False)  #Doesnlt Call BuildURL()
		exit()

	if args.printOnlyProcessed:
		parseAndPrintURLs(swaggerFile,isYaml,url,globalPathVar,True)    #Calls BuildURL()
		exit()

	# lowPrivSessionID = getSessionID("session_url","username","password")
	confirmDetails(IP,url,swaggerFile,lowPrivSessionID,verbose,isYaml,outputDir,csvDir,proxy,authZCheck,authNCheck)

	# responseDict = getSwaggerFromWeb(swaggerURL,webclientSessionID)
	responseDict = getSwaggerFromFile(swaggerFile,isYaml)
	APIList = convertAndGetAPIList(responseDict)

	if authNCheck:
		print(f"{PURPLE}{UNDERLINE}| AUTHN TEST WITH NO/GIBBRISH SESSION COOKIE | TOTAL-URLS: {len(APIList)} |{ENDC}\n")
		AuthenticationTest(url,APIList,outputDir,csvDir,verbose,proxy,globalPathVar)

	if authZCheck:
		print(f"{PURPLE}{UNDERLINE}|AUTHZ TEST WITH READ ONLY SESSION|{ENDC}{ENDC}\n")
		AuthorizationTest(url,APIList,lowPrivSessionID,outputDir,csvDir,verbose,proxy,globalPathVar)

main()
