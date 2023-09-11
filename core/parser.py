import json
import re,os
from core.colors import *
from core.constants import *

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



def buildClassObjectsFromSwagger(classDict):
	allClassesDict = {}
	for className,classObjs in classDict.items():
		try:
			classProperties = classObjs["properties"]
			allClassesDict[className]=classProperties
		except KeyError:
			allClassesDict[className]={}

	return allClassesDict


def getClassObjects(allClassesDict, className):
	# className = "TitanProfileRequest"
	return allClassesDict[className]


#Only For Testing
def printClassProperties(allClassesDict):
	for className, classProperties in allClassesDict.items():
		print(f"[-]{className}")
		try:
			for propertyName, propertyAttributes in classProperties.items():
				propertyDatatype = propertyAttributes['type']
				propertyExample = propertyAttributes.get('example',"")
				print(f"{propertyName} : {propertyDatatype} : {propertyExample}")
			print()
		except KeyError:
			#Class has no properties
			pass


#Build the Query Param for GET Requests With Class Reference
def buildQueryForGet(queryParams,allClassesDict,className):
	classObject = getClassObjects(allClassesDict,className)

	for paramName, paramAttributes in classObject.items():
		#IF PARAMETER REFERS TO ANOTHER CLASS
		if paramAttributes.get('$ref'):
			className = paramAttributes.get('$ref').split("/")[-1]
			buildQueryForGet(queryParams,allClassesDict,className)       #Recursion Bro

		else:
			paramExample = paramAttributes.get('example',None)           #If Swagger has example value
			if paramExample:
				queryParams[paramName] = paramExample
			else:
				paramType = paramAttributes['type']
				queryParams[paramName] = sampleValueDict.get(paramType)

	return queryParams


#Build Requestbody for POST/PUT Requests
def buildRequestBodyForPostPutgg(allClassesDict,className,requestBody,currentBodyDict,isClassParam):
	classObject = getClassObjects(allClassesDict,className)
	# print(f"isClassParam = {isClassParam}")

	for paramName, paramAttributes in classObject.items():
		#IF PARAMETERS ALSO POINT TO ANOTHER CLASS
		if paramAttributes.get('$ref'):
			className = paramAttributes.get('$ref').split("/")[-1]
			buildRequestBodyForPostPutgg(allClassesDict,className,requestBody,currentBodyDict,True)  #Recursion 
			requestBody[paramName]=currentBodyDict
			currentBodyDict={}
			# print(f"currentBodyDict = {currentBodyDict}")
			# print(f"REQUESTBODY ==> {requestBody}")
			# print("GG Bhai\n")

		else:
			paramExample = paramAttributes.get('example',None)
			if paramExample:
				paramValue = paramAttributes.get('example')

			else:
				paramType = paramAttributes['type']
				paramValue = sampleValueDict.get(paramType)

			currentBodyDict[paramName] = paramValue

	if not isClassParam:
		# print(f"Append directly to classParam : dict= {currentBodyDict}")
		requestBody.update(currentBodyDict)

		# requestBody["AddAsSolo"]  = currentBodyDict

	return requestBody


def buildRequestBodyForPostPut(allClassesDict,className):
	classObject = getClassObjects(allClassesDict,className)
	currentBodyDict = {}
	isClassParam = None
	requestBody = {}
	buildRequestBodyForPostPutgg(allClassesDict,className,requestBody,currentBodyDict,isClassParam)
	return requestBody



def convertAndGetAPIList(responseDict):
	pathDict = responseDict['paths']

	try:
		allClassesDict = buildClassObjectsFromSwagger(responseDict['definitions'])
	except KeyError:
		print(colored("[]No Class Definations in Swagger File","red"))
		allClassesDict ={}

	APIList = []

	for APIPath, requestInfoRoot in pathDict.items():
		for method,requestInfo in requestInfoRoot.items():
			# print(f"[-]API: {APIPath}")

			# ###TEST
			# if not method.upper=="POST" and not APIPath =="/rx-service/v2/profile":
			# 	continue
			# ##TEST-END

			#GET|DELETE REQUESTS
			if method.upper() == "GET" or method.upper()=="DELETE":     

				#1)GET|DELETE: No Parameters
				if not requestInfo.get("parameters"):
					APIList.append({"path":APIPath,"method":method})

				else:
					queryParams = {}
					for paramDict in requestInfo['parameters']:

						#2)GET|DELETE: Query Parameters
						if paramDict.get("in") == "query":
							paramName = paramDict['name']
							paramType = paramDict['type']

							paramExample = paramDict.get('x-example',None) or paramDict.get('x-annotation-example',None)   #Need to check if others also exist
							if paramExample:
								queryParams[paramName] = paramExample
							else:
								queryParams[paramName] = sampleValueDict.get(paramType)

						elif paramDict.get("in") == "body":
							#3)GET|DELETE: Class Reference
							if paramDict.get("schema").get("$ref"):
								classNameUnfiltered = paramDict["schema"]["$ref"]
								className = classNameUnfiltered.split("/")[-1]
								buildQueryForGet(queryParams,allClassesDict,className)             #queryParams will have the paramters
							

							elif paramDict["schema"]["type"] == "array":
								classNameUnfiltered = paramDict["schema"]['items']

								#GET|DELETE: ARRAY OF CLASSES
								if classNameUnfiltered.get("$ref"):
									className = classNameUnfiltered["$ref"].split("/")[-1]
									buildQueryForGet(queryParams,allClassesDict,className)             #queryParams will have the paramters

								#GET|DELETE: ARRAY OF STRINGS
								elif classNameUnfiltered.get("type") == "string":
									paramName = paramDict["name"]
									queryParams[paramName] = sampleValueDict.get("xArrayQueryParam")

								#GET|DELETE: IF SOMETHING UNKNOWN
								else:
									print(f"UNKNOWN: {APIPath} --> {paramDict} ")


					APIList.append({"path":APIPath,"method":method,"queryParams":queryParams})


			#PUT|POST REQUESTS
			elif method.upper() == "PUT" or method.upper() == "POST":

				#1)No RequestBody or QueryParams
				if not requestInfo.get("parameters"):
					APIList.append({"path":APIPath,"method":method})

				else:
					queryParams = {}
					requestBody = {}
					for paramDict in requestInfo['parameters']:
						#2)Query Parameters (@RequestParam)
						if paramDict.get("in") == "query":
							paramName = paramDict['name']
							paramType = paramDict['type']

							paramExample = paramDict.get('x-example',None) or paramDict.get('x-annotation-example',None)   #Need to check if others also exist
							if paramExample:
								queryParams[paramName] = paramExample
							else:
								queryParams[paramName] = sampleValueDict.get(paramType)


						elif paramDict.get("in") == "body":
							#3)CLASS
							if paramDict.get("schema").get("$ref"):
								classNameUnfiltered = paramDict["schema"]['$ref']	
								className = classNameUnfiltered.split("/")[-1]
								requestBody = buildRequestBodyForPostPut(allClassesDict,className)


							#OTHERS
							elif paramDict.get("schema").get("type"):

								#4)FILE
								if paramDict["schema"]["type"] == "file":
									paramName = paramDict["name"]
									requestBody = sampleValueDict.get("file")


								#5)ARRAY
								elif paramDict["schema"]["type"] == "array":
									classNameUnfiltered = paramDict["schema"]['items']

									#ARRAY OF CLASSES
									if classNameUnfiltered.get("$ref"):
										className = classNameUnfiltered.get("$ref").split("/")[-1]
										requestBody = buildRequestBodyForPostPut(allClassesDict,className)  #Get Class Properties
										requestBody = [requestBody]                                         #Convert to array

									#ARRAY OF STRINGS
									elif classNameUnfiltered.get("type") == "string":
										requestBody = sampleValueDict.get("arrayReqBody")

									#IF SOMETHING UNKNOWN
									else:
										print(f"UNKNOWN: {APIPath} --> {paramDict} ")       #DEBUG

					#POST|PUT Add to APIList
					if requestBody and queryParams:
						APIList.append({"path":APIPath,"method":method,"requestBody":requestBody,"queryParams":queryParams})
					elif queryParams:
						APIList.append({"path":APIPath,"method":method,"queryParams":queryParams})
					elif requestBody:
						APIList.append({"path":APIPath,"method":method,"requestBody":requestBody})


	# print("\n-------- FINAL LIST --------")
	# for API in APIList:
	# 	print(f"[-]{API['method'].upper()}: {unquote(API['URL'])}")

	return APIList



def buildPathVariables(url,globalPathVar):
	with open(PATH_VARIABLES_FILE, 'r') as file:
	    pathVariables = json.load(file)

	for key, value in pathVariables.items():
		url = url.replace(f"{{{key}}}",f"{value}")               #Replace {pathVariable} with the value	

	#Default Value For Path Variables
	globalPathVar = globalPathVar or PATH_VARIABLE_DEFAULT_VALUE  
	url = re.sub(r"\{[^}]+\}", globalPathVar, url)    #Replace /{anything} with /pradeep
	return url

