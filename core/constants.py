import os

#DEFAULT VALUES FOR PATH VARIABLES
scriptDir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))        #os.path.dirname twice to go ../
PATH_VARIABLES_FILE = os.path.join(scriptDir , "pathVariables.json")
PATH_VARIABLE_DEFAULT_VALUE = "Pradeep"


#DEFAULT VALUES FOR PARAMETERS
xInteger = 123123
xString = "stringParam"
xBoolean = "True"
xArrayQueryParam = "arrayQueryParam"
xArrayReqBody = ['item1','item2'] 
xFile = "File-Required"
sampleValueDict = {"integer":xInteger,
					"string":xString,
					"boolean":xBoolean,
					"arrayQueryParam":xArrayQueryParam,
					"arrayReqBody":xArrayReqBody,
					"file":xFile}

#OUTPUT
AUTHN_RESULT_FILENAME = "authN-results"
AUTHZ_RESULT_FILENAME = "authZ-results"

#ARGUMENTS
CONST_IP = "xx.xx.xx.xx"
CONST_SWAGGER_FILE_PATH = "rx-service.json"
CONST_LOW_PRIV_TOKEN = "lowPrivilegedUserToken"

