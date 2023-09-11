import os
import csv
from core.utils import getUniqueFilename
from core.colors import *


def saveResultToFile(isAuthN,unauthNZ_List,notFoundList,validList,outputDir,getMethodSuccessList=None):
	os.chdir(outputDir)
	if isAuthN:
		fileName = getUniqueFilename("authN_Results-007",".txt")
	else:
		fileName = getUniqueFilename("authZ_Results-007",".txt")

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
		fileName = getUniqueFilename("authN_Results-007",".csv")
	else:
		fileName = getUniqueFilename("authZ_Results-007",".csv")

	with open(fileName,"w") as file:
		writer = csv.writer(file)
		writer.writerow(header)

		if isAuthN:
			writer.writerow(["[-]UN-AUTHENTICATED API"])
		else:
			writer.writerow(["[-]UNAUTHORIZED API"])

		for API in unauthNZ_List:
			writer.writerow([slNo, API[1], API[0],API[2]])   #API | Method | ResponseCode
			slNo+=1

		writer.writerows([[],["[-]NOT-FOUND API"]]) 
		for API in notFoundList:
			writer.writerow([slNo, API[1], API[0],API[2]])   #API | Method | ResponseCode
			slNo+=1

		if getMethodSuccessList:
			writer.writerows([[],["[-]GET APIs with ResponseCode 200"]]) 
			for API in getMethodSuccessList:
				writer.writerow([slNo, API[1], API[0],API[2]])   #API | Method | ResponseCode
				slNo+=1

		writer.writerows([[],["[-]SUCCESFULL API"]])
		for API in validList:
			writer.writerow([slNo, API[1], API[0],API[2]])   #API | Method | ResponseCode
			slNo+=1

	print(f"\n{GREEN}[-]Output Saved To: {csvDir}/{fileName}{ENDC}")
