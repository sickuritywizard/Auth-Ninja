import os

def getUniqueFilename(fileName,ext):
	if not os.path.exists(fileName+ext):
		return fileName+ext
	else:
		fileName = fileName+"_{}"
		counter = 1
		while os.path.exists(fileName.format(counter)+ext):
			counter += 1
		fileName = fileName.format(counter)

	return fileName+ext
