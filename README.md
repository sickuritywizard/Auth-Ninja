# AuthNZ-Tester-007

- For Automating the AuthN and AuthZ Test of APIs. 
- Parses SwaggerFile (Json/Yaml) file and extracts all the APIs.

## Usage
```
Hardcode the values in the script, or provide respective flags.

-h, --help                  show this help message and exit
-i, --ip IP                 Target IP [Provide IP or URL]
-u, --url BASEURL.          Base URL [Ex:http://host.com/api/v2 {No Trailing Slash}]
-f, --file SWAGGERFILE      Swagger File Location
-s, --sessionID SESSIONID   Session ID of Low Privileged User for AuthZ Check
-o , --output OUTPUTDIR     Output Directory (Default: Output is not saved)
-c , --csv CSVDIR           Output Directory for CSV File (Default: Output is not saved)
-y, --yaml                  Use if Input file Is Yaml [Default: Json]
-v, --verbose               Disable Verbose Output
-z, --authz                 Run AuthZ Check [Default False]
-n, --noauthn               Disable Authentication Test
 ```


## Examples

1)Authentication Test
> authNZ-Tester-007.py -f "/pathToSwagger.json" -u "http://host.com/api/v1"

2)Both Authentication and Authorization Test
> authNZ-Tester-007.py -f "/pathToSwagger.json" -u "http://host.com/api/v1" -z

3)Only Authorization Test
> authNZ-Tester-007.py -f "/pathToSwagger.json" -u "http://host.com/api/v1" -z -n

4)If input File is yaml
> authNZ-Tester-007.py -f "/pathToSwagger.yml" -u "http://host.com/api/v1" -y

5)OutputResults to CSV
> authNZ-Tester-007.py -f "/pathToSwagger.json" -u "http://host.com/api/v1" -c "OutputDirectory/"

