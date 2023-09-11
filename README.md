# Auth-Ninja

- For Automating the AuthN and AuthZ Testing of APIs. 
- Parses SwaggerFile (Json/Yaml) file and extracts all the APIs.

## Whats New
- Auth-NinjaV2 parses the Query Parametes along with the Request Body.
- If an example as been given in the swagger file, it extracts that as well.
- The values of the PathVariables are now referenced using the pathVaribles.json file
- The default values for parameters and requestbody can be set in the core/constants.py.

## Usage
```
-h, --help                  Show this help message and exit
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
-p, --proxy                 Set Proxy
-g <value>                  Set the default value for all the Path Variables in API
-po, --print-only           Parse the OpenAPI/Swagger File and only print all the API
-pop                        Parse the OpenAPI File, Replace PathVariables and then print it
 ```


## Examples

1)Authentication Test
> auth-ninja -f "/pathToSwagger.json" -u "http://host.com/"

2)Both Authentication and Authorization Test
> auth-ninja -f "/pathToSwagger.json" -u "http://host.com/" -z

3)Perform Only Authorization Test
> auth-ninja -f "/pathToSwagger.json" -u "http://host.com/" -z -n

4)If Input File is yaml
> auth-ninja -f "/pathToSwagger.yml" -u "http://host.com/" -y

5)OutputResults to CSV
> auth-ninja -f "/pathToSwagger.json" -u "http://host.com/" -c .

6)Print All the APIs
> auth-ninja -f "/pathToSwagger.json" -u "http://host.com/" -pop


## Note
- Auth-Ninja V2 has still not been tested with adequate swagger files
- The old V1 app can still be found in deprecated/auth-ninja-v1.py 

## Additional
> Use https://github.com/sickuritywizard/urlsToSwagger-007 to convert URL List to Swagger Docs
