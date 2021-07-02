# KnownUser.V3.Python
Before getting started please read the [documentation](https://github.com/queueit/Documentation/tree/main/serverside-connectors) to get acquainted with server-side connectors.

Connector was developed and verified with Python v.2.7 and Django v.1.8. Please reach out to us if you are using another web framework, so we add it to the supported providers.

You can find the latest released version [here](https://github.com/queueit/KnownUser.V3.Python/releases/latest)

## Implementation
The KnownUser validation must be done on *all requests except requests for static and cached pages, resources like images, css files and ...*. 
So, if you add the KnownUser validation logic to a central place, then be sure that the Triggers only fire on page requests (including ajax requests) and not on e.g. image.

If we have the `integrationconfig.json` copied  in the folder beside other knownuser files inside web application folder then 
the following method (using Django v.1.8) is all that is needed to validate that a user has been through the queue:
 
```python
from django.http import HttpResponse

import django
import sys
import re

from queueit_knownuserv3.http_context_providers import Django_1_8_Provider
from queueit_knownuserv3.models import QueueEventConfig
from queueit_knownuserv3.known_user import KnownUser


def index(request):
    try:
        with open('integrationconfiguration.json', 'r') as myfile:
            integrationsConfigString = myfile.read()

        customerId = "" # Your Queue-it customer ID
        secretKey = "" # Your 72 char secret key as specified in Go Queue-it self-service platform

        response = HttpResponse()
        httpContextProvider = Django_1_8_Provider(request, response)
        requestUrl = httpContextProvider.getOriginalRequestUrl()
        requestUrlWithoutToken = re.sub(
            "([\\?&])(" + KnownUser.QUEUEIT_TOKEN_KEY + "=[^&]*)",
            '',
            requestUrl,
            flags=re.IGNORECASE)
        # The requestUrlWithoutToken is used to match Triggers and as the Target url (where to return the users to).
        # It is therefor important that this is exactly the url of the users browsers. So, if your webserver is
        # behind e.g. a load balancer that modifies the host name or port, reformat requestUrlWithoutToken before proceeding.

        queueitToken = request.GET.get(KnownUser.QUEUEIT_TOKEN_KEY)

        validationResult = KnownUser.validateRequestByIntegrationConfig(
            requestUrlWithoutToken, queueitToken, integrationsConfigString,
            customerId, secretKey, httpContextProvider)

        if (validationResult.doRedirect()):
            response["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response["Pragma"] = "no-cache"
	    response["Expires"] = "Fri, 01 Jan 1990 00:00:00 GMT"

            if (not validationResult.isAjaxResult):
                response.status_code = 302
                response["Location"] = validationResult.redirectUrl                                
            else:
                headerKey = validationResult.getAjaxQueueRedirectHeaderKey()
                response[headerKey] = validationResult.getAjaxRedirectUrl()                
        else:
            # Request can continue, we remove queueittoken from url to avoid sharing of user specific token
            if (requestUrl != requestUrlWithoutToken and validationResult.actionType == "Queue"):
                response.status_code = 302
                response["Location"] = requestUrlWithoutToken                
            
        return response

    except StandardError as stdErr:
        # There was an error validating the request
        # Use your own logging framework to log the error
        # This was a configuration error, so we let the user continue
        print stdErr.message        
```

## Implementation using inline queue configuration
Specify the configuration in code without using the Trigger/Action paradigm. In this case it is important *only to queue-up page requests* and not requests for resources. 
This can be done by adding custom filtering logic before caling the `KnownUser.resolveQueueRequestByLocalConfig()` method. 

The following is an example (using Django v.1.8) of how to specify the configuration in code:

```python
from django.http import HttpResponse

import django
import sys
import re

from queueit_knownuserv3.http_context_providers import Django_1_8_Provider
from queueit_knownuserv3.models import QueueEventConfig
from queueit_knownuserv3.known_user import KnownUser


def index(request):
    try:
        
        customerId = "" # Your Queue-it customer ID
        secretKey = "" # Your 72 char secret key as specified in Go Queue-it self-service platform

	queueConfig = QueueEventConfig()
	queueConfig.eventId = "" # ID of the queue to use
	queueConfig.queueDomain = "xxx.queue-it.net" #Domain name of the queue.
	# queueConfig.cookieDomain = ".my-shop.com" #Optional - Domain name where the Queue-it session cookie should be saved
	queueConfig.cookieValidityMinute = 15 #Validity of the Queue-it session cookie should be positive number.
	queueConfig.extendCookieValidity = true #Should the Queue-it session cookie validity time be extended each time the validation runs?
	# queueConfig.culture = "da-DK" #Optional - Culture of the queue layout in the format specified here: https://msdn.microsoft.com/en-us/library/ee825488(v=cs.20).aspx.  If unspecified then settings from Event will be used.
	# queueConfig.layoutName = "NameOfYourCustomLayout" #Optional - Name of the queue layout. If unspecified then settings from Event will be used.
	response = HttpResponse()
        httpContextProvider = Django_1_8_Provider(request, response)
        requestUrl = httpContextProvider.getOriginalRequestUrl()
        requestUrlWithoutToken = re.sub(
            "([\\?&])(" + KnownUser.QUEUEIT_TOKEN_KEY + "=[^&]*)",
            '',
            requestUrl,
            flags=re.IGNORECASE)
        # The requestUrlWithoutToken is used to match Triggers and as the Target url (where to return the users to).
        # It is therefor important that this is exactly the url of the users browsers. So, if your webserver is
        # behind e.g. a load balancer that modifies the host name or port, reformat requestUrlWithoutToken before proceeding.

        queueitToken = request.GET.get(KnownUser.QUEUEIT_TOKEN_KEY)

	validationResult = KnownUser.resolveQueueRequestByLocalConfig(
            requestUrlWithoutToken, queueitToken, queueConfig, customerId, secretKey,
            httpContextProvider)

        if (validationResult.doRedirect()):
            response["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response["Pragma"] = "no-cache"
	    response["Expires"] = "Fri, 01 Jan 1990 00:00:00 GMT"
	    
	     if (not validationResult.isAjaxResult):
                response.status_code = 302
                response["Location"] = validationResult.redirectUrl                                
            else:
                headerKey = validationResult.getAjaxQueueRedirectHeaderKey()
                response[headerKey] = validationResult.getAjaxRedirectUrl()     
        else:
            # Request can continue, we remove queueittoken from url to avoid sharing of user specific token
            if (requestUrl != requestUrlWithoutToken and validationResult.actionType == "Queue"):
                response.status_code = 302
                response["Location"] = requestUrlWithoutToken
            
	return response

    except StandardError as stdErr:
        # There was an error validating the request
        # Use your own logging framework to log the error
        # This was a configuration error, so we let the user continue
        print stdErr.message        
```
