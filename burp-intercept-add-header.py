# what you need to know:
# - this will intercept http requests based on the destination url, look for a soap security header and update it to a new one
# - it requires a username and password
# - it wont probably work for you, soap is complicated and implementation of services differ, but it should be painful 
#   to tweak just a few lines to make it work (add a nonce? change namespaces? etc..) 

from burp import IBurpExtender
from burp import IHttpListener
 
from java.net import URL

from datetime import datetime
 
class BurpExtender(IBurpExtender, IHttpListener):

 
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Header fixer")
        callbacks.registerHttpListener(self)
        return
 
    def processHttpMessage(self, toolFlag, messageIsRequest, currentRequest):
        # only process requests
        if not messageIsRequest:
            return
        
        requestInfo = self._helpers.analyzeRequest(currentRequest)
        
        url = requestInfo.getUrl().toString()
        #print(url)
        if url.find('http://close-brothers-premium-finance-sta.sites.ac:80/') < 0 :
            return
        
        timestamp = datetime.now()
        print "Intercepting message at:", timestamp.isoformat()
         
        headers = requestInfo.getHeaders()
        newHeaders = list(headers) #it's a Java arraylist; get a python list
        #newHeaders.append("Timestamp: " + timestamp.isoformat())
        
        #add auth if not present:
        if not any("Authorization" in h for h in newHeaders):
            newHeaders.append("Authorization: Basic YWRtaW46cGFzc3dvcmQ=")
        
        hostIndex=[newHeaders.index(h) for h in newHeaders if "Host: " in h]
        if len(hostIndex) != 1:
            print('number of Host headers is %d - this is odd, stopping' % len(hostIndex))
            return
        
        newHost = 'localhost'
        
        if newHeaders[hostIndex[0]].find(newHost) < 0:
            print("Host set to %s - resetting to host %s" % (newHeaders[hostIndex[0]], newHost))
            newHeaders[hostIndex[0]] = 'Host: '+newHost
        
        bodyBytes = currentRequest.getRequest()[requestInfo.getBodyOffset():]
        bodyStr = self._helpers.bytesToString(bodyBytes)
        #newMsgBody = bodyStr + timestamp.isoformat()
        
        newMessage = self._helpers.buildHttpMessage(newHeaders, bodyStr)
         
        print "Sending modified message:"
        print "----------------------------------------------"
        print self._helpers.bytesToString(newMessage)
        print "----------------------------------------------\n\n"
         
        currentRequest.setRequest(newMessage)
        return
