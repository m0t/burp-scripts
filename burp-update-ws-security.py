# what you need to know:
# - this will intercept http requests based on the destination url, look for a soap security header and update it to a new one
# - it requires a username and password
# - it wont probably work for you, soap is complicated and implementation of services differ, but it should be painful 
#   to tweak just a few lines to make it work (add a nonce? change namespaces? etc..) 

from burp import IBurpExtender
from burp import IHttpListener
 
from java.net import URL
 
import suds.wsse as s
import re
from datetime import datetime

class BurpExtender(IBurpExtender, IHttpListener):

    def genSecurityHeader(self, username, password):
        #you'd think this just junk and wtf, but actually...
        wsse = ('wsse', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd')
        wsu = ('wsu', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd')

        security = s.Element('Security', ns=wsse)
        security.addPrefix('wsu','http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecuriaty-utility-1.0.xsd')

        # Create UsernameToken, Username/Pass Element
        token = s.Element('UsernameToken', ns=wsse)
        uname = s.Element('Username', ns=wsse).setText(username)
        passwd = s.Element('Password', ns=wsse).setText(password)
        token.insert(uname)
        token.insert(passwd)

        #you might need a nonce, you might need a time, you might need to take a bow and dance around the table,oh!
        #nonce = Element('Nonce', ns=wsu) and so on and so on
    
        ts = s.Timestamp()
    
        security.insert(ts.xml())
        security.insert(token)
        return security.plain()
    

    def update_soap_header(self, bodyStr, username, password):
        new_header = self.genSecurityHeader(username, password)
        
        if re.search('<wsse:Security.*<\/wsse:Security>',bodyStr, flags=re.DOTALL):
            print('found SOAP Security Header, modifying')
            print("New header:\n %s" % new_header)
            bodyStr = re.sub('<wsse:Security.*<\/wsse:Security>',new_header,bodyStr, flags=re.DOTALL)

        return bodyStr
 
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("SOAP WS-Security updater")
        callbacks.registerHttpListener(self)
        return
 
    def processHttpMessage(self, toolFlag, messageIsRequest, currentRequest):
        # only process requests
        if not messageIsRequest:
            return
        
        #XXX move somewhere else
        username = 'lalalala'
        password = 'lololo'
        
        requestInfo = self._helpers.analyzeRequest(currentRequest)
        
        url = requestInfo.getUrl().toString()
        #print(url)
        if url.find('example.com:443/somethingsomething/') < 0 :
            return
        
        timestamp = datetime.now()
        print "Intercepting message at:", timestamp.isoformat()
         
        headers = requestInfo.getHeaders()
        newHeaders = list(headers) #it's a Java arraylist; get a python list
        #newHeaders.append("Timestamp: " + timestamp.isoformat())
        
         
        bodyBytes = currentRequest.getRequest()[requestInfo.getBodyOffset():]
        bodyStr = self._helpers.bytesToString(bodyBytes)
        #newMsgBody = bodyStr + timestamp.isoformat()
        newMsgBody = self.update_soap_header(bodyStr, username, password)
        
        newMessage = self._helpers.buildHttpMessage(newHeaders, newMsgBody)
         
        print "Sending modified message:"
        print "----------------------------------------------"
        print self._helpers.bytesToString(newMessage)
        print "----------------------------------------------\n\n"
         
        currentRequest.setRequest(newMessage)
        return
