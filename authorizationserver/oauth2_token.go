package authorizationserver

import (
	"github.com/ory-am/fosite"
	"log"
	"net/http"
)

func tokenEndpoint(rw http.ResponseWriter, req *http.Request) {
	// This context will be passed to all methods.

	ctx := fosite.NewContext()

	// Create an empty session object which will be passed to the request handlers
	mySessionData := newSession("578e280b2629a7da0416303b")

	mySessionData.JWTClaims.Add("email", "pauldoherty@rfproximity.com")
	mySessionData.JWTClaims.Add("scope", []string{"profile", "apps"})
	mySessionData.JWTClaims.Add("client", "ttnctl")
	mySessionData.JWTClaims.Add("username", "pjd99")
	mySessionData.JWTClaims.Add("created", "2015-11-12T13:12:27.332Z")
	mySessionData.JWTClaims.Add("name", map[string]string{"last": "Doherty", "first": "Paul"})
	mySessionData.JWTClaims.Add("valid", true)
	mySessionData.JWTClaims.Add("_id", "578e280b2629a7da0416303b")
	mySessionData.JWTClaims.Add("apps", []string{"70B3D57ED000124B"})

	log.Printf("Session data:  %s\n", mySessionData)
	
	// This will create an access request object and iterate through the registered TokenEndpointHandlers to validate the request.
	accessRequest, err := oauth2.NewAccessRequest(ctx, req, mySessionData)

	log.Printf("Request info: %s", req)


	// Catch any errors, e.g.:
	// * unknown client
	// * invalid redirect
	// * ...
	if err != nil {
		log.Printf("Error occurred in NewAccessRequest: %s\nStack: \n%s", err, err.(stackTracer).StackTrace())
		oauth2.WriteAccessError(rw, accessRequest, err)
		return
	} else {
		currentSession := accessRequest.GetSession()
        	if currentSession != nil {
                	userName :=  currentSession.GetUsername()
                	log.Printf("Uname or email: %s\n", userName)
			log.Printf("Session data:  %s\n", currentSession)
        	}
	}

	// Grant requested scopes
	for _, scope := range accessRequest.GetRequestedScopes() {
		accessRequest.GrantScope(scope)
	}

	// Next we create a response for the access request. Again, we iterate through the TokenEndpointHandlers
	// and aggregate the result in response.
	response, err := oauth2.NewAccessResponse(ctx, req, accessRequest)
	if err != nil {
		log.Printf("Error occurred in NewAccessResponse: %s\nStack: \n%s", err, err.(stackTracer).StackTrace())
		oauth2.WriteAccessError(rw, accessRequest, err)
		return
	}

	// All done, send the response.
	oauth2.WriteAccessResponse(rw, accessRequest, response)

	// The client now has a valid access token
}
