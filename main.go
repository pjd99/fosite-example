package main

import (
	"fmt"
	"strings"
	"github.com/pjd99/oauth2-server/authorizationserver"
	"github.com/pjd99/oauth2-server/oauth2client"
	"github.com/pjd99/oauth2-server/resourceserver"
	"github.com/ory-am/fosite/storage"
	goauth "golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"github.com/dgrijalva/jwt-go"
	"log"
	"net/http"
	"os/exec"
	"encoding/json"
	"database/sql"
        _ "github.com/go-sql-driver/mysql"
)

// Struct for JSON reply to applications GET request
type Application1  struct {
    Eui         string    `json:"eui"`
    Name        string    `json:"name"`
    Owner       string    `json:"owner"`
    AccessKeys  []string  `json:"accessKeys"`
    Valid       bool      `json:"valid"`
}

// A valid oauth2 client (check the store) that additionally requests an OpenID Connect id token
var clientConf = goauth.Config{
	ClientID:     "ttnctl",
	ClientSecret: "",
	RedirectURL:  "http://localhost:3846/callback",
	Scopes:       []string{"offline"},
	Endpoint: goauth.Endpoint{
		TokenURL: "http://localhost:3846/users/token",
		AuthURL:  "http://localhost:3846/users/auth",
	},
}

// The same thing (valid oauth2 client) but for using the cliend credentials grant
var appClientConf = clientcredentials.Config{
	ClientID:     "ttnctl",
	ClientSecret: "",
	Scopes:       []string{"fosite"},
	TokenURL:     "http://localhost:3846/users/token",
}

var pubKey string = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41\nfGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7\nmCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBp\nHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2\nXrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3b\nODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy\n7wIDAQAB\n-----END PUBLIC KEY-----\n"

func main() {

	var db *sql.DB = storage.GetDatabase()
	defer db.Close()
	// navigation
	http.HandleFunc("/", HomeHandler(clientConf)) // show some links on the index

	// Token api
	http.HandleFunc("/key", PublicKeyHandler())

	// Application request handler
	http.HandleFunc("/applications", ApplicationReqHandler())

	// ### oauth2 server ###
	authorizationserver.RegisterHandlers() // the authorization server (fosite)

	// ### oauth2 client ###
	// the following handlers are oauth2 consumers
	http.HandleFunc("/client", oauth2client.ClientEndpoint(appClientConf)) // complete a client credentials flow
	http.HandleFunc("/owner", oauth2client.OwnerHandler(clientConf))       // complete a resource owner password credentials flow
	http.HandleFunc("/callback", oauth2client.CallbackHandler(clientConf)) // the oauth2 callback endpoint

	// ### protected resource ###
	http.HandleFunc("/protected", resourceserver.ProtectedEndpoint(appClientConf))

	fmt.Println("Please open your webbrowser at http://localhost:3846")
	_ = exec.Command("open", "http://localhost:3846").Run()
	log.Fatal(http.ListenAndServe(":3846", nil))
}

func ApplicationReqHandler() func(rw http.ResponseWriter, req *http.Request) {
        return func(rw http.ResponseWriter, req *http.Request){

		rw.Header().Set("Content-Type:", "application/json; charset=utf-8")

		var authString string

		var app1 = []Application1{}

		authString = req.Header.Get("Authorization")

		stringSlice := strings.Split(authString, " ")

		if len(stringSlice) == 2 {
			tokenType := stringSlice[0]
			authToken  := stringSlice[1]

			if tokenType == "bearer" {
				 // Parse takes the token string and a function for looking up the key. The latter is especially
                        	// useful if you use multiple keys for your application.  The standard is to use 'kid' in the
                        	// head of the token to identify which key to use, but the parsed token (head and claims) is provided
                       		// to the callback, providing flexibility.
                        	token, err := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
	                        	// Don't forget to validate the alg is what you expect:
        	                        if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
                	                        return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
                        	        }
                                	anoPubKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pubKey))
                                	if err != nil {
                                		fmt.Errorf("failed to parse DER encoded public key: " + err.Error())
                                	}
                                	return anoPubKey, nil
                        	})


                        	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
                                	email := claims["email"]

					var db *sql.DB = storage.GetDatabase()
					var databaseAppEUI  string
              				var databaseName  string
              				var databaseOwner  string
              				var databaseAccess_key  string
              				var databaseValid  int
					rows, err := db.Query("SELECT applications.app_eui, applications.name, applications.owner, applications.access_key, applications.valid FROM applications INNER JOIN user_application ON applications.app_eui = user_application.app_eui INNER JOIN users ON user_application.user_id = users.user_id WHERE users.email = ?", email)
					if err != nil {
              				       log.Fatal(err)
              				}
					defer rows.Close()

					for rows.Next() {
                      				err := rows.Scan(&databaseAppEUI, &databaseName, &databaseOwner, &databaseAccess_key, &databaseValid)
                      				if err != nil {
                              				log.Fatal(err)
                      				}
						var b bool
						if databaseValid >= 1{
							b = true
						} 
						a:=  Application1 {
                        				Eui:   databaseAppEUI,
                        				Name: databaseName,
                        				Owner: databaseOwner,
                        				AccessKeys: []string{databaseAccess_key},
                        				Valid: b }
                      				app1 = append(app1, a)
              				}
              				err = rows.Err()
              				if err != nil {
                      				log.Fatal(err)
              				}

                        	} else {
                                	fmt.Println(err)
                        	}


			}
		}

		json.NewEncoder(rw).Encode(app1)
	}
}

func PublicKeyHandler() func(rw http.ResponseWriter, req *http.Request) {
        return func(rw http.ResponseWriter, req *http.Request){ 
		mapA := map[string]string{"algorithm": "RS256", "key": pubKey}
        	//mapB, _ := json.Marshal(mapA)
		json.NewEncoder(rw).Encode(mapA)
	}
}
 


func HomeHandler(c goauth.Config) func(rw http.ResponseWriter, req *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		rw.Write([]byte(fmt.Sprintf(`
		<p>You can obtain an access token using various methods</p>
		<ul>
			<li>
				<a href="%s">Authorize code grant (with OpenID Connect)</a>
			</li>
			<li>
				<a href="%s">Implicit grant (with OpenID Connect)</a>
			</li>
			<li>
				<a href="/client">Client credentials grant</a>
			</li>
			<li>
				<a href="/owner">Resource owner password credentials grant</a>
			</li>
			<li>
				<a href="%s">Refresh grant</a>. <small>You will first see the login screen which is required to obtain a valid refresh token.</small>
			</li>
			<li>
				<a href="%s">Make an invalid request</a>
			</li>
		</ul>`,
			c.AuthCodeURL("some-random-state-foobar")+"&nonce=some-random-nonce",
			"http://localhost:3846/users/auth?client_id=my-client&redirect_uri=http%3A%2F%2Flocalhost%3A3846%2Fcallback&response_type=token%20id_token&scope=fosite%20openid&state=some-random-state-foobar&nonce=some-random-nonce",
			c.AuthCodeURL("some-random-state-foobar")+"&nonce=some-random-nonce",
			"/users/auth?client_id=my-client&scope=fosite&response_type=123&redirect_uri=http://localhost:3846/callback",
		)))
	}
}
