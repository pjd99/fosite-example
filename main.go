package main

import (
	"fmt"
	"strings"
	"reflect"
	"strconv"
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

// Struct for JSON reply to applications GET request
type User  struct {
	UserID            int       `json:"userid"`
    FirstName         string    `json:"first"`
    LastName          string    `json:"last"`
    UserName          string    `json:"user"`
    Email             string     `json:"email"`
    Scope             string      `json:"scope"`
	UserApps         []string     `json:"userapps"`
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

	// Application request handler for GET and POST
	http.HandleFunc("/applications", ApplicationReqHandler())
	// Application request handler DELETE
	http.HandleFunc("/applications/", DeleteApplicationReqHandler())

	// users request handler GET list all if admin
	http.HandleFunc("/users", UsersReqHandler())
	
	// user request handler for GET, PUT and DELETE if admin
	http.HandleFunc("/user/", UserReqHandler())
	
	// user request handler for POST if admin
	http.HandleFunc("/user", UserReqHandler())
	
	// link user - application request handler for GET, PUT and DELETE if admin
	http.HandleFunc("/link/", LinkReqHandler())

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
			
		var authString string
			
		authString = req.Header.Get("Authorization")

		stringSlice := strings.Split(authString, " ")
			
		if req.Method == "GET" {

			rw.Header().Set("Content-Type:", "application/json; charset=utf-8")
		
			var app1 = []Application1{}
		
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
                            scope := claims["scope"]
							fmt.Printf("scope list %s\n", scope)
							
							var isAdmin bool = false
							
							switch reflect.TypeOf(scope).Kind() {
								case reflect.Slice:
									s := reflect.ValueOf(scope)
		                           fmt.Println("In scope Slice case")
									
									for i := 0; i < s.Len(); i++ {
										fmt.Println("In scope for loop")
										fmt.Printf("scope list %s\n", s.Index(i).Interface())
										if s.Index(i).Interface() == "admin"{
											fmt.Printf("scope list %s\n", scope)
											isAdmin = true
										}
									}
							}
							
							var db *sql.DB = storage.GetDatabase()
							var databaseAppEUI  string
              				var databaseName  string
              				var databaseOwner  string
              				var databaseAccess_key  string
              				var databaseValid  int
							
							
							if isAdmin {
								
								rows, err := db.Query("SELECT applications.app_eui, applications.name, applications.owner, applications.access_key, applications.valid FROM applications")
								if err != nil {
						            http.Error(rw, "Server error, unable to access applications.", 500)
									fmt.Printf("SQL err select applications: %s\n", err)   
						            return
	              				}
								defer rows.Close()

								for rows.Next() {
	                      			err := rows.Scan(&databaseAppEUI, &databaseName, &databaseOwner, &databaseAccess_key, &databaseValid)
	                      			if err != nil {
							            http.Error(rw, "Server error, unable to access applications.", 500)
										fmt.Printf("SQL err select applications: %s\n", err)   
							            return
	                      			}
									var b bool
									if databaseValid >= 1{
										b = true
									} 
									a:=  Application1 {
	                        			Eui: databaseAppEUI,
	                        			Name: databaseName,
	                        			Owner: databaseOwner,
	                        			AccessKeys: []string{databaseAccess_key},
	                        			Valid: b }
	                      				app1 = append(app1, a)
	              					}
	              					err = rows.Err()
	              					if err != nil {
							            http.Error(rw, "Server error, unable to access applications.", 500)
										fmt.Printf("SQL err select applications: %s\n", err)   
							            return
	              					}
								
							} else {
								
								rows, err := db.Query("SELECT applications.app_eui, applications.name, applications.owner, applications.access_key, applications.valid FROM applications INNER JOIN user_application ON applications.app_eui = user_application.app_eui INNER JOIN users ON user_application.user_id = users.user_id WHERE users.email = ?", email)
								if err != nil {
						            http.Error(rw, "Server error, unable to access applications.", 500)
									fmt.Printf("SQL err select applications: %s\n", err)   
						            return
	              				}
								defer rows.Close()

								for rows.Next() {
	                      			err := rows.Scan(&databaseAppEUI, &databaseName, &databaseOwner, &databaseAccess_key, &databaseValid)
	                      			if err != nil {
							            http.Error(rw, "Server error, unable to access applications.", 500)
										fmt.Printf("SQL err select applications: %s\n", err)   
							            return
	                      			}
									var b bool
									if databaseValid >= 1{
										b = true
									} 
									a:=  Application1 {
	                        			Eui: databaseAppEUI,
	                        			Name: databaseName,
	                        			Owner: databaseOwner,
	                        			AccessKeys: []string{databaseAccess_key},
	                        			Valid: b }
	                      				app1 = append(app1, a)
	              					}
	              					err = rows.Err()
	              					if err != nil {
							            http.Error(rw, "Server error, unable to access applications.", 500)
										fmt.Printf("SQL err select applications: %s\n", err)   
							            return
	              					}
							}
                    	} else {
                            fmt.Printf("Invalid Token %s\n", err)   
				            http.Error(rw, "Server error, Invalid Token.", 500)    
				            return
                        }
			}
		}
		// Send Application details
		json.NewEncoder(rw).Encode(app1)
		
		
		} else if req.Method == "POST" {
			// Valiate token
			// Get values name and EUI
		
			req.ParseForm()
		
			appName := req.Form.Get("name")
			appEUI := req.Form.Get("appeui")
		
			fmt.Printf("POST App Name: %s\n", appName)
			fmt.Printf("POST App Eui: %s\n", appEUI)
		    
			if (appName == "" || appEUI == "") {
	            http.Error(rw, "Server error, unable to create your account.", 500)
				fmt.Println("Post Data for AppEUI or App Name empty")      
	            return
			}
		// add application to DB for this user 
		
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
						
						//Check APP EUI does not exist in DB 
						
						//ADD App EUI to DB and link to user
						
						var db *sql.DB = storage.GetDatabase()
						
						var databaseAppEUI  string
						
						var accessCode = "AfRmGNnMzWO4FpZ0QezbBPIm5JmgE0Z9tC6SoyUVCNw="
						
						// Check if APP EUI exists
						err := db.QueryRow("SELECT app_eui FROM applications WHERE app_eui=?", appEUI).Scan(&databaseAppEUI)
						if err == sql.ErrNoRows {
					        // Insert APP EUI and add to user_application table
					        _, err = db.Exec("INSERT INTO applications(app_eui, name, owner, access_key, valid) VALUES(?, ?, ?, ?, ?)", appEUI, appName, email, accessCode, 1)
					        if err != nil {
					            http.Error(rw, "Server error, unable to create your account.", 500)
								fmt.Printf("SQL err insert applications: %s\n", err)   
					            return
					        }
							
					        _, err = db.Exec("INSERT INTO user_application (user_id, app_eui) SELECT user_id, ? FROM users WHERE email = ?", appEUI, email)
					        if err != nil {
					            http.Error(rw, "Server error, unable to create your account.", 500)
								fmt.Printf("SQL err insert into user_application: %s\n", err)     
					            return
					        }
							
							rw.WriteHeader(http.StatusCreated)
					        rw.Write([]byte("Application created!"))
					        return
							
						} else {
				            http.Error(rw, "Server error, unable to create your account.", 500)
							fmt.Printf("SQL Error App EUI already exists: %s\n", err)    
				            return
						}
					} else {
                                fmt.Printf("Invalid Token %s\n", err)   
					            http.Error(rw, "Server error, unable to create your account.", 500)    
					            return
                    }
			}
		} else {
            http.Error(rw, "Server error, unable to create your account.", 500)
			fmt.Println("Auth bearer incorrect length when split")      
            return
		}
	}
  }
}

func DeleteApplicationReqHandler() func(rw http.ResponseWriter, req *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request){
	
		if req.Method == "DELETE" {
		
			var authString string
			
			authString = req.Header.Get("Authorization")

			stringSlice := strings.Split(authString, " ")
			
			appEUI := req.URL.Path[len("/applications/"):]
			
			fmt.Printf("DELETE App Name: %s\n", appEUI)
			
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
							fmt.Printf("Deleting application for account: %s\n", email) 
						
							var db *sql.DB = storage.GetDatabase()

							var databaseAppEUI  string
							// Check if APP EUI exists
							err := db.QueryRow("SELECT app_eui FROM applications WHERE app_eui=?", appEUI).Scan(&databaseAppEUI)
							if err == sql.ErrNoRows {
					            http.Error(rw, "Server error, unable to delete your account.", 500)
								fmt.Printf("SQL Error App EUI does not exist: %s\n", err)    
					            return
							
							} else {
						        _, err = db.Exec("DELETE FROM user_application WHERE app_eui = ?", appEUI)
						        if err != nil {
						            http.Error(rw, "Server error, unable to delete your account.", 500)
									fmt.Printf("SQL err delete from user_application: %s\n", err)     
						            return
						        }
								
						        // Delete APP EUI from user_application table
						        _, err = db.Exec("DELETE FROM applications WHERE app_eui = ?", appEUI)
						        if err != nil {
						            http.Error(rw, "Server error, unable to delete your account.", 500)
									fmt.Printf("SQL err could not delete application: %s\n", err)   
						            return
						        }
							
								rw.WriteHeader(http.StatusOK)
						        rw.Write([]byte("Application deleted!"))
						        return
							}
						} else {
	                                fmt.Printf("Invalid Token %s\n", err)   
						            http.Error(rw, "Server error, unable to delete your account.", 500)    
						            return
	                    }
				}
			} else {
	            http.Error(rw, "Server error, unable to create your account.", 500)
				fmt.Println("Auth bearer incorrect length when split")      
	            return
			}
		
		
		
		}
	
	}
}

func UsersReqHandler() func(rw http.ResponseWriter, req *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request){
	
		var authString string
			
		authString = req.Header.Get("Authorization")

		stringSlice := strings.Split(authString, " ")
			
		if req.Method == "GET" {

			rw.Header().Set("Content-Type:", "application/json; charset=utf-8")
			
		
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

						var users = []User{}

                        if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
                            scope := claims["scope"]
							fmt.Printf("scope list %s\n", scope)
							switch reflect.TypeOf(scope).Kind() {
								case reflect.Slice:
									s := reflect.ValueOf(scope)
		                           fmt.Println("In scope Slice case")
									
									for i := 0; i < s.Len(); i++ {
										fmt.Println("In scope for loop")
										fmt.Printf("scope list %s\n", s.Index(i).Interface())
										if s.Index(i).Interface() == "admin"{
											fmt.Printf("scope list %s\n", scope)
											
											var db *sql.DB = storage.GetDatabase()
											
											var databaseUserID     int
											var databaseFirstName  string
					              			var databaseLastName   string
					              			var databaseUserName   string
					              			var databaseEmail      string
					              			var databaseScope      string
											rows, err := db.Query("SELECT user_id, first_name, last_name, email, user_name, scope FROM users ORDER BY last_name")
											defer rows.Close()



											for rows.Next() {
				                      			err := rows.Scan(&databaseUserID, &databaseFirstName, &databaseLastName, &databaseEmail, &databaseUserName, &databaseScope)
				                      			if err != nil {
										            http.Error(rw, "Server error, unable to access users.", 500)
													fmt.Printf("SQL err select from users: %s\n", err)     
										            return
				                      			}
												
												a:=  User {
													UserID:    databaseUserID,
				                        			FirstName: databaseFirstName,
				                        			LastName:  databaseLastName,
				                        			UserName:  databaseUserName,
				                        			Email:     databaseEmail,
				                        			Scope:     databaseScope }
				                      				
												users = append(users, a)
				              					
											}
											
				              				err = rows.Err()
				              				if err != nil {
												http.Error(rw, "Server error, unable to access users.", 500)
												fmt.Printf("SQL err select from users: %s\n", err)     
												return
				              				}
											
										}
											
									}
								default:
						            http.Error(rw, "Server error, Scope value not array.", 500)
									fmt.Println("Server error, Scope value not array")    
						            return
							}	
						}  else {
	                                fmt.Printf("Invalid Token %s\n", err)   
						            http.Error(rw, "Server error, unable to obtain user account.", 500)    
						            return
	                    }
						json.NewEncoder(rw).Encode(users)
						return
						// Send user details
				}  else {
	            http.Error(rw, "Server error, unable to list users.", 500)
				fmt.Println("No bearer token label")      
	            return
			}
			} else {
	            http.Error(rw, "Server error, unable to list users.", 500)
				fmt.Println("Auth bearer incorrect length when split")      
	            return
			}
		}

	}
}

func UserReqHandler() func(rw http.ResponseWriter, req *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request){
		
		var authString string
			
		authString = req.Header.Get("Authorization")

		stringSlice := strings.Split(authString, " ")
		
		var userString string
		
		var userID int
		
		if req.Method != "POST" {
			
			userString = req.URL.Path[len("/user/"):]
			
			if v, err := strconv.Atoi(userString); err == nil {
				userID = v
			} else {
				fmt.Printf("Invalid or missing UserID %s\n", err)   
				http.Error(rw, "Server error, Invalid or missing UserID.", 500)    
				return
			}
			
		}
		
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
                        scope := claims["scope"]
						
						
						// get user details
						if req.Method == "GET" {
			
							rw.Header().Set("Content-Type:", "application/json; charset=utf-8")
							var user User
							
							fmt.Printf("scope list %s\n", scope)
							switch reflect.TypeOf(scope).Kind() {
								case reflect.Slice:
									s := reflect.ValueOf(scope)
		                           fmt.Println("In scope Slice case")
							
									for i := 0; i < s.Len(); i++ {
										fmt.Println("In scope for loop")
										fmt.Printf("scope list %s\n", s.Index(i).Interface())
										if s.Index(i).Interface() == "admin"{
											fmt.Printf("scope list %s\n", scope)
									
											var db *sql.DB = storage.GetDatabase()
											var databaseUserID     int
											var databaseFirstName  string
					              			var databaseLastName   string
					              			var databaseUserName   string
					              			var databaseEmail      string
					              			var databaseScope      string
											
											var databaseUserApplication  string
									
											err := db.QueryRow("SELECT user_id, first_name, last_name, email, user_name, scope FROM users WHERE user_id=?", userID).Scan(&databaseUserID, &databaseFirstName, &databaseLastName, &databaseEmail, &databaseUserName, &databaseScope)
											if err == sql.ErrNoRows {
									            http.Error(rw, "Server error, unable to find user account.", 500)
												fmt.Printf("SQL Error userID does not exist: %s\n", err)    
									            return
					
											}
											
											
											rows, err1 := db.Query("SELECT app_eui FROM user_application WHERE user_id=?", userID)
											if err1 != nil {
									            http.Error(rw, "Server error, unable to access user applications.", 500)
												fmt.Printf("SQL err select user applications: %s\n", err1)   
									            return
				              				}
											defer rows.Close()
											
											var userApps []string

											for rows.Next() {
				                      			err := rows.Scan(&databaseUserApplication)
				                      			if err != nil {
										            http.Error(rw, "Server error, unable to access applications.", 500)
													fmt.Printf("SQL err select applications: %s\n", err)   
										            return
				                      			}
												
												userApps = append(userApps, databaseUserApplication)
												
				              				}
				              					
											err = rows.Err()
				              				if err != nil {
										        http.Error(rw, "Server error, unable to access user applications.", 500)
												fmt.Printf("SQL err select user applications: %s\n", err)   
										        return
				              				}
												
											
											
											fmt.Printf("Int no %s\n", userID)   
											user.UserID =  databaseUserID
		                        			user.FirstName = databaseFirstName
		                        			user.LastName = databaseLastName
		                        			user.UserName = databaseUserName
		                        			user.Email =   databaseEmail
		                        			user.Scope =   databaseScope
											user.UserApps = userApps
									
										}
									}
								default:
						            http.Error(rw, "Server error, Scope value not array.", 500)
									fmt.Println("Server error, Scope value not array")    
						            return
								}
						
								json.NewEncoder(rw).Encode(user)
								return
	                    
						}
						
						// Create new user
						if req.Method == "POST" {
							
							req.ParseForm()
							
                			firstName := req.Form.Get("firstname")
                			lastName := req.Form.Get("lastname")
                			userName := req.Form.Get("username")
							password := req.Form.Get("password")
                			email :=   req.Form.Get("email")
                			userScope :=   req.Form.Get("scope") 
		
							fmt.Printf("POST user email: %s\n", email)
		    
							if (email == "" || scope == "") {
					            http.Error(rw, "Server error, unable to create user.", 500)
								fmt.Println("Post Data for email or scope values empty")      
					            return
							}
							fmt.Printf("scope list %s\n", scope)
							switch reflect.TypeOf(scope).Kind() {
								case reflect.Slice:
									s := reflect.ValueOf(scope)
									fmt.Println("In scope Slice case")
									for i := 0; i < s.Len(); i++ {
										if s.Index(i).Interface() == "admin"{
											fmt.Println("User is admin for POST")
											var db *sql.DB = storage.GetDatabase()
											
											// Check if user email already exists
											var databaseEmail      string
											err := db.QueryRow("SELECT email FROM users WHERE email=?", email).Scan(&databaseEmail)
											if err == sql.ErrNoRows {
										        // Insert user
												fmt.Println("Attempting User INSERT")
										        _, err = db.Exec("INSERT INTO users (first_name, last_name, password, email, user_name, scope) VALUES(?, ?, ?, ?, ?, ?)", firstName, lastName, password, email, userName, userScope)
										        if err != nil {
										            http.Error(rw, "Server error, unable to create user.", 500)
													fmt.Printf("SQL err on insert user: %s\n", err)   
										            return
										        }
												
												err = authorizationserver.ReloadUsers(email, password)
										        if err != nil {
										            http.Error(rw, "Server error, unable to add user to oauth2 store.", 500)
													fmt.Printf("Server error, unable to add user to oauth2 store: %s\n", err)   
										            return
										        }
												
												rw.WriteHeader(http.StatusCreated)
										        rw.Write([]byte("User created!"))
										        return
							
											} else {
									            http.Error(rw, "Server error, unable to create your account.", 500)
												fmt.Printf("SQL Error email already exists: %s\n", err)    
									            return
											}
											
											
										}
									}
								default:
						            http.Error(rw, "Server error, Scope value not array.", 500)
									fmt.Println("Server error, Scope value not array")    
						            return
								}
							
						}
						
						if req.Method == "DELETE" {
							
							
							fmt.Printf("scope list %s\n", scope)
							switch reflect.TypeOf(scope).Kind() {
								case reflect.Slice:
									s := reflect.ValueOf(scope)
									fmt.Println("In scope Slice case")
									for i := 0; i < s.Len(); i++ {
										if s.Index(i).Interface() == "admin"{
											fmt.Println("User is admin for DELETE")
											var db *sql.DB = storage.GetDatabase()

											// Check if user email already exists
											var databaseEmail      string
											var databasePassword     string
											err := db.QueryRow("SELECT email, password FROM users WHERE user_id=?", userID).Scan(&databaseEmail, &databasePassword)
											if err == sql.ErrNoRows {
									            http.Error(rw, "Server error, unable to delete user.", 500)
												fmt.Printf("SQL Error user_id does not exist: %s\n", err)    
									            return
							
											} else {
												// delete from user/applcation table if exists
										        _, err = db.Exec("DELETE FROM user_application WHERE user_id = ?", userID)
										        if err != nil {
										            http.Error(rw, "Server error, unable to delete user.", 500)
													fmt.Printf("SQL err delete from user_application: %s\n", err)     
										            return
										        }
												// delete user
										        _, err = db.Exec("DELETE FROM users WHERE user_id = ?", userID)
										        if err != nil {
										            http.Error(rw, "Server error, unable to delete user.", 500)
													fmt.Printf("SQL err delete from users: %s\n", err)     
										            return
										        }
												
												err = authorizationserver.ReloadUsers(databaseEmail, databasePassword)
										        if err == nil {
										            http.Error(rw, "Server error, unable to delete user to oauth2 store.", 500)
													fmt.Printf("Server error, unable to add delete to oauth2 store: %s\n", err)   
										            return
										        }
												
												rw.WriteHeader(http.StatusOK)
										        rw.Write([]byte("User deleted!"))
										        return
											
											
										}
									}
								}
								default:
									http.Error(rw, "Server error, Scope value not array.", 500)
									fmt.Println("Server error, Scope value not array")    
									return
							}
						}
						
						if req.Method == "PUT" {
							
							req.ParseForm()
							
                			firstName := req.Form.Get("firstname")
                			lastName := req.Form.Get("lastname")
                			userName := req.Form.Get("username")
							password := req.Form.Get("password")
                			email :=   req.Form.Get("email")
                			userScope :=   req.Form.Get("scope") 
		
							fmt.Printf("POST user email: %s\n", email)
		    
							if (email == "" || userScope == "" || firstName == "" || lastName == "" || password == "" || userName == "" ) {
					            http.Error(rw, "Server error, unable to update user.", 500)
								fmt.Println("PUT Data for email or scope values empty")      
					            return
							}
							fmt.Printf("scope list %s\n", scope)
							switch reflect.TypeOf(scope).Kind() {
								case reflect.Slice:
									s := reflect.ValueOf(scope)
									fmt.Println("In scope Slice case")
									for i := 0; i < s.Len(); i++ {
										if s.Index(i).Interface() == "admin"{
											fmt.Println("User is admin for PUT")
											var db *sql.DB = storage.GetDatabase()
											
											// Check if user email already exists
											var databaseEmail      string
											err := db.QueryRow("SELECT email FROM users WHERE user_id=?", userID).Scan(&databaseEmail)
											if err == sql.ErrNoRows {
												
									            http.Error(rw, "Server error, unable to update user.", 500)
												fmt.Printf("SQL Error user does not exist: %s\n", err)    
									            return
												
											} else {
										        // UPDATE user
												fmt.Println("Attempting User UPDATE")
										        _, err = db.Exec("UPDATE users SET first_name=?, last_name=?, password=?, email=?, user_name=?, scope=? WHERE user_id=?", firstName, lastName, password, email, userName, userScope, userID)
										        if err != nil {
										            http.Error(rw, "Server error, unable to update user.", 500)
													fmt.Printf("SQL err on update user: %s\n", err)   
										            return
										        }
												
												err = authorizationserver.ReloadUsers(email, password)
										        if err != nil {
										            http.Error(rw, "Server error, unable to update user to oauth2 store.", 500)
													fmt.Printf("Server error, unable to add update to oauth2 store: %s\n", err)   
										            return
										        }
												
												rw.WriteHeader(http.StatusOK)
										        rw.Write([]byte("User updated!"))
										        return
											}
											
											
										}
									}
								default:
						            http.Error(rw, "Server error, Scope value not array.", 500)
									fmt.Println("Server error, Scope value not array")    
						            return
								}
						}	
					} else {
						fmt.Printf("Invalid Token %i\n", err)   
						http.Error(rw, "Server error, unable to obtain user account.", 500)    
						return
					}
					
				} else {
					http.Error(rw, "Server error, unable to list users.", 500)
					fmt.Println("No bearer token label")
					return
				}
		
		} else {
			http.Error(rw, "Server error, unable to list users.", 500)
			fmt.Println("Auth bearer incorrect length when split")      
			return
		}
		
		
	}
}

func LinkReqHandler() func(rw http.ResponseWriter, req *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request){
		
		var authString string
		
		var userString string
		
		var userID int
		
		var appEUI string 
			
		authString = req.Header.Get("Authorization")

		stringSlice := strings.Split(authString, " ")
		
		urlPart := req.URL.Path[len("/link/"):]

		urlSplit := strings.Split(urlPart, "/")
		
		appEUI = urlSplit[0]
		
		userString = urlSplit[1]
		
		if (appEUI == "" || userString == "") {
            http.Error(rw, "Server error, unable to update user.", 500)
			fmt.Println("URL Data for appEUI or UserID values empty")      
            return
		}
		
		if v, err := strconv.Atoi(userString); err == nil {
			userID = v
		} else {
			fmt.Printf("Invalid or missing UserID %s\n", err)   
			http.Error(rw, "Server error, Invalid or missing UserID.", 500)    
			return
		}
		
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
                        scope := claims["scope"]
						
						if req.Method == "POST" {
							fmt.Printf("scope list %s\n", scope)
							switch reflect.TypeOf(scope).Kind() {
								case reflect.Slice:
									s := reflect.ValueOf(scope)
									fmt.Println("In scope Slice case")
									for i := 0; i < s.Len(); i++ {
										if s.Index(i).Interface() == "admin"{
											fmt.Println("User is admin for POST")
											///**************************************************
											var db *sql.DB = storage.GetDatabase()
											
											// Check if user  exists
											var databaseEmail      string
											err := db.QueryRow("SELECT email FROM users WHERE user_id=?", userID).Scan(&databaseEmail)
											if err == sql.ErrNoRows {
									            http.Error(rw, "Server error, unable to link user-application.", 500)
												fmt.Printf("SQL Error UserID does not exists: %s\n", err)    
									            return
												
											} else {
												// Check if application  exists
												var databaseAPPName      string
												err := db.QueryRow("SELECT name FROM applications WHERE app_eui=?", appEUI).Scan(&databaseAPPName)
												if err == sql.ErrNoRows {
										            http.Error(rw, "Server error, unable to link user-application.", 500)
													fmt.Printf("SQL Error application does not exist: %s\n", err)    
										            return
												
												} else {
											        // Insert user
													fmt.Println("Attempting user_application INSERT")
											        _, err = db.Exec("INSERT INTO user_application (user_id, app_eui) VALUES(?, ?)", userID, appEUI)
											        if err != nil {
											            http.Error(rw, "Server error, unable to link user-application.", 500)
														fmt.Printf("SQL err on insert user_application: %s\n", err)   
											            return
											        }
												
													rw.WriteHeader(http.StatusCreated)
											        rw.Write([]byte("User Application Linked!"))
											        return
												}
										       
											}
											//****************************************************************
										}
									}
								default:
									http.Error(rw, "Server error, Scope value not array.", 500)
									fmt.Println("Server error, Scope value not array")    
									return
							}
							
							
						} else if req.Method == "DELETE" {
							fmt.Printf("scope list %s\n", scope)
							switch reflect.TypeOf(scope).Kind() {
								case reflect.Slice:
									s := reflect.ValueOf(scope)
									fmt.Println("In scope Slice case")
									for i := 0; i < s.Len(); i++ {
										if s.Index(i).Interface() == "admin"{
											fmt.Println("User is admin for POST")
											///**************************************************
											var db *sql.DB = storage.GetDatabase()
											
											// Check if user  exists
											var databaseEmail      string
											err := db.QueryRow("SELECT email FROM users WHERE user_id=?", userID).Scan(&databaseEmail)
											if err == sql.ErrNoRows {
									            http.Error(rw, "Server error, unable to remove link user-application.", 500)
												fmt.Printf("SQL Error UserID does not exists: %s\n", err)    
									            return
												
											} else {
												// Check if application  exists
												var databaseAPPName      string
												err := db.QueryRow("SELECT name FROM applications WHERE app_eui=?", appEUI).Scan(&databaseAPPName)
												if err == sql.ErrNoRows {
										            http.Error(rw, "Server error, unable to remove link user-application.", 500)
													fmt.Printf("SQL Error application does not exist: %s\n", err)    
										            return
												
												} else {
													
													// delete from user/applcation table if exists
											        _, err = db.Exec("DELETE FROM user_application WHERE user_id = ? AND app_eui=?", userID, appEUI)
											        if err != nil {
											            http.Error(rw, "Server error, unable to delete user.", 500)
														fmt.Printf("SQL err delete from user_application: %s\n", err)     
											            return
											        }
												
													rw.WriteHeader(http.StatusCreated)
											        rw.Write([]byte("User Application Link Removed!"))
											        return
												}
										       
											}
											//****************************************************************
										}
									}
								default:
									http.Error(rw, "Server error, Scope value not array.", 500)
									fmt.Println("Server error, Scope value not array")    
									return
							}
							
							
						}
						
						
					} else {
						fmt.Printf("Invalid Token %i\n", err)   
						http.Error(rw, "Server error, unable to obtain user account.", 500)    
						return
					}
			} else {
					http.Error(rw, "Server error, unable to link users.", 500)
					fmt.Println("No bearer token label")
					return
			}
		} else {
			http.Error(rw, "Server error, unable to link users.", 500)
			fmt.Println("Auth bearer incorrect length when split")      
			return
		}
		
		
		
		
		
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
