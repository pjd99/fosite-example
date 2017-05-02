package authorizationserver

import (
	"fmt"
	"os"
	"bufio"
	"encoding/pem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"net/http"
	"time"
	
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/compose"
	"github.com/ory-am/fosite/handler/openid"
	oauth2jwt "github.com/ory-am/fosite/handler/oauth2"
	"github.com/ory-am/fosite/storage"
	"github.com/ory-am/fosite/token/jwt"
	"github.com/pkg/errors"
)

func RegisterHandlers() {
	// Set up oauth2 endpoints. You could also use gorilla/mux or any other router.
	http.HandleFunc("/users/auth", authEndpoint)
	http.HandleFunc("/users/token", tokenEndpoint)

	// revoke tokens
	http.HandleFunc("/users/revoke", revokeEndpoint)
	http.HandleFunc("/users/introspect", introspectionEndpoint)
}

// This is an exemplary storage instance. We will add a client and a user to it so we can use these later on.
// var store = storage.NewExampleStore()

var store = storage.LoadStore()

var config = new(compose.Config)

// Because we are using oauth2 and open connect id, we use this little helper to combine the two in one
// variable.
var strat = compose.CommonStrategy{
	// alternatively you could use:
	//OAuth2Strategy:
        CoreStrategy:  compose.NewOAuth2JWTStrategy(loadRSAKey()),
	//CoreStrategy: compose.NewOAuth2HMACStrategy(config, []byte("some-super-cool-secret-that-nobody-knows")),

	// open id connect strategy
	OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(mustRSAKey()),
}

type Session struct {

     *oauth2jwt.JWTSession

    //*jwt.JWTClaims,
    //*jwt.JWTHeader,
    //*jwt.ExpiresaAt
}

var oauth2 = compose.Compose(
	config,
	store,
	strat,

	// enabled handlers
	compose.OAuth2AuthorizeExplicitFactory,
	compose.OAuth2AuthorizeImplicitFactory,
	compose.OAuth2ClientCredentialsGrantFactory,
	compose.OAuth2RefreshTokenGrantFactory,
	compose.OAuth2ResourceOwnerPasswordCredentialsFactory,

	compose.OAuth2TokenRevocationFactory,
	compose.OAuth2TokenIntrospectionFactory,

	// be aware that open id connect factories need to be added after oauth2 factories to work properly.
	compose.OpenIDConnectExplicitFactory,
	compose.OpenIDConnectImplicitFactory,
	compose.OpenIDConnectHybridFactory,
)

// A session is passed from the `/auth` to the `/token` endpoint. You probably want to store data like: "Who made the request",
// "What organization does that person belong to" and so on.
// For our use case, the session will meet the requirements imposed by JWT access tokens, HMAC access tokens and OpenID Connect
// ID Tokens plus a custom field

// newSession is a helper function for creating a new session. This may look like a lot of code but since we are
// setting up multiple strategies it is a bit longer.
// Usually, you could do:
//
//  session = new(fosite.DefaultSession)


func newOpenIDSession(user string) *openid.DefaultSession {
	return &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Issuer:    "https://fosite.my-application.com",
			Subject:   user,
			Audience:  "https://my-client.my-application.com",
			ExpiresAt: time.Now().Add(time.Hour * 6),
			IssuedAt:  time.Now(),
		},
		Headers: &jwt.Headers{
			Extra: make(map[string]interface{}),
		},
	}
}


func newSession(user string) *Session {
        return &Session{
		JWTSession: &oauth2jwt.JWTSession{
                	JWTClaims: &jwt.JWTClaims{
                                Issuer:    "ttn-account",
                                Subject:   user,
                                Audience:  "all",
                                IssuedAt:  time.Now(),
                                NotBefore: time.Now(),
				ExpiresAt: time.Now().AddDate(0, 0, 14),
                                Extra:     make(map[string]interface{}),
                        },
                        JWTHeader: &jwt.Headers{
				Extra: make(map[string]interface{}),
			},
			ExpiresAt:  map[fosite.TokenType]time.Time{
            			fosite.AuthorizeCode: time.Now().Add(10 * time.Minute),
            			fosite.AccessToken:   time.Now().Add(1 * time.Hour),
            			fosite.RefreshToken:  time.Now().AddDate(0, 0, 14),
        		},
			Username: user,
		},
        }
}

func ReloadUsers(name string, secret string) error { 
	err = store.ReloadUsers(name, secret)
	if err != nil {
		return err
	}
	return nil
}

func mustRSAKey() *rsa.PrivateKey { 
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	return key
}

func loadRSAKey() *rsa.PrivateKey {
	 // Load PEM
	pemfile, err := os.Open("./cert/rs256-public.pem")

	if err != nil {
		fmt.Println(err)
	os.Exit(1)
	}

	// need to convert pemfile to []byte for decoding

	pemfileinfo, _ := pemfile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte,size)

	// read pemfile content into pembytes
	buffer := bufio.NewReader(pemfile)
	_, err = buffer.Read(pembytes)


	// proper decoding now
	data, _ := pem.Decode([]byte(pembytes))


	pemfile.Close()
	fmt.Printf("PEM Type :\n%s\n", data.Type)
	fmt.Printf("PEM Headers :\n%s\n", data.Headers)
	fmt.Printf("PEM Bytes :\n%x\n", string(data.Bytes)) 
        
	// var pubkey rsa.PublicKey

	tempkey, err := x509.ParsePKIXPublicKey(data.Bytes)
        
	if err != nil {
		panic("failed to parse DER encoded public key: " + err.Error())
	}

	pubkey := tempkey.(*rsa.PublicKey)

	privkey := loadRSAPrivKey()

	privkey.PublicKey = *pubkey 
	return privkey
}


func loadRSAPrivKey() *rsa.PrivateKey {
	 // Load PEM
        pemfile, err := os.Open("./cert/rs256-private.pem")

        if err != nil {
                fmt.Println(err)
        os.Exit(1)
        }

        // need to convert pemfile to []byte for decoding

        pemfileinfo, _ := pemfile.Stat()
        var size int64 = pemfileinfo.Size()
        pembytes := make([]byte,size)

        // read pemfile content into pembytes
        buffer := bufio.NewReader(pemfile)
        _, err = buffer.Read(pembytes)


        // proper decoding now
        data, _ := pem.Decode([]byte(pembytes))


        pemfile.Close()
        fmt.Printf("PEM Type :\n%s\n", data.Type)
        fmt.Printf("PEM Headers :\n%s\n", data.Headers)
        fmt.Printf("PEM Bytes :\n%x\n", string(data.Bytes)) 
        
        key, err := x509.ParsePKCS1PrivateKey(data.Bytes)
        if err != nil {
                panic(err)
        }
	return key
}



type stackTracer interface {
	StackTrace() errors.StackTrace
}
