/*
This file provide http digest authorization.
Call CalcDigestHeader() to generate Authorization as string
After that,set that string into http header
*/
package linker_util

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// DigestHeaders tracks the state of authentication
type DigestHeaders struct {
	Realm     string
	Qop       string
	Method    string
	Nonce     string
	Opaque    string
	Algorithm string
	HA1       string
	HA2       string
	Cnonce    string
	Path      string
	Nc        int16
	Username  string
	Password  string
	Domain    string
	Stale     string
}

/*
This method can be used to generate Authorization string,which can be set into HTTP header and provide digest auth
username:account username
password:account password
method:http method like GET,POST.etc
urlStr:full url,which GET or POST to
note that this method is written simply, errors may occur and are handled by ease,it should be fullfill to be robust

*/
func CalcDigestHeader(username string, password string, method string, urlStr string) (digest string, err error) {

	//Step 1:
	//Do http request without Auth,without Body
	req, err := http.NewRequest(method, urlStr, nil)
	//	req,err:=http.NewRequest()
	if err != nil {
		panic(err)
	}
	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		panic("Error generating digest,check gerrit host and port.")
	}

	//Delete this segment
	//print resp
	//	fmt.Println("WWW-Authenticate: " + resp.Header.Get("WWW-Authenticate"))

	//Step 2:
	//If statusCode is 401,then get realm,nonce,...,as a map from resp
	if resp.StatusCode == 401 {
		//respMap is a map of realm,nonce qop etc.
		respMap := digestAuthParams(resp)
		//Step 3:
		//Generate HTTP digest
		var d DigestHeaders
		//Set algorithm
		if respMap["algorithm"] == "" {
			d.Algorithm = "MD5"
		} else {
			d.Algorithm = respMap["algorithm"]
		}
		//Set realm
		d.Realm = respMap["realm"]
		//Set nonce
		d.Nonce = respMap["nonce"]
		//Set qoq,opaque
		d.Opaque = respMap["opaque"]
		d.Qop = respMap["qop"]

		//Set domain
		d.Domain = respMap["domain"]
		//Set stale
		d.Stale = respMap["stale"]

		//Set username,password
		d.Username = username
		d.Password = password

		//Generate cnonce
		d.Cnonce = randomKey()
		//		d.Cnonce = ""
		//Set nc
		//		d.Nc = 0x1
		//Set opaque
		//		d.Opaque = ""

		tmpUrl, err := url.Parse(urlStr)
		if err != nil {
			//handle exception
			fmt.Println(err)
		}
		d.Path = tmpUrl.RequestURI()
		d.Method = method

		//Generate A1,A2
		d.digestChecksum()

		//Generate response
		response := h(strings.Join([]string{d.HA1, d.Nonce, fmt.Sprintf("%08x", d.Nc),
			d.Cnonce, d.Qop, d.HA2}, ":"))
		//Combine them as string
		digestHeader := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", cnonce="%s", nc=%08x, qop=%s, response="%s", algorithm=%s`,
			d.Username, d.Realm, d.Nonce, d.Path, d.Cnonce, d.Nc, d.Qop, response, d.Algorithm)
		return digestHeader, nil
	} else {
		//Return
		return
	}
}

/*
Parse Authorization header from the http.Request. Returns a map of
auth parameters or nil if the header is not a valid parsable Digest
auth header.
*/
func digestAuthParams(r *http.Response) map[string]string {
	s := strings.SplitN(r.Header.Get("Www-Authenticate"), " ", 2)
	if len(s) != 2 || s[0] != "Digest" {
		return nil
	}

	result := map[string]string{}
	for _, kv := range strings.Split(s[1], ",") {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		result[strings.Trim(parts[0], "\" ")] = strings.Trim(parts[1], "\" ")
	}
	return result
}

//Generate cnonce
func randomKey() string {
	k := make([]byte, 12)
	for bytes := 0; bytes < len(k); {
		n, err := rand.Read(k[bytes:])
		if err != nil {
			panic("rand.Read() failed")
		}
		bytes += n
	}
	return base64.StdEncoding.EncodeToString(k)
}

//Generate MD5
func (d *DigestHeaders) digestChecksum() {
	switch d.Algorithm {
	case "MD5":
		// A1
		h := md5.New()
		A1 := fmt.Sprintf("%s:%s:%s", d.Username, d.Realm, d.Password)
		io.WriteString(h, A1)
		d.HA1 = fmt.Sprintf("%x", h.Sum(nil))

		// A2
		h = md5.New()
		A2 := fmt.Sprintf("%s:%s", d.Method, d.Path)
		io.WriteString(h, A2)
		d.HA2 = fmt.Sprintf("%x", h.Sum(nil))
	case "MD5-sess":
	default:
		//token
	}
}

/*
H function for MD5 algorithm (returns a lower-case hex MD5 digest)
*/
func h(data string) string {
	digest := md5.New()
	digest.Write([]byte(data))
	return fmt.Sprintf("%x", digest.Sum(nil))
}
