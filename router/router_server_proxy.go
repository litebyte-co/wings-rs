package router

import (
        "crypto"
        "crypto/ecdsa"
        "crypto/elliptic"
        "crypto/rand"
        "fmt"
        "log"
        "net/http"
        "os"
        "os/exec"
        "path/filepath"
        "time"

        "github.com/gin-gonic/gin"
        "github.com/go-acme/lego/v4/certcrypto"
        "github.com/go-acme/lego/v4/certificate"
        "github.com/go-acme/lego/v4/challenge/http01"
        "github.com/go-acme/lego/v4/lego"
        "github.com/go-acme/lego/v4/registration"
)

// LetsEncryptUser stores Let's Encrypt user details
type LetsEncryptUser struct {
        Email        string
        Registration *registration.Resource
        key          crypto.PrivateKey
}

func (u *LetsEncryptUser) GetEmail() string {
        return u.Email
}
func (u LetsEncryptUser) GetRegistration() *registration.Resource {
        return u.Registration
}
func (u *LetsEncryptUser) GetPrivateKey() crypto.PrivateKey {
        return u.key
}

// Create a reverse proxy with SSL support
func postServerProxyCreate(c *gin.Context) {
        _ = ExtractServer(c)

        var data struct {
                Domain         string `json:"domain"`
                IP             string `json:"ip"`
                Port           string `json:"port"`
                Ssl            bool   `json:"ssl"`
                UseLetsEncrypt bool   `json:"use_lets_encrypt"`
                ClientEmail    string `json:"client_email"`
                SslCert        string `json:"ssl_cert"`
                SslKey         string `json:"ssl_key"`
        }

        if err := c.BindJSON(&data); err != nil {
                log.Println("Error: Failed to bind JSON request:", err)
                c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
                return
        }

        challengeDir := fmt.Sprintf("/srv/server_certs/%s/.well-known/acme-challenge/", data.Domain)
        log.Println("Creating ACME challenge directory:", challengeDir)
        if err := os.MkdirAll(challengeDir, 0755); err != nil {
                log.Println("Error: Failed to create ACME challenge directory:", err)
                c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create ACME challenge directory"})
                return
        }

        if _, err := os.Stat(challengeDir); os.IsNotExist(err) {
                log.Println("Error: ACME challenge directory does not exist after creation attempt!")
                c.JSON(http.StatusInternalServerError, gin.H{"error": "ACME challenge directory creation failed"})
                return
        }

        go func() {
                log.Println("Starting ACME challenge server on 127.0.0.1:81")
                err := http.ListenAndServe("127.0.0.1:81", http.FileServer(http.Dir(challengeDir)))
                if err != nil {
                        log.Println("Error: Failed to start ACME challenge server:", err)
                }
        }()

        nginxConfigPath := fmt.Sprintf("/etc/nginx/conf.d/%s.conf", data.Domain)
        nginxConfig := fmt.Sprintf(`server {
        listen 80;
        server_name %s;

        location /.well-known/acme-challenge/ {
                root %s;
        }

        location / {
                proxy_pass http://%s:%s;
                proxy_set_header Host $host;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
}`, data.Domain, challengeDir, data.IP, data.Port)

        log.Println("Writing Nginx config:", nginxConfigPath)
        if err := os.WriteFile(nginxConfigPath, []byte(nginxConfig), 0644); err != nil {
                log.Println("Error: Failed to write Nginx config:", err)
                return
        }

        log.Println("Reloading Nginx")
        exec.Command("systemctl", "reload", "nginx").Run()

        time.Sleep(3 * time.Second)
        testFilePath := filepath.Join(challengeDir, "testfile")
        log.Println("Creating ACME test file:", testFilePath)
        if err := os.WriteFile(testFilePath, []byte("test"), 0644); err != nil {
                log.Println("Error: Failed to create test file:", err)
        }

        resp, err := http.Get("http://" + data.Domain + "/.well-known/acme-challenge/testfile")
        if err != nil || resp.StatusCode != http.StatusOK {
                log.Println("Error: ACME challenge not accessible:", err)
                c.JSON(http.StatusInternalServerError, gin.H{"error": "ACME challenge not accessible"})
                return
        }

        if data.Ssl && data.UseLetsEncrypt {
                log.Println("Requesting SSL certificate for", data.Domain)
                privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
                user := LetsEncryptUser{Email: data.ClientEmail, key: privateKey}

                config := lego.NewConfig(&user)
                config.Certificate.KeyType = certcrypto.RSA2048
                client, _ := lego.NewClient(config)

                client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "81"))
                reg, _ := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
                user.Registration = reg

                certRequest := certificate.ObtainRequest{Domains: []string{data.Domain}, Bundle: true}
                cert, err := client.Certificate.Obtain(certRequest)
                if err != nil {
                        log.Println("Error: Failed to obtain certificate:", err)
                        return
                }

                certPath := fmt.Sprintf("/srv/server_certs/%s/cert.pem", data.Domain)
                keyPath := fmt.Sprintf("/srv/server_certs/%s/key.pem", data.Domain)

                log.Println("Saving certificate files")
                _ = os.WriteFile(certPath, cert.Certificate, 0644)
                _ = os.WriteFile(keyPath, cert.PrivateKey, 0644)

                nginxSSLConfig := fmt.Sprintf(`server {
        listen 80;
        server_name %s;
        return 301 https://$host$request_uri;
}
server {
        listen 443 ssl http2;
        server_name %s;
        ssl_certificate %s;
        ssl_certificate_key %s;
        location / {
                proxy_pass http://%s:%s;
                proxy_set_header Host $host;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
}`, data.Domain, data.Domain, certPath, keyPath, data.IP, data.Port)

                log.Println("Updating Nginx configuration with SSL")
                _ = os.WriteFile(nginxConfigPath, []byte(nginxSSLConfig), 0644)
                exec.Command("systemctl", "reload", "nginx").Run()
        }

        c.Status(http.StatusAccepted)
}

// Delete a server proxy
func postServerProxyDelete(c *gin.Context) {
        _ = ExtractServer(c)

        var data struct {
                Domain string `json:"domain"`
                Port   string `json:"port"`
        }

        if err := c.BindJSON(&data); err != nil {
                log.Println("Error: Failed to parse delete request:", err)
                return
        }

        nginxConfigPath := fmt.Sprintf("/etc/nginx/conf.d/%s.conf", data.Domain)
        log.Println("Deleting Nginx config:", nginxConfigPath)
        _ = os.Remove(nginxConfigPath)
        exec.Command("systemctl", "reload", "nginx").Run()

        c.Status(http.StatusAccepted)
}
