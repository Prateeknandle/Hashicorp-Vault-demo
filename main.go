package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/go-sql-driver/mysql"
	vault "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/kubernetes"
)

var db *sql.DB

func main() {
	config := vault.DefaultConfig()

	config.Address = "http://vault:8200"

	client, err := vault.NewClient(config)
	if err != nil {
		log.Fatalf("unable to initialize Vault client: %v", err)
	}

	//	client.SetToken("hvs.MY9Wz5eRQTJhNI5a1HYMI8G9")
	if client.Token() == "" {
		_, err1 := getSecretWithKubernetesAuth(client)
		if err1 != nil {
			log.Fatalf("%v", err1)
		}
	}
	//go renewToken(client)

	secret, err := client.KVv2("knox").Get(context.Background(), "microservice/secret")
	if err != nil {
		fmt.Printf("unable to read secret: %v", err)
	}

	t, err := secret.Raw.TokenTTL()
	if t == 0 {
		go renewToken(client)
	}
	if err != nil {
		log.Fatalf("%v", err)
	}

	value, ok := secret.Data["password"].(string)
	if !ok {
		fmt.Printf("value type assertion failed: %T %#v", secret.Data["password"], secret.Data["password"])
	}

	fmt.Println(value)
	fmt.Println("Access granted!")

	cfg := mysql.Config{
		User:   "root",
		Passwd: value,
		Net:    "tcp",
		Addr:   "mysql:3306",
		DBName: "mysql",
	}
	// Get a database handle.

	db, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		fmt.Println(err)
	}

	pingErr := db.Ping()
	if pingErr != nil {
		fmt.Println(pingErr)
	}
	fmt.Println("Connected!")

	time.Sleep(time.Second * 3600)

}
func getSecretWithKubernetesAuth(client *vault.Client) (*vault.Secret, error) {
	// If set, the VAULT_ADDR environment variable will be the address that
	// your pod uses to communicate with Vault.
	//config := vault.DefaultConfig() // modify for more granular configuration

	// client, err := vault.NewClient(config)
	// if err != nil {
	// 	return "", fmt.Errorf("unable to initialize Vault client: %w", err)
	// }

	// The service-account token will be read from the path where the token's
	// Kubernetes Secret is mounted. By default, Kubernetes will mount it to
	// /var/run/secrets/kubernetes.io/serviceaccount/token, but an administrator
	// may have configured it to be mounted elsewhere.
	// In that case, we'll use the option WithServiceAccountTokenPath to look
	// for the token there.
	k8sAuth, err := auth.NewKubernetesAuth(
		"knox",
		auth.WithServiceAccountTokenPath("/var/run/secrets/kubernetes.io/serviceaccount/token"),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize Kubernetes auth method: %w", err)
	}

	authInfo, err := client.Auth().Login(context.TODO(), k8sAuth)
	if err != nil {
		return nil, fmt.Errorf("unable to log in with Kubernetes auth: %w", err)
	}
	if authInfo == nil {
		return nil, fmt.Errorf("no auth info was returned after login")
	}
	return authInfo, err
}

func renewToken(client *vault.Client) {

	vaultLoginResp, err := getSecretWithKubernetesAuth(client)
	if err != nil {
		log.Fatalf("unable to authenticate to Vault: %v", err)
	}
	tokenErr := manageTokenLifecycle(client, vaultLoginResp)
	if tokenErr != nil {
		log.Fatalf("unable to start managing token lifecycle: %v", tokenErr)
	}

}

// Starts token lifecycle management. Returns only fatal errors as errors,
// otherwise returns nil so we can attempt login again.
func manageTokenLifecycle(client *vault.Client, token *vault.Secret) error {
	renew := token.Auth.Renewable // You may notice a different top-level field called Renewable. That one is used for dynamic secrets renewal, not token renewal.
	if !renew {
		log.Printf("Token is not configured to be renewable. Re-attempting login.")
		return nil
	}

	watcher, err := client.NewLifetimeWatcher(&vault.LifetimeWatcherInput{
		Secret:    token,
		Increment: 3600, // Learn more about this optional value in https://www.vaultproject.io/docs/concepts/lease#lease-durations-and-renewal
	})
	if err != nil {
		return fmt.Errorf("unable to initialize new lifetime watcher for renewing auth token: %w", err)
	}

	go watcher.Start()
	defer watcher.Stop()

	select {
	// `DoneCh` will return if renewal fails, or if the remaining lease
	// duration is under a built-in threshold and either renewing is not
	// extending it or renewing is disabled. In any case, the caller
	// needs to attempt to log in again.
	case err := <-watcher.DoneCh():
		if err != nil {
			log.Printf("Failed to renew token: %v. Re-attempting login.", err)
			return nil
		}
		// This occurs once the token has reached max TTL.
		log.Printf("Token can no longer be renewed. Re-attempting login.")
		return nil

	// Successfully completed renewal
	case renewal := <-watcher.RenewCh():
		log.Printf("Successfully renewed: %#v", renewal)
	}
	return err
}
