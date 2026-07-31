package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	// Azure managed identity
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	// Database
	"github.com/jackc/pgconn"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/log/logrusadapter"
	"github.com/jackc/pgx/v4/pgxpool"

	// Config
	"github.com/spf13/viper"

	// Logging
	log "github.com/sirupsen/logrus"
)

func dbConnect() (*pgxpool.Pool, error) {
	if globalDb == nil {
		var err error
		var config *pgxpool.Config
		dbConnection := viper.GetString("DbConnection")
		config, err = pgxpool.ParseConfig(dbConnection)
		if err != nil {
			log.Fatal(err)
		}

		// Read and parse connection lifetime
		dbPoolMaxLifeTime, errt := time.ParseDuration(viper.GetString("DbPoolMaxConnLifeTime"))
		if errt != nil {
			log.Fatal(errt)
		}
		config.MaxConnLifetime = dbPoolMaxLifeTime

		// Read and parse max connections
		dbPoolMaxConns := viper.GetInt32("DbPoolMaxConns")
		if dbPoolMaxConns > 0 {
			config.MaxConns = dbPoolMaxConns
		}

		// Read current log level and use one less-fine level
		// below that
		config.ConnConfig.Logger = logrusadapter.NewLogger(log.New())
		levelString, _ := (log.GetLevel() - 1).MarshalText()
		pgxLevel, _ := pgx.LogLevelFromString(string(levelString))
		config.ConnConfig.LogLevel = pgxLevel

		// When Azure managed-identity auth is enabled, inject a fresh Entra
		// access token as the DB password before every new connection.
		if viper.GetBool("DatabaseUseAzureIdentity") {
			if err = configureAzureIdentityAuth(config); err != nil {
				log.Fatal(err)
			}
		}

		// Connect!
		globalDb, err = pgxpool.ConnectConfig(context.Background(), config)
		if err != nil {
			log.Fatal(err)
		}
		dbName := config.ConnConfig.Config.Database
		dbUser := config.ConnConfig.Config.User
		dbHost := config.ConnConfig.Config.Host
		log.Infof("Connected as '%s' to '%s' @ '%s'", dbUser, dbName, dbHost)

		return globalDb, err
	}
	return globalDb, nil
}

// azurePostgresScope is the Entra token scope for Azure Database for PostgreSQL.
const azurePostgresScope = "https://ossrdbms-aad.database.windows.net/.default"

// configureAzureIdentityAuth wires the pgx pool to authenticate to Postgres
// using an Entra (Azure AD) access token obtained via AKS Workload Identity,
// instead of a static password. The token is short-lived (~60 min), so it is
// injected in BeforeConnect, which runs before every new physical connection
// (initial connect and pool refills).
func configureAzureIdentityAuth(config *pgxpool.Config) error {
	opts := &azidentity.WorkloadIdentityCredentialOptions{}
	// Optional explicit identity selection; when empty the SDK falls back to
	// the AZURE_CLIENT_ID injected by the Workload Identity webhook. This lets
	// a single workload choose among multiple federated identities.
	if clientID := os.Getenv("DATABASE_AZURE_CLIENT_ID"); clientID != "" {
		opts.ClientID = clientID
	}
	cred, err := azidentity.NewWorkloadIdentityCredential(opts)
	if err != nil {
		return fmt.Errorf("azure identity: %w", err)
	}

	// Enforce verify-full TLS on every connection in identity mode: the Entra
	// token is a bearer credential and must never traverse a connection whose
	// server identity is unverified. The sslmode parsed from DATABASE_URL is not
	// enough to guarantee that — pgx leaves hostname verification disabled for
	// sslmode=require and verify-ca (InsecureSkipVerify=true) and even permits a
	// plaintext fallback for sslmode=prefer. Harden the primary connection and
	// every fallback to verify-full, preserving any operator-supplied root CAs
	// and defaulting to the system trust store (Azure's public roots ship in the
	// runtime image's ca-certificates).
	hardenTLS := func(t *tls.Config, host string) (*tls.Config, error) {
		if t == nil {
			t = &tls.Config{}
		}
		t.InsecureSkipVerify = false
		if t.ServerName == "" {
			t.ServerName = host
		}
		if t.RootCAs == nil {
			rootCAs, cerr := x509.SystemCertPool()
			if cerr != nil {
				return nil, fmt.Errorf("load system cert pool for verified TLS: %w", cerr)
			}
			t.RootCAs = rootCAs
		}
		if t.MinVersion < tls.VersionTLS12 {
			t.MinVersion = tls.VersionTLS12
		}
		return t, nil
	}
	if config.ConnConfig.TLSConfig, err = hardenTLS(config.ConnConfig.TLSConfig, config.ConnConfig.Host); err != nil {
		return err
	}
	for _, fb := range config.ConnConfig.Fallbacks {
		if fb.TLSConfig, err = hardenTLS(fb.TLSConfig, fb.Host); err != nil {
			return err
		}
	}
	log.Info("Azure identity auth: enforcing verify-full TLS on all Postgres connections")

	config.BeforeConnect = func(ctx context.Context, connConfig *pgx.ConnConfig) error {
		token, err := cred.GetToken(ctx, policy.TokenRequestOptions{
			Scopes: []string{azurePostgresScope},
		})
		if err != nil {
			return fmt.Errorf("acquire entra token: %w", err)
		}
		connConfig.Password = token.Token
		return nil
	}
	return nil
}

func loadVersions() error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	row := db.QueryRow(context.Background(), "SELECT postgis_full_version()")
	var verStr string
	err = row.Scan(&verStr)
	if err != nil {
		return err
	}
	// Parse full version string
	//   POSTGIS="3.0.0 r17983" [EXTENSION] PGSQL="110" GEOS="3.8.0-CAPI-1.11.0 "
	//   PROJ="6.2.0" LIBXML="2.9.4" LIBJSON="0.13" LIBPROTOBUF="1.3.2" WAGYU="0.4.3 (Internal)"
	re := regexp.MustCompile(`([A-Z]+)="(.+?)"`)
	vers := make(map[string]string)
	for _, mtch := range re.FindAllStringSubmatch(verStr, -1) {
		vers[mtch[1]] = mtch[2]
	}

	pgisVer, ok := vers["POSTGIS"]
	if !ok {
		return errors.New("POSTGIS key missing from postgis_full_version")
	}
	// Convert Postgis version string into a lexically (and/or numerically) sortable form
	// "3.1.1 r17983" => "3001001"
	pgisMajMinPat := strings.Split(strings.Split(pgisVer, " ")[0], ".")
	pgisMaj, _ := strconv.Atoi(pgisMajMinPat[0])
	pgisMin, _ := strconv.Atoi(pgisMajMinPat[1])
	pgisPat, _ := strconv.Atoi(pgisMajMinPat[2])
	pgisNum := 1000000*pgisMaj + 1000*pgisMin + pgisPat
	vers["POSTGISFULL"] = strconv.Itoa(pgisNum)
	globalVersions = vers
	globalPostGISVersion = pgisNum

	return nil
}

func dBTileRequest(ctx context.Context, tr *TileRequest) ([]byte, error) {
	db, err := dbConnect()
	if err != nil {
		log.Error(err)
		return nil, err
	}
	row := db.QueryRow(ctx, tr.SQL, tr.Args...)
	var mvtTile []byte
	err = row.Scan(&mvtTile)
	if err != nil {
		log.Warn(err)

		// check for errors retrieving the rendered tile from the database
		// Timeout errors can occur if the context deadline is reached
		// or if the context is canceled during/before a database query.
		if pgconn.Timeout(err) {
			return nil, tileAppError{
				SrcErr:  err,
				Message: fmt.Sprintf("Timeout: deadline exceeded on %s/%s", tr.LayerID, tr.Tile.String()),
			}
		}

		return nil, tileAppError{
			SrcErr:  err,
			Message: fmt.Sprintf("SQL error on %s/%s", tr.LayerID, tr.Tile.String()),
		}

	}
	return mvtTile, nil
}
