package clipsight

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/template"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/quicksight"
	"github.com/aws/aws-sdk-go-v2/service/quicksight/types"
	validator "github.com/fujiwara/go-amzn-oidc/validator"
	"github.com/fujiwara/ridge"
	"github.com/julienschmidt/httprouter"
	"github.com/mashiike/accesslogger"
	googleoidcmiddleware "github.com/mashiike/google-oidc-middleware"
)

// ServeOption is Options for CLI Serve command
type ServeOption struct {
	BaseURL                     *url.URL `help:"site base url" env:"CLIPSIGHT_BASE_URL" default:"http://localhost:8080"`
	Addr                        string   `help:"local server address" env:"CLIPSIGHT_ADDR" default:":8080"`
	Prefix                      string   `help:"site prefix" default:"/" env:"CLIPSIGHT_PREFIX"`
	Templates                   string   `help:"Path for index.html template dir" type:"path" env:"CLIPSIGHT_TEMPLATES"`
	AuthType                    string   `help:"Types of Authentication" enum:"google,aws" default:"google" env:"CLIPSIGHT_AUTH_TYPE"`
	GoogleClientID              string   `help:"google client id for auth type is google" env:"GOOGLE_CLIENT_ID"`
	GoogleClientSecret          string   `help:"google client secret for auth type is google" env:"GOOGLE_CLIENT_SECRET"`
	GoogleOIDCSessionEncryptKey string   `help:"session encrypt key for google auth" env:"GOOGLE_OIDC_SESSION_ENCRYPT_KEY"`
}

//go:embed templates
var defaultTemplates embed.FS

func (app *ClipSight) RunServe(ctx context.Context, opt *ServeOption) error {
	authMiddleware, err := app.NewAuthMiddleware(ctx, opt)
	if err != nil {
		return err
	}

	var templateFS fs.FS
	if opt.Templates != "" {
		templateFS = os.DirFS(opt.Templates)
	} else {
		templateFS, err = fs.Sub(defaultTemplates, "templates")
		if err != nil {
			return fmt.Errorf("default templates sub: %w", err)
		}
	}
	tpl, err := template.ParseFS(templateFS, "index.html")
	if err != nil {
		return fmt.Errorf("failed parse template: %w", err)
	}
	router := httprouter.New()

	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		var buf bytes.Buffer
		if err := tpl.ExecuteTemplate(&buf, "index.html", map[string]interface{}{
			"BaseURL": opt.BaseURL,
		}); err != nil {
			log.Println("[error] failed execute template ERROR CODE 001:", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError)+"\nERROR CODE 001", http.StatusInternalServerError)
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		io.Copy(w, &buf)
	})

	router.GET("/api/dashboards", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		ctx := r.Context()
		w.Header().Set("Content-Type", "application/json")
		user, ok := GetUserFromContext(r.Context())
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "dashboars not found",
			})
			return
		}
		qs, err := app.NewQuickSightClientWithUser(ctx, user)
		if err != nil {
			log.Printf("[error] can not initialize QuickSightclient: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "can not initialize",
			})
			return
		}
		result := make(map[string]interface{})
		for i, dashbord := range user.Dashboards {
			if !dashbord.IsVisible() {
				continue
			}
			output, err := qs.GenerateEmbedUrlForRegisteredUser(ctx, &quicksight.GenerateEmbedUrlForRegisteredUserInput{
				AwsAccountId: aws.String(app.awsAccountID),
				ExperienceConfiguration: &types.RegisteredUserEmbeddingExperienceConfiguration{
					Dashboard: &types.RegisteredUserDashboardEmbeddingConfiguration{
						InitialDashboardId: aws.String(dashbord.DashboardID),
					},
				},
				UserArn: aws.String(user.QuickSightUserARN),
				AllowedDomains: []string{
					opt.BaseURL.String(),
				},
				SessionLifetimeInMinutes: aws.Int64(60),
			})
			if err != nil {
				log.Println("[error]", err)
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error": "can not get embeded url",
				})
				return
			}
			result[fmt.Sprintf("dashbboard%d", i+1)] = map[string]interface{}{
				"name": dashbord.Name,
				"url":  output.EmbedUrl,
			}
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"dashboards": result,
		})
	})

	accessLoggingMiddleware := accesslogger.New(accesslogger.CombinedDLogger(os.Stderr))

	ridge.RunWithContext(ctx, opt.Addr, opt.Prefix,
		accessLoggingMiddleware(
			authMiddleware(
				router,
			),
		),
	)
	return nil
}

func (app *ClipSight) NewAuthMiddleware(ctx context.Context, opt *ServeOption) (func(http.Handler) http.Handler, error) {
	autholization := func(w http.ResponseWriter, r *http.Request, next http.Handler, email Email) {
		user, ok, err := app.GetUser(ctx, email)
		if err != nil {
			log.Printf("[error] ERROR CODE 002: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError)+"\nERROR CODE 002", http.StatusInternalServerError)
			return
		}
		if !ok {
			log.Println("[debug] user not found")
			http.NotFound(w, r)
			return
		}
		if !user.IsActive() {
			log.Printf("[info] user id %s is not active", user.ID)
			http.NotFound(w, r)
			return
		}
		r = r.WithContext(WithUser(r.Context(), user))
		next.ServeHTTP(w, r)
	}
	switch strings.ToLower(opt.AuthType) {
	case "google":
		authenticationMiddleware, err := googleoidcmiddleware.New(&googleoidcmiddleware.Config{
			ClientID:          opt.GoogleClientID,
			ClientSecret:      opt.GoogleClientSecret,
			SessionEncryptKey: []byte(opt.GoogleOIDCSessionEncryptKey),
			Scopes:            []string{"email"},
			BaseURL:           opt.BaseURL,
		})
		if err != nil {
			return nil, fmt.Errorf("failed initialize google OIDC: %w", err)
		}
		m := func(next http.Handler) http.Handler {
			return authenticationMiddleware(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					//auth check
					log.Println("[debug] get claim")
					claims, ok := googleoidcmiddleware.IDTokenClaims(r.Context())
					if !ok {
						http.NotFound(w, r)
						return
					}
					log.Println("[debug] check email")
					email, ok := claims["email"].(string)
					if !ok {
						log.Println("[debug] email not found")
						http.NotFound(w, r)
						return
					}
					log.Printf("[debug] email: %s", email)
					autholization(w, r, next, Email(email))
				}),
			)
		}
		return m, err
	case "aws":
		m := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				claims, err := validator.Validate(r.Header.Get("x-amzn-oidc-data"))
				if err != nil {
					log.Printf("[warn] ERROR CODE 003: %v", err)
					http.Error(w, http.StatusText(http.StatusForbidden)+"\nERROR CODE 003", http.StatusForbidden)
					return
				}
				autholization(w, r, next, Email(claims.Email()))
			})
		}
		return m, nil
	default:
		return nil, fmt.Errorf("unknwon auth type: %s", opt.AuthType)
	}
}
