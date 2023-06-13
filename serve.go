package clipsight

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
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
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"github.com/mashiike/accesslogger"
	googleoidcmiddleware "github.com/mashiike/google-oidc-middleware"
	"github.com/mashiike/slogutils"
	"golang.org/x/exp/slog"
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
			slog.ErrorCtx(r.Context(), "failed execute template", slog.String("error_code", "001"), slog.String("detail", err.Error()))
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
		slog.InfoCtx(ctx, "accume role", slog.String("user_id", user.ID), slog.String("email", user.Email.String()), slog.String("iam_role", user.IAMRoleARN))
		qs, err := app.NewQuickSightClientWithUser(ctx, user)
		if err != nil {
			slog.ErrorCtx(r.Context(), "failed initialize QuickSight client",
				slog.String("user_id", user.ID),
				slog.String("error_code", "002"),
				slog.String("detail", err.Error()),
			)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code":  "002",
				"error": "can not initialize",
			})
			return
		}
		result := make(map[string]interface{})
		for i, dashbord := range user.Dashboards {
			if !dashbord.IsVisible() {
				continue
			}
			d, exists, err := app.DescribeDashboard(ctx, dashbord.DashboardID)
			if err != nil {
				slog.ErrorCtx(r.Context(), "failed describe dashboard",
					slog.String("user_id", user.ID),
					slog.String("error_code", "006"),
					slog.String("detail", err.Error()),
				)
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"code":  "006",
					"error": "can not describe dashboard",
				})
				return
			}
			if !exists {
				slog.WarnCtx(r.Context(), "dashboard not found",
					slog.String("user_id", user.ID),
					slog.String("dashboard_id", dashbord.DashboardID),
				)
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
			slog.InfoCtx(ctx, "generate embed url",
				slog.String("user_id", user.ID),
				slog.String("email", user.Email.String()),
				slog.String("quick_sight_user_arn", user.QuickSightUserARN),
				slog.String("dashboard_id", dashbord.DashboardID),
				slog.String("dashboard_name", *d.Name),
			)
			if err != nil {
				slog.ErrorCtx(r.Context(), "failed generate embed url",
					slog.String("user_id", user.ID),
					slog.String("error_code", "003"),
					slog.String("detail", err.Error()),
				)
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"code":  "003",
					"error": "can not get embeded url",
				})
				return
			}
			result[fmt.Sprintf("dashbboard%d", i+1)] = map[string]interface{}{
				"name": d.Name,
				"url":  output.EmbedUrl,
			}
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"dashboards": result,
		})
	})

	accessLoggingMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			l := accesslogger.NewAccessLog(r)
			reqId := r.Header.Get("X-Request-Id")
			if reqId == "" {
				reqId = uuid.New().String()
			}
			ctx := slogutils.With(r.Context(), slog.String("request_id", reqId))
			responseWriter := &accesslogger.ResponseWriter{
				ResponseWriter: w,
			}
			r = r.WithContext(ctx)
			defer func() {
				err := recover()
				l = l.WriteResponseInfo(responseWriter)
				slog.Log(r.Context(), LevelNotice, l.Request,
					slog.String("request_id", reqId),
					slog.String("remote_addr", l.RemoteAddr),
					slog.String("accessed_at", l.AccessedAt.Format("02/Jan/2006:15:04:05 -0700")),
					slog.Int("status_code", l.StatusCode),
					slog.Int("body_byte_sent", l.BodyByteSent),
					slog.String("referer", l.Referer),
					slog.String("user_agent", l.UserAgent),
					slog.Int64("response_time_microseconds", l.ResponseTime),
					slog.Int64("first_sent_time_microseconds", l.FirstSentTime),
					slog.String("host", r.Host),
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.String("proto", r.Proto),
					slog.String("x_amzn_trace_id", r.Header.Get("X-Amzn-Trace-Id")),
					slog.String("x_amz_cf_id", r.Header.Get("X-Amz-Cf-Id")),
					slog.String("cloudfront_viewer_country", r.Header.Get("CloudFront-Viewer-Country")),
				)
				if err != nil {
					panic(err)
				}
			}()
			next.ServeHTTP(responseWriter, r)
		})
	}
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
			slog.ErrorCtx(r.Context(), "failed get user", slog.String("error_code", "004"), slog.String("detail", err.Error()))
			http.Error(w, http.StatusText(http.StatusInternalServerError)+"\nERROR CODE 004", http.StatusInternalServerError)
			return
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		if !user.IsActive() {
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
					slog.DebugCtx(r.Context(), "get claim")
					claims, ok := googleoidcmiddleware.IDTokenClaims(r.Context())
					if !ok {
						http.NotFound(w, r)
						return
					}
					slog.DebugCtx(r.Context(), "check email")
					email, ok := claims["email"].(string)
					if !ok {
						http.NotFound(w, r)
						return
					}
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
					slog.ErrorCtx(r.Context(), "failed validate oidc token", slog.String("error_code", "005"), slog.String("detail", err.Error()))
					http.Error(w, http.StatusText(http.StatusForbidden)+"\nERROR CODE 005", http.StatusForbidden)
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
