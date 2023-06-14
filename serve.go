package clipsight

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
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
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
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
	APIOnly                     bool     `help:"API only mode" env:"CLIPSIGHT_API_ONLY"`
	Templates                   string   `help:"Path for index.html template dir" type:"path" env:"CLIPSIGHT_TEMPLATES"`
	Static                      string   `help:"Path for static files" type:"path" env:"CLIPSIGHT_STATIC"`
	AuthType                    string   `help:"Types of Authentication" enum:"google,aws,none" default:"google" env:"CLIPSIGHT_AUTH_TYPE"`
	GoogleClientID              string   `help:"google client id for auth type is google" env:"GOOGLE_CLIENT_ID"`
	GoogleClientSecret          string   `help:"google client secret for auth type is google" env:"GOOGLE_CLIENT_SECRET"`
	GoogleOIDCSessionEncryptKey string   `help:"session encrypt key for google auth" env:"GOOGLE_OIDC_SESSION_ENCRYPT_KEY"`
	AuthHeader                  string   `help:"auth header name for auth type is none" env:"CLIPSIGHT_AUTH_HEADER" default:"ClipSight-Auth-Email"`
}

//go:embed templates
var defaultTemplates embed.FS

type handler struct {
	tpl     *template.Template
	static  http.Handler
	router  *chi.Mux
	app     *ClipSight
	baseURL *url.URL
}

func (app *ClipSight) newHandler(baseURL *url.URL, tpl *template.Template, static http.Handler, middlewares chi.Middlewares) *handler {
	h := &handler{
		tpl:     tpl,
		router:  chi.NewRouter(),
		static:  static,
		app:     app,
		baseURL: baseURL,
	}
	for _, m := range middlewares {
		h.router.Use(m)
	}
	h.SetRoute()
	return h
}

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

	accessLoggingMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			l := accesslogger.NewAccessLog(r)
			reqId := middleware.GetReqID(r.Context())
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
	var static http.Handler
	if opt.Static != "" {
		static = http.StripPrefix(opt.Prefix, http.FileServer(http.Dir(opt.Static)))
	}
	h := app.newHandler(opt.BaseURL, tpl, static, chi.Middlewares{
		middleware.RequestID,
		middleware.RealIP,
		accessLoggingMiddleware,
		middleware.Recoverer,
		authMiddleware,
	})

	ridge.RunWithContext(ctx, opt.Addr, opt.Prefix, h)
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
			slog.WarnCtx(r.Context(), "user not found", slog.Int("staus", http.StatusNotFound), slog.String("email", email.String()))
			http.NotFound(w, r)
			return
		}
		if !user.IsActive() {
			slog.WarnCtx(r.Context(), "user is not active", slog.Int("staus", http.StatusNotFound), slog.String("user_id", user.ID), slog.String("email", email.String()))
			http.NotFound(w, r)
			return
		}
		slog.Info("auth success", slog.String("user_id", user.ID), slog.String("email", email.String()), slog.Int("dashbaords_count", len(user.Dashboards)))
		r = r.WithContext(WithUser(r.Context(), user))
		next.ServeHTTP(w, r)
	}
	authType := strings.ToLower(opt.AuthType)
	slog.InfoCtx(ctx, "new auth middleware", slog.String("auth_type", authType))
	switch authType {
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
						slog.DebugCtx(r.Context(), "not found claim")
						http.NotFound(w, r)
						return
					}
					slog.DebugCtx(r.Context(), "check email")
					email, ok := claims["email"].(string)
					if !ok {
						slog.DebugCtx(r.Context(), "not found email")
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
	case "none":
		m := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				email := Email(r.Header.Get(opt.AuthHeader))
				if err := email.Validate(); err != nil {
					slog.ErrorCtx(r.Context(), "failed validate email", slog.String("error_code", "008"), slog.String("detail", err.Error()))
					http.Error(w, http.StatusText(http.StatusForbidden)+"\nERROR CODE 008", http.StatusForbidden)
					return
				}
				autholization(w, r, next, email)
			})
		}
		return m, nil
	default:
		return nil, fmt.Errorf("unknwon auth type: %s", opt.AuthType)
	}

}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.router.ServeHTTP(w, r)
}

func (h *handler) Use(middleware func(http.Handler) http.Handler) {
	h.router.Use(middleware)
}

func (h *handler) SetRoute() {
	if h.tpl != nil {
		h.router.Get("/", h.ServeIndex)
	}
	if h.static != nil {
		h.router.Get("/static/*", http.StripPrefix("/static/", h.static).ServeHTTP)
	}
	h.router.Route("/api", func(r chi.Router) {
		r.Get("/health", h.ServeHealth)
		r.Get("/me", h.ServeMe)
		r.Get("/dashboards", h.ServeDashbords)
		r.Get("/dashboards/{dashboard_id}", h.ServeDashbord)
	})
}

func (h *handler) ServeIndex(w http.ResponseWriter, r *http.Request) {
	var buf bytes.Buffer
	if err := h.tpl.ExecuteTemplate(&buf, "index.html", map[string]interface{}{
		"BaseURL": h.baseURL,
	}); err != nil {
		slog.ErrorCtx(r.Context(), "failed execute template", slog.String("error_code", "001"), slog.String("detail", err.Error()))
		http.Error(w, http.StatusText(http.StatusInternalServerError)+"\nERROR CODE 001", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	io.Copy(w, &buf)
}

type ErrorResponse struct {
	Status   int    `json:"status"`
	Code     string `json:"code"`
	Detail   string `json:"detail"`
	internal error  `json:"-"`
}

func (e *ErrorResponse) Error() string {
	return fmt.Sprintf("status: %d, code: %s, detail: %s", e.Status, e.Code, e.Detail)
}

func (e *ErrorResponse) Unwrap() error {
	return e.internal
}

func (h *handler) ServeDashbords(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Content-Type", "application/json")
	user, ok := GetUserFromContext(r.Context())
	if !ok {
		slog.WarnCtx(ctx, "user context not found")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "dashboars not found",
		})
		return
	}
	slog.InfoCtx(ctx, "accume role", slog.String("user_id", user.ID), slog.String("email", user.Email.String()), slog.String("iam_role", user.IAMRoleARN))
	qs, err := h.app.NewQuickSightClientWithUser(ctx, user)
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
		slog.InfoCtx(ctx, "generate embed url",
			slog.String("user_id", user.ID),
			slog.String("email", user.Email.String()),
			slog.String("quick_sight_user_arn", user.QuickSightUserARN),
			slog.String("dashboard_id", dashbord.DashboardID),
		)
		resp, exists, err := h.generateEmbedUrl(ctx, qs, user.QuickSightUserARN, dashbord.DashboardID)
		if err != nil {
			var e *ErrorResponse
			if errors.As(err, &e) {
				slog.ErrorCtx(r.Context(), "failed generate embed url",
					slog.String("user_id", user.ID),
					slog.String("error_code", e.Code),
					slog.String("detail", e.Detail),
				)
				w.WriteHeader(e.Status)
				json.NewEncoder(w).Encode(e)
				return
			}
			slog.ErrorCtx(r.Context(), "failed generate embed url",
				slog.String("user_id", user.ID),
				slog.String("error_code", "999"),
				slog.String("detail", err.Error()),
			)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code":  "999",
				"error": "can not generate embed url",
			})
		}
		if !exists {
			slog.WarnCtx(r.Context(), "dashboard not found",
				slog.String("user_id", user.ID),
				slog.String("dashboard_id", dashbord.DashboardID),
			)
			continue
		}
		result[fmt.Sprintf("dashbboard%d", i+1)] = resp
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"dashboards": result,
	})
}

func (h *handler) ServeMe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Content-Type", "application/json")
	user, ok := GetUserFromContext(ctx)
	if !ok {
		slog.WarnCtx(ctx, "user context not found")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "user not found",
		})
		return
	}
	w.WriteHeader(http.StatusOK)
	dashbaords := make([]map[string]interface{}, 0, len(user.Dashboards))
	for _, d := range user.Dashboards {
		if !d.IsVisible() {
			continue
		}
		dashbaord := map[string]interface{}{
			"id": d.DashboardID,
		}
		if !d.Expire.IsZero() {
			dashbaord["expire"] = d.Expire
		}
		dashbaords = append(dashbaords, dashbaord)
	}
	userResp := map[string]interface{}{
		"id":         user.ID,
		"email":      user.Email.String(),
		"dashboards": dashbaords,
	}
	if !user.TTL.IsZero() {
		userResp["expire"] = user.TTL
	}
	json.NewEncoder(w).Encode(userResp)
}

func (h *handler) ServeHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
	})
}

func (h *handler) ServeDashbord(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	dashboardID := chi.URLParam(r, "dashboard_id")
	user, ok := GetUserFromContext(r.Context())
	if !ok {
		slog.WarnCtx(r.Context(), "user context not found")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "dashboars not found",
		})
		return
	}
	slog.InfoCtx(r.Context(), "accume role", slog.String("user_id", user.ID), slog.String("email", user.Email.String()), slog.String("iam_role", user.IAMRoleARN))
	qs, err := h.app.NewQuickSightClientWithUser(r.Context(), user)
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
	var visible bool
	for _, d := range user.Dashboards {
		if d.DashboardID == dashboardID {
			visible = d.IsVisible()
		}
	}
	if !visible {
		slog.WarnCtx(r.Context(), "dashboard can not visible",
			slog.String("user_id", user.ID),
			slog.String("dashboard_id", dashboardID),
		)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "dashboars not found",
		})
		return
	}
	resp, exists, err := h.generateEmbedUrl(r.Context(), qs, user.QuickSightUserARN, dashboardID)
	if err != nil {
		var e *ErrorResponse
		if errors.As(err, &e) {
			slog.ErrorCtx(r.Context(), "failed generate embed url",
				slog.String("user_id", user.ID),
				slog.String("error_code", e.Code),
				slog.String("detail", e.Detail),
			)
			w.WriteHeader(e.Status)
			json.NewEncoder(w).Encode(e)
			return
		}
		slog.ErrorCtx(r.Context(), "failed generate embed url",
			slog.String("user_id", user.ID),
			slog.String("error_code", "999"),
			slog.String("detail", err.Error()),
		)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":  "999",
			"error": "can not generate embed url",
		})
		return
	}
	if !exists {
		slog.WarnCtx(r.Context(), "dashboard not found",
			slog.String("user_id", user.ID),
			slog.String("dashboard_id", dashboardID),
		)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "dashboard not found",
		})
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func (h *handler) generateEmbedUrl(ctx context.Context, qs *quicksight.Client, quickSightUserARN string, dashboardID string) (map[string]interface{}, bool, error) {
	d, exists, err := h.app.DescribeDashboard(ctx, dashboardID)
	if err != nil {
		return nil, false, &ErrorResponse{
			Status:   http.StatusInternalServerError,
			Code:     "006",
			Detail:   "can not describe dashboard",
			internal: err,
		}
	}
	if !exists {
		return nil, false, nil
	}
	output, err := qs.GenerateEmbedUrlForRegisteredUser(ctx, &quicksight.GenerateEmbedUrlForRegisteredUserInput{
		AwsAccountId: aws.String(h.app.awsAccountID),
		ExperienceConfiguration: &types.RegisteredUserEmbeddingExperienceConfiguration{
			Dashboard: &types.RegisteredUserDashboardEmbeddingConfiguration{
				InitialDashboardId: aws.String(dashboardID),
			},
		},
		UserArn: aws.String(quickSightUserARN),
		AllowedDomains: []string{
			h.baseURL.String(),
		},
		SessionLifetimeInMinutes: aws.Int64(60),
	})
	if err != nil {
		return nil, false, &ErrorResponse{
			Status:   http.StatusInternalServerError,
			Code:     "003",
			Detail:   "can not get embeded url",
			internal: err,
		}
	}
	return map[string]interface{}{
		"name": d.Name,
		"url":  output.EmbedUrl,
	}, true, nil
}
