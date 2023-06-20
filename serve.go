package clipsight

import (
	"bytes"
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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
	PublicPath                  string   `help:"Public path for static files" default:"" env:"CLIPSIGHT_PUBLIC_PATH"`
	EnableIndexFallback         bool     `help:"Enable index fallback" env:"CLIPSIGHT_ENABLE_INDEX_FALLBACK"`
	AuthType                    string   `help:"Types of Authentication" enum:"google,aws,none,dummy" default:"google" env:"CLIPSIGHT_AUTH_TYPE"`
	GoogleClientID              string   `help:"google client id for auth type is google" env:"GOOGLE_CLIENT_ID"`
	GoogleClientSecret          string   `help:"google client secret for auth type is google" env:"GOOGLE_CLIENT_SECRET"`
	GoogleOIDCSessionEncryptKey string   `help:"session encrypt key for google auth" env:"GOOGLE_OIDC_SESSION_ENCRYPT_KEY"`
	AuthHeader                  string   `help:"auth header name for auth type is none" env:"CLIPSIGHT_AUTH_HEADER" default:"ClipSight-Auth-Email"`
	DummyEmail                  string   `help:"dummy email for auth type is none" env:"CLIPSIGHT_DUMMY_EMAIL" default:""`
	EnableConsole               bool     `help:"enable quicksight console" env:"CLIPSIGHT_ENABLE_CONSOLE"`
}

//go:embed public
var defaultPublic embed.FS

type handler struct {
	public fs.FS
	router *chi.Mux
	app    *ClipSight
	opt    *ServeOption
}

type fallbackFS struct {
	fs           fs.FS
	fallbackPath string
}

func (f fallbackFS) Open(name string) (fs.File, error) {
	tryFiles := []string{name}
	if filepath.Ext(name) == "" {
		tryFiles = append(tryFiles, name+".html")
	}
	tryFiles = append(tryFiles, f.fallbackPath)
	for _, tryFile := range tryFiles {
		slog.Debug("try open", slog.String("name", tryFile))
		file, err := f.fs.Open(tryFile)
		if err == nil {
			return file, nil
		}
	}
	return nil, os.ErrNotExist
}

func (app *ClipSight) RunServe(ctx context.Context, opt *ServeOption) error {
	var err error
	authMiddleware, err := app.NewAuthMiddleware(ctx, opt)
	if err != nil {
		return err
	}
	var publicFS fs.FS
	if !opt.APIOnly {
		if opt.PublicPath != "" {
			publicFS = os.DirFS(opt.PublicPath)
		} else {
			publicFS, err = fs.Sub(defaultPublic, "public")
			if err != nil {
				return fmt.Errorf("default public sub: %w", err)
			}
		}
	}
	if opt.EnableIndexFallback {
		publicFS = fallbackFS{
			fs:           publicFS,
			fallbackPath: "index.html",
		}
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
	h := app.newHandler(opt, publicFS, chi.Middlewares{
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
	case "dummy":
		email := Email(opt.DummyEmail)
		if err := email.Validate(); err != nil {
			return nil, fmt.Errorf("failed validate dummy email: %w", err)
		}
		m := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				autholization(w, r, next, email)
			})
		}
		return m, nil
	default:
		return nil, fmt.Errorf("unknwon auth type: %s", opt.AuthType)
	}

}

func (app *ClipSight) newHandler(opt *ServeOption, publicFS fs.FS, middlewares chi.Middlewares) *handler {
	h := &handler{
		public: publicFS,
		router: chi.NewRouter(),
		app:    app,
		opt:    opt,
	}
	for _, m := range middlewares {
		h.router.Use(m)
	}
	h.SetRoute()
	return h
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.router.ServeHTTP(w, r)
}

func (h *handler) Use(middleware func(http.Handler) http.Handler) {
	h.router.Use(middleware)
}

func (h *handler) SetRoute() {
	if h.public != nil {
		h.router.Handle("/*", http.FileServer(http.FS(h.public)))
	}
	h.router.Route("/api", func(r chi.Router) {
		r.Get("/health", h.ServeHealth)
		r.Get("/me", h.ServeMe)
		r.Get("/dashboards", h.ServeDashbords)
		r.Get("/dashboards/{dashboard_id}", h.ServeDashbord)
		r.Get("/console", h.ServeConsole)
	})
}

type ErrorResponse struct {
	Status   int    `json:"status"`
	Code     string `json:"code"`
	Detail   string `json:"detail"`
	internal error  `json:"-"`
}

func (e *ErrorResponse) Error() string {
	return fmt.Sprintf("status: %d, code: %s, detail: %s", e.Status, e.Code, e.internal.Error())
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
	start := 0
	limit := 10
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		var err error
		limit, err = strconv.Atoi(limitStr)
		if err != nil {
			slog.ErrorCtx(r.Context(), "failed parse limit", slog.String("user_id", user.ID), slog.String("email", user.Email.String()), slog.String("limit", limitStr), slog.String("error_code", "011"), slog.String("detail", err.Error()))
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code":  "011",
				"error": "invalid limit",
			})
			return
		}
		if limit > 30 || limit < 0 {
			slog.ErrorCtx(r.Context(), "limit over 30", slog.String("user_id", user.ID), slog.String("email", user.Email.String()), slog.String("limit", limitStr), slog.String("error_code", "011"))
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code":  "011",
				"error": "limit over 30",
			})
			return
		}
	}
	if cursor := r.URL.Query().Get("cursor"); cursor != "" {
		slog.InfoCtx(ctx, "get dashboards with cursor", slog.String("user_id", user.ID), slog.String("email", user.Email.String()), slog.String("cursor", cursor))
		base64Str, err := base64.URLEncoding.DecodeString(cursor)
		if err != nil {
			slog.ErrorCtx(r.Context(), "failed decode cursor", slog.String("user_id", user.ID), slog.String("email", user.Email.String()), slog.String("cursor", cursor), slog.String("error_code", "010"), slog.String("detail", err.Error()))
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code":  "010",
				"error": "invalid cursor",
			})
			return
		}
		if !bytes.HasPrefix(base64Str, []byte("dashboards/")) {
			slog.ErrorCtx(r.Context(), "invalid cursor not has dashborods prefix", slog.String("user_id", user.ID), slog.String("email", user.Email.String()), slog.String("cursor", cursor), slog.String("error_code", "010"), slog.String("decoded_cursor", string(base64Str)))
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code":  "010",
				"error": "invalid cursor",
			})
			return
		}
		start, err = strconv.Atoi(string(bytes.TrimPrefix(base64Str, []byte("dashboards/"))))
		if err != nil {
			slog.ErrorCtx(r.Context(), "failed convert cursor to int", slog.String("user_id", user.ID), slog.String("email", user.Email.String()), slog.String("cursor", cursor), slog.String("error_code", "010"), slog.String("detail", err.Error()))
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code":  "010",
				"error": "invalid cursor",
			})
			return
		}
	}
	end := start + limit
	var fields []string
	if fieldsStr := r.URL.Query().Get("fields"); fieldsStr != "" {
		fields = strings.Split(fieldsStr, ",")
	} else {
		fields = []string{"id", "name", "embeded_url"}
	}
	dashboards, err := h.app.GetVisibleDashboardIDs(ctx, user)
	if err != nil {
		slog.ErrorCtx(r.Context(), "failed get visible dashboards", slog.String("user_id", user.ID), slog.String("email", user.Email.String()), slog.String("error_code", "013"), slog.String("detail", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":  "013",
			"error": "can not get visible dashboards",
		})
		return
	}

	if end > len(dashboards) {
		end = len(dashboards)
	}

	for i := start; i < end; i++ {
		dashbord := dashboards[i]
		slog.InfoCtx(ctx, "generate embed url",
			slog.String("user_id", user.ID),
			slog.String("email", user.Email.String()),
			slog.String("quick_sight_user_arn", user.QuickSightUserARN),
			slog.String("dashboard_id", dashbord),
		)
		resp, exists, err := h.generateEmbedUrlForDashboard(ctx, qs, user.QuickSightUserARN, dashbord, fields)
		if err != nil {
			var e *ErrorResponse
			if errors.As(err, &e) {
				slog.ErrorCtx(r.Context(), "failed generate embed url",
					slog.String("user_id", user.ID),
					slog.String("error_code", e.Code),
					slog.String("detail", e.internal.Error()),
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
				slog.String("dashboard_id", dashbord),
			)
			continue
		}
		result[fmt.Sprintf("dashbboard%d", i+1)] = resp
	}
	resp := map[string]interface{}{
		"dashboards": result,
		"has_next":   end < len(user.Dashboards),
	}
	if end < len(user.Dashboards) {
		resp["cursor"] = base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("dashboards/%d", end+1)))
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
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
	userResp := map[string]interface{}{
		"id":          user.ID,
		"email":       user.Email.String(),
		"can_console": user.CanConsole && h.opt.EnableConsole,
	}
	if !user.TTL.IsZero() {
		userResp["expire"] = user.TTL
	}
	json.NewEncoder(w).Encode(userResp)
}

func (h *handler) ServeHealth(w http.ResponseWriter, r *http.Request) {
	time.Sleep(5 * time.Second)
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
	dashboards, err := h.app.GetVisibleDashboardIDs(r.Context(), user)
	if err != nil {
		slog.ErrorCtx(r.Context(), "failed get visible dashboards",
			slog.String("user_id", user.ID),
			slog.String("error_code", "013"),
			slog.String("detail", err.Error()),
		)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":  "013",
			"error": "can not get visible dashboards",
		})
		return
	}
	var visible bool
	for _, d := range dashboards {
		if d == dashboardID {
			visible = true
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
	var fields []string
	if fieldsStr := r.URL.Query().Get("fields"); fieldsStr != "" {
		fields = strings.Split(fieldsStr, ",")
	} else {
		fields = []string{"id", "name", "embeded_url"}
	}
	resp, exists, err := h.generateEmbedUrlForDashboard(r.Context(), qs, user.QuickSightUserARN, dashboardID, fields)
	if err != nil {
		var e *ErrorResponse
		if errors.As(err, &e) {
			slog.ErrorCtx(r.Context(), "failed generate embed url",
				slog.String("user_id", user.ID),
				slog.String("error_code", e.Code),
				slog.String("detail", e.internal.Error()),
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

func (h *handler) ServeConsole(w http.ResponseWriter, r *http.Request) {
	slog.WarnCtx(r.Context(), "console api", slog.String("path", r.URL.Path))
	w.Header().Set("Content-Type", "application/json")
	user, ok := GetUserFromContext(r.Context())
	if !ok {
		slog.WarnCtx(r.Context(), "user context not found")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "console not found",
		})
		return
	}
	if !user.CanConsole {
		slog.WarnCtx(r.Context(), "user can not console",
			slog.String("user_id", user.ID),
		)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "console not found",
		})
		return
	}
	slog.InfoCtx(r.Context(), "accume role", slog.String("user_id", user.ID), slog.String("email", user.Email.String()), slog.String("iam_role", user.IAMRoleARN))
	qs, err := h.app.NewQuickSightClientWithUser(r.Context(), user)
	if err != nil {
		var e *ErrorResponse
		if errors.As(err, &e) {
			slog.ErrorCtx(r.Context(), "failed generate embed url",
				slog.String("user_id", user.ID),
				slog.String("error_code", e.Code),
				slog.String("detail", e.internal.Error()),
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
	embededURL, err := h.generateEmbedUrlForConsole(r.Context(), qs, user.QuickSightUserARN)
	if err != nil {
		var e *ErrorResponse
		if errors.As(err, &e) {
			slog.ErrorCtx(r.Context(), "failed generate embed url",
				slog.String("user_id", user.ID),
				slog.String("error_code", e.Code),
				slog.String("detail", e.internal.Error()),
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
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"embeded_url": embededURL,
	})
}

func (h *handler) generateEmbedUrlForDashboard(ctx context.Context, qs *quicksight.Client, quickSightUserARN string, dashboardID string, fields []string) (map[string]interface{}, bool, error) {
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
	resp := make(map[string]interface{}, 3)
	for _, f := range fields {
		switch strings.ToLower(f) {
		case "name":
			resp["name"] = d.Name
		case "last_updated_time":
			resp["updated_at"] = (*d.LastUpdatedTime).Unix()
		case "created_at":
			resp["created_at"] = (*d.CreatedTime).Unix()
		case "id":
			resp["id"] = dashboardID
		case "embeded_url":
			output, err := qs.GenerateEmbedUrlForRegisteredUser(ctx, &quicksight.GenerateEmbedUrlForRegisteredUserInput{
				AwsAccountId: aws.String(h.app.awsAccountID),
				ExperienceConfiguration: &types.RegisteredUserEmbeddingExperienceConfiguration{
					Dashboard: &types.RegisteredUserDashboardEmbeddingConfiguration{
						InitialDashboardId: aws.String(dashboardID),
					},
				},
				UserArn: aws.String(quickSightUserARN),
				AllowedDomains: []string{
					h.opt.BaseURL.String(),
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
			resp["embeded_url"] = output.EmbedUrl
		}
	}
	return resp, true, nil
}

func (h *handler) generateEmbedUrlForConsole(ctx context.Context, qs *quicksight.Client, quickSightUserARN string) (string, error) {
	output, err := qs.GenerateEmbedUrlForRegisteredUser(ctx, &quicksight.GenerateEmbedUrlForRegisteredUserInput{
		AwsAccountId: aws.String(h.app.awsAccountID),
		ExperienceConfiguration: &types.RegisteredUserEmbeddingExperienceConfiguration{
			QuickSightConsole: &types.RegisteredUserQuickSightConsoleEmbeddingConfiguration{
				InitialPath: aws.String("/start"),
				FeatureConfigurations: &types.RegisteredUserConsoleFeatureConfigurations{
					StatePersistence: &types.StatePersistenceConfigurations{
						Enabled: false,
					},
				},
			},
		},
		UserArn: aws.String(quickSightUserARN),
		AllowedDomains: []string{
			h.opt.BaseURL.String(),
		},
		SessionLifetimeInMinutes: aws.Int64(60),
	})
	if err != nil {
		return "", &ErrorResponse{
			Status:   http.StatusInternalServerError,
			Code:     "003",
			Detail:   "can not get embeded url",
			internal: err,
		}
	}
	return *output.EmbedUrl, nil
}
