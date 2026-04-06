package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	x402 "github.com/coinbase/x402/go"
	x402http "github.com/coinbase/x402/go/http"
	evmserver "github.com/coinbase/x402/go/mechanisms/evm/exact/server"
	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/viatika-ai/x402-research-gateway/internal/config"
)

// Handler handles x402-protected research API requests.
type Handler struct {
	router     *chi.Mux
	cfg        *config.GatewayConfig
	x402srv    *x402http.HTTPServer
	routeIndex map[string]*config.RouteConfig // "GET /path" -> config
	httpClient *http.Client
}

// chiHTTPAdapter implements x402http.HTTPAdapter for net/http requests.
type chiHTTPAdapter struct {
	r *http.Request
}

func (a *chiHTTPAdapter) GetHeader(name string) string { return a.r.Header.Get(name) }
func (a *chiHTTPAdapter) GetMethod() string            { return a.r.Method }
func (a *chiHTTPAdapter) GetPath() string              { return a.r.URL.Path }
func (a *chiHTTPAdapter) GetURL() string               { return a.r.URL.String() }
func (a *chiHTTPAdapter) GetAcceptHeader() string      { return a.r.Header.Get("Accept") }
func (a *chiHTTPAdapter) GetUserAgent() string         { return a.r.UserAgent() }

// NewHandler creates a new research gateway handler with x402 SDK integration.
func NewHandler(cfg *config.GatewayConfig) *Handler {
	network := x402.Network(cfg.Network)

	facilitatorClient := x402http.NewFacilitatorClient(&x402http.FacilitatorConfig{
		URL: cfg.FacilitatorURL,
	})

	// Build x402 route config from YAML routes
	x402Routes := make(x402http.RoutesConfig)
	routeIndex := make(map[string]*config.RouteConfig)

	for i := range cfg.Routes {
		r := &cfg.Routes[i]
		key := r.Method + " " + r.Path
		x402Routes[key] = x402http.RouteConfig{
			Description: r.Description,
			MimeType:    r.MimeType,
			Accepts: x402http.PaymentOptions{
				{
					Scheme:            "exact",
					Network:           network,
					PayTo:             cfg.RecipientAddress,
					Price:             r.Price,
					MaxTimeoutSeconds: 60,
				},
			},
		}
		routeIndex[key] = r
	}

	x402srv := x402http.NewServer(
		x402Routes,
		x402.WithFacilitatorClient(facilitatorClient),
		x402.WithSchemeServer(network, evmserver.NewExactEvmScheme()),
	)

	h := &Handler{
		router:     chi.NewRouter(),
		cfg:        cfg,
		x402srv:    x402srv,
		routeIndex: routeIndex,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}

	h.router.Use(chimw.RequestID)
	h.router.Use(chimw.RealIP)
	h.router.Use(chimw.Logger)
	h.router.Use(chimw.Recoverer)
	h.router.Use(chimw.Timeout(30 * time.Second))

	// CORS
	h.router.Use(chimw.SetHeader("Access-Control-Allow-Origin", "*"))
	h.router.Use(chimw.SetHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS"))
	h.router.Use(chimw.SetHeader("Access-Control-Allow-Headers", "Content-Type, PAYMENT-SIGNATURE, X-PAYMENT"))

	// Health endpoint (free)
	h.router.Get("/health", h.handleHealth)

	// Register all configured research routes
	for i := range cfg.Routes {
		r := &cfg.Routes[i]
		slog.Info("Registering route", "method", r.Method, "path", r.Path, "price", r.Price, "upstream", r.Upstream.BaseURL+r.Upstream.Path)
		switch r.Method {
		case "GET":
			h.router.Get(r.Path, h.handleProtectedRoute)
		case "POST":
			h.router.Post(r.Path, h.handleProtectedRoute)
		}
	}

	return h
}

// Initialize calls the x402 SDK to discover facilitator capabilities.
func (h *Handler) Initialize(ctx context.Context) error {
	if err := h.x402srv.Initialize(ctx); err != nil {
		return fmt.Errorf("initialize x402 resource server: %w", err)
	}
	return nil
}

// Router returns the chi router.
func (h *Handler) Router() http.Handler {
	return h.router
}

// handleProtectedRoute serves any configured research route via x402 payment flow.
func (h *Handler) handleProtectedRoute(w http.ResponseWriter, r *http.Request) {
	// Accept both header names for compatibility
	paymentHeader := r.Header.Get("PAYMENT-SIGNATURE")
	if paymentHeader == "" {
		paymentHeader = r.Header.Get("X-PAYMENT")
	}

	if paymentHeader == "" {
		// No payment → generate 402 response via SDK
		adapter := &chiHTTPAdapter{r: r}
		reqCtx := x402http.HTTPRequestContext{
			Adapter:       adapter,
			Path:          r.URL.Path,
			Method:        r.Method,
			PaymentHeader: "",
		}
		result := h.x402srv.ProcessHTTPRequest(r.Context(), reqCtx, nil)
		resp := result.Response
		for k, v := range resp.Headers {
			w.Header().Set(k, v)
		}
		if resp.Body != nil {
			writeJSON(w, resp.Status, resp.Body)
		} else {
			w.WriteHeader(resp.Status)
		}
		return
	}

	// Payment header present → verify and proxy
	h.handlePaymentAndProxy(w, r, paymentHeader)
}

// handlePaymentAndProxy verifies the x402 payment via facilitator, then proxies to upstream.
func (h *Handler) handlePaymentAndProxy(w http.ResponseWriter, r *http.Request, paymentHeader string) {
	routeKey := r.Method + " " + r.URL.Path
	route, ok := h.routeIndex[routeKey]
	if !ok {
		http.Error(w, "route not found", http.StatusNotFound)
		return
	}

	// Decode the base64 payment header
	paymentBytes, err := base64.StdEncoding.DecodeString(paymentHeader)
	if err != nil {
		paymentBytes, err = base64.URLEncoding.DecodeString(paymentHeader)
		if err != nil {
			h.returnPaymentError(w, r, "invalid payment header encoding")
			return
		}
	}

	// Parse the v2 payment payload
	var v2Payload struct {
		X402Version int                    `json:"x402Version"`
		Payload     map[string]interface{} `json:"payload"`
		Accepted    struct {
			Scheme            string                 `json:"scheme"`
			Network           string                 `json:"network"`
			Asset             string                 `json:"asset"`
			Amount            string                 `json:"amount"`
			PayTo             string                 `json:"payTo"`
			MaxTimeoutSeconds int                    `json:"maxTimeoutSeconds"`
			Extra             map[string]interface{} `json:"extra,omitempty"`
		} `json:"accepted"`
	}
	if err := json.Unmarshal(paymentBytes, &v2Payload); err != nil {
		h.returnPaymentError(w, r, fmt.Sprintf("invalid payment payload: %v", err))
		return
	}

	// Convert to v1 format for the facilitator
	v1PaymentPayload := map[string]interface{}{
		"x402Version": 1,
		"scheme":      v2Payload.Accepted.Scheme,
		"network":     v2Payload.Accepted.Network,
		"payload":     v2Payload.Payload,
	}

	resourceURL := fmt.Sprintf("https://%s%s", r.Host, r.URL.Path)

	// Use authorized value from signed payload as maxAmountRequired
	maxAmount := v2Payload.Accepted.Amount
	if authMap, ok := v2Payload.Payload["authorization"].(map[string]interface{}); ok {
		if val, ok := authMap["value"].(string); ok {
			maxAmount = val
		}
	}

	extraJSON, err := json.Marshal(v2Payload.Accepted.Extra)
	if err != nil {
		slog.Warn("Failed to marshal extra JSON", "error", err)
		h.returnPaymentError(w, r, "failed to process payment extra data")
		return
	}

	v1Requirements := map[string]interface{}{
		"scheme":            v2Payload.Accepted.Scheme,
		"network":           v2Payload.Accepted.Network,
		"maxAmountRequired": maxAmount,
		"resource":          resourceURL,
		"description":       route.Description,
		"mimeType":          route.MimeType,
		"payTo":             v2Payload.Accepted.PayTo,
		"maxTimeoutSeconds": v2Payload.Accepted.MaxTimeoutSeconds,
		"asset":             v2Payload.Accepted.Asset,
		"extra":             json.RawMessage(extraJSON),
	}

	// Verify with facilitator
	verifyReq := map[string]interface{}{
		"x402Version":         1,
		"paymentPayload":      v1PaymentPayload,
		"paymentRequirements": v1Requirements,
	}

	verifyBody, err := json.Marshal(verifyReq)
	if err != nil {
		slog.Error("Failed to marshal verify request", "error", err)
		h.returnPaymentError(w, r, "internal error")
		return
	}

	slog.Info("Calling facilitator /verify",
		"route", route.ID,
		"facilitator", h.cfg.FacilitatorURL,
		"network", v2Payload.Accepted.Network,
	)

	verifyResp, err := http.Post(h.cfg.FacilitatorURL+"/verify", "application/json", bytes.NewReader(verifyBody))
	if err != nil {
		slog.Error("Facilitator verify failed", "error", err)
		h.returnPaymentError(w, r, "facilitator unavailable")
		return
	}
	defer verifyResp.Body.Close()

	verifyRespBody, err := io.ReadAll(verifyResp.Body)
	if err != nil {
		slog.Error("Failed to read verify response", "error", err)
		h.returnPaymentError(w, r, "facilitator response unreadable")
		return
	}

	slog.Info("Facilitator verify response", "status", verifyResp.StatusCode, "body", string(verifyRespBody))

	var verifyResult struct {
		IsValid        bool   `json:"isValid"`
		InvalidReason  string `json:"invalidReason,omitempty"`
		InvalidMessage string `json:"invalidMessage,omitempty"`
		Payer          string `json:"payer,omitempty"`
	}
	if err := json.Unmarshal(verifyRespBody, &verifyResult); err != nil {
		slog.Error("Failed to parse verify response", "error", err, "body", string(verifyRespBody))
		h.returnPaymentError(w, r, "invalid facilitator response")
		return
	}

	if verifyResp.StatusCode != http.StatusOK || !verifyResult.IsValid {
		reason := verifyResult.InvalidReason
		if reason == "" {
			reason = "payment_invalid"
		}
		slog.Warn("Payment verification failed", "reason", reason, "message", verifyResult.InvalidMessage)
		h.returnPaymentError(w, r, fmt.Sprintf("verification failed: %s - %s", reason, verifyResult.InvalidMessage))
		return
	}

	// Payment verified! Settle best-effort (non-blocking for resource access).
	var txHash string
	go func() {
		settleReq := map[string]interface{}{
			"x402Version":         1,
			"paymentPayload":      v1PaymentPayload,
			"paymentRequirements": v1Requirements,
		}
		settleBody, err := json.Marshal(settleReq)
		if err != nil {
			slog.Error("Failed to marshal settle request", "error", err)
			return
		}
		settleResp, err := http.Post(h.cfg.FacilitatorURL+"/settle", "application/json", bytes.NewReader(settleBody))
		if err != nil {
			slog.Warn("Facilitator settle failed (non-blocking)", "error", err)
			return
		}
		defer settleResp.Body.Close()
		settleRespBody, _ := io.ReadAll(settleResp.Body)
		slog.Info("Facilitator settle response", "status", settleResp.StatusCode, "body", string(settleRespBody))
	}()

	slog.Info("Payment verified, proxying to upstream",
		"route", route.ID,
		"payer", verifyResult.Payer,
		"upstream", route.Upstream.BaseURL+route.Upstream.Path,
	)

	// Proxy to upstream research API
	result, err := proxyToUpstream(r.Context(), h.httpClient, route, r)
	if err != nil {
		slog.Error("Upstream proxy failed", "route", route.ID, "error", err)
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error":   "upstream_error",
			"message": fmt.Sprintf("upstream API request failed: %v", err),
		})
		return
	}

	// Return upstream response with payment metadata headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Research-Route", route.ID)
	w.Header().Set("X-Research-Payer", verifyResult.Payer)
	if txHash != "" {
		w.Header().Set("X-Research-Transaction", txHash)
	}
	w.WriteHeader(result.StatusCode)
	_, _ = w.Write(result.Body)
}

// returnPaymentError sends a 402 with fresh payment requirements.
func (h *Handler) returnPaymentError(w http.ResponseWriter, r *http.Request, _ string) {
	reqCtx := x402http.HTTPRequestContext{
		Adapter:       &chiHTTPAdapter{r: r},
		Path:          r.URL.Path,
		Method:        r.Method,
		PaymentHeader: "",
	}
	result := h.x402srv.ProcessHTTPRequest(context.Background(), reqCtx, nil)
	if result.Response != nil {
		for k, v := range result.Response.Headers {
			w.Header().Set(k, v)
		}
	}
	w.WriteHeader(http.StatusPaymentRequired)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Warn("Failed to encode JSON response", "error", err)
	}
}
