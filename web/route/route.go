// Copyright 2015 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package route

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/julienschmidt/httprouter"
)

type param string

// Param returns param p for the context, or the empty string when
// param does not exist in context.
func Param(ctx context.Context, p string) string {
	if v := ctx.Value(param(p)); v != nil {
		return v.(string)
	}
	return ""
}

// WithParam returns a new context with param p set to v.
func WithParam(ctx context.Context, p, v string) context.Context {
	return context.WithValue(ctx, param(p), v)
}

// Router wraps httprouter.Router and adds support for prefixed sub-routers,
// per-request context injections and instrumentation.
type Router struct {
	rtr      *httprouter.Router
	prefix   string
	instrh   func(handlerName string, handler http.HandlerFunc) http.HandlerFunc

	as       *AuthStore
}

// New returns a new Router.
func New(basicAuthOrigin string) *Router {
	as := NewAuthStore(basicAuthOrigin)
	r := &Router{
		rtr: httprouter.New(),
		as: as,
	}
	return r
}

// WithInstrumentation returns a router with instrumentation support.
func (r *Router) WithInstrumentation(instrh func(handlerName string, handler http.HandlerFunc) http.HandlerFunc) *Router {
	if r.instrh != nil {
		newInstrh := instrh
		instrh = func(handlerName string, handler http.HandlerFunc) http.HandlerFunc {
			return newInstrh(handlerName, r.instrh(handlerName, handler))
		}
	}
	return &Router{
		rtr: r.rtr,
		prefix: r.prefix,
		instrh: instrh,

		as: r.as,
	}
}

// WithPrefix returns a router that prefixes all registered routes with prefix.
func (r *Router) WithPrefix(prefix string) *Router {
	return &Router{
		rtr: r.rtr,
		prefix: r.prefix + prefix,
		instrh: r.instrh,

		as: r.as,
	}
}

// handle turns a HandlerFunc into an httprouter.Handle.
func (r *Router) handle(handlerName string, h http.HandlerFunc) httprouter.Handle {
	if r.instrh != nil {
		// This needs to be outside the closure to avoid data race when reading and writing to 'h'.
		h = r.instrh(handlerName, h)
	}
	return func(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()

		for _, p := range params {
			ctx = context.WithValue(ctx, param(p.Key), p.Value)
		}
		h(w, req.WithContext(ctx))
	}
}

// Get registers a new GET route.
func (r *Router) Get(path string, h http.HandlerFunc) {
	r.rtr.GET(r.prefix+path, r.handle(path, h))
}

// Options registers a new OPTIONS route.
func (r *Router) Options(path string, h http.HandlerFunc) {
	r.rtr.OPTIONS(r.prefix+path, r.handle(path, h))
}

// Del registers a new DELETE route.
func (r *Router) Del(path string, h http.HandlerFunc) {
	r.rtr.DELETE(r.prefix+path, r.handle(path, h))
}

// Put registers a new PUT route.
func (r *Router) Put(path string, h http.HandlerFunc) {
	r.rtr.PUT(r.prefix+path, r.handle(path, h))
}

// Post registers a new POST route.
func (r *Router) Post(path string, h http.HandlerFunc) {
	r.rtr.POST(r.prefix+path, r.handle(path, h))
}

// Redirect takes an absolute path and sends an internal HTTP redirect for it,
// prefixed by the router's path prefix. Note that this method does not include
// functionality for handling relative paths or full URL redirects.
func (r *Router) Redirect(w http.ResponseWriter, req *http.Request, path string, code int) {
	http.Redirect(w, req, r.prefix+path, code)
}

// ServeHTTP implements http.Handler.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if !r.as.CheckBasicAuthHttp(w,req) {
		return
	}
	r.rtr.ServeHTTP(w, req)
}

// FileServe returns a new http.HandlerFunc that serves files from dir.
// Using routes must provide the *filepath parameter.
func FileServe(dir string) http.HandlerFunc {
	fs := http.FileServer(http.Dir(dir))

	return func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = Param(r.Context(), "filepath")
		fs.ServeHTTP(w, r)
	}
}

// AuthStore 线程不安全，初始化后不允许修改
type AuthStore struct {
	base64AuthList map[string]bool
	open bool
}
// NewAuthStore authList: user:pwd列表，逗号分割，要求密码无逗号
func NewAuthStore(authList string) *AuthStore {
	arr := strings.Split(strings.TrimSpace(authList),",")
	as := &AuthStore{}
	as.base64AuthList = make(map[string]bool, 8)
	for _,v := range arr {
		origin := strings.TrimSpace(v)
		if origin != "" {
			as.open = true
			as.base64AuthList[base64.StdEncoding.EncodeToString([]byte(origin))] = true
		}
	}
	if as.open {
		fmt.Println("AUTH MESSAGE: ", "当前服务已开启Basic Auth")
	}
	return as
}
func (as *AuthStore) BasicAuthWarp(f http.HandlerFunc)http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !as.CheckBasicAuthHttp(w, r) {
			return
		}
		f(w,r)
	}
}
// CheckBasicAuthHttp 校验并且写入response
func (as *AuthStore) CheckBasicAuthHttp(w http.ResponseWriter, r *http.Request) bool {
	if as.open {
		s := r.Header.Get("Authorization")
		if !as.CheckBasicAuth(strings.TrimLeft(s, "Basic ")) {
			w.Header().Add("WWW-Authenticate", "Basic realm=\"Log in with secret\"")
			w.WriteHeader(401)
			w.Write([]byte("请登录！"))
			return false
		}
	}
	return true
}
func (as *AuthStore) CheckBasicAuth(base64Auth string) bool {
	_,ok := as.base64AuthList[base64Auth]
	return ok
}