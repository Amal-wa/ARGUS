/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// This dev server (not the Gateway) is what actually serves the dashboard's
// HTML/JS/CSS to the browser on :5173 -- the Gateway's SecurityHeadersMiddleware
// (services/api-gateway/app/middleware/security_headers.py) only ever touches
// :8000 JSON/API responses, never this origin. Without headers set HERE, the
// page a user's browser actually renders carries none of that protection
// (verified live: `curl -i http://localhost:5173/` returned no
// Content-Security-Policy/X-Frame-Options/X-Content-Type-Options before this
// change). frame-ancestors is a CSP directive (not a standalone header) --
// X-Frame-Options is kept alongside it for older clients that don't honor CSP
// frame-ancestors. See SECURITY.md's "HTTP security headers" section for the
// full per-layer picture, including the production caveat (this dev server is
// a demo artifact -- a real static-file server in front of `vite build`
// output would need these same three headers configured at THAT layer).
const SECURITY_HEADERS = {
  "Content-Security-Policy": "frame-ancestors 'none'",
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
};

export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    port: 5173,
    headers: SECURITY_HEADERS,
  },
  // `npm run preview` (see package.json / README's Build section) serves the
  // production `vite build` output locally -- mirrored here so that path also
  // carries the same three headers, not just `npm run dev`.
  preview: {
    headers: SECURITY_HEADERS,
  },
  test: {
    environment: "jsdom",
    globals: false,
  },
});
