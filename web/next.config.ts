import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  async rewrites() {
    // Proxy API calls in local development.
    return [{ source: "/api/backend/:path*", destination: `${process.env.API_BASE_URL ?? "http://localhost:8000"}/:path*` }];
  },
};

export default nextConfig;
