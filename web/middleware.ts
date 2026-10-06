import { NextResponse } from "next/server";
import type { NextRequest } from "next/request-shim";

// Session gate placeholder: redirect unauthenticated visitors to /login.
export function middleware(request: NextRequest) {
  const token = request.cookies.get("ta_session");
  if (!token && !request.nextUrl.pathname.startsWith("/login")) {
    return NextResponse.redirect(new URL("/login", request.url));
  }
  return NextResponse.next();
}

export const config = { matcher: ["/dashboard/:path*", "/cases/:path*"] };
