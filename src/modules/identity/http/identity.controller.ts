import type { FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import type { createIdentityService } from "../application/identity.service.js";
import type { ITokenService } from "../application/token.service.js";

const loginSchema = z.object({
  email: z.string().email().max(320),
  password: z.string().min(1).max(1024),
});
const refreshSchema = z.object({ refreshToken: z.string().optional() });

export type IdentityControllerOptions = {
  service: ReturnType<typeof createIdentityService>;
  tokens: ITokenService;
  accessTtl: number;
  refreshTtl: number;
  browserCookieAuth: boolean;
  publicOrigin: string;
};

export class IdentityController {
  constructor(private options: IdentityControllerOptions) {}

  verifyOrigin = async (request: FastifyRequest, reply: FastifyReply) => {
    if (
      this.options.browserCookieAuth &&
      request.headers.origin !== this.options.publicOrigin
    ) {
      return reply.code(403).send({ error: "origin_forbidden" });
    }
  };

  login = async (request: FastifyRequest, reply: FastifyReply) => {
    const parsed = loginSchema.safeParse(request.body);
    if (!parsed.success)
      return reply.code(400).send({ error: "invalid_request" });
    const issued = await this.options.service.login.execute(
      parsed.data.email,
      parsed.data.password,
    );
    if (this.options.browserCookieAuth)
      this.setRefreshCookie(reply, issued.refreshToken);
    const result = {
      accessToken: issued.accessToken,
      expiresIn: this.options.accessTtl,
      tokenType: "Bearer",
    };
    return this.options.browserCookieAuth
      ? result
      : { ...result, refreshToken: issued.refreshToken };
  };

  refresh = async (request: FastifyRequest, reply: FastifyReply) => {
    const parsed = refreshSchema.safeParse(request.body ?? {});
    const raw =
      request.cookies["__Host-aquila_refresh"] ??
      (parsed.success ? parsed.data.refreshToken : undefined);
    if (!raw) return reply.code(401).send({ error: "invalid_refresh_token" });
    const issued = await this.options.service.refresh.execute(raw);
    if (this.options.browserCookieAuth)
      this.setRefreshCookie(reply, issued.refreshToken);
    const result = {
      accessToken: issued.accessToken,
      expiresIn: this.options.accessTtl,
      tokenType: "Bearer",
    };
    return this.options.browserCookieAuth
      ? result
      : { ...result, refreshToken: issued.refreshToken };
  };

  logout = async (request: FastifyRequest, reply: FastifyReply) => {
    let sessionId: string | undefined;
    const authorization = request.headers.authorization;
    if (authorization?.startsWith("Bearer ")) {
      try {
        sessionId = (
          await this.options.tokens.verifyAccessToken(authorization.slice(7))
        ).sid;
      } catch {
        /* logout stays idempotent */
      }
    }
    await this.options.service.logout.execute(
      sessionId,
      request.cookies["__Host-aquila_refresh"],
    );
    reply.clearCookie("__Host-aquila_refresh", { path: "/" });
    return reply.code(204).send();
  };

  private setRefreshCookie(reply: FastifyReply, value: string) {
    reply.setCookie("__Host-aquila_refresh", value, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      path: "/",
      maxAge: this.options.refreshTtl,
    });
  }
}
