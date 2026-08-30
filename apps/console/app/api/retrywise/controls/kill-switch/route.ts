import { controlPlaneConfiguration, proxyControlPlane } from "@/lib/control-plane";

const ENABLE_REASONS = new Set(["emergency_stop", "operator_safety_hold", "test_mode_hold"]);
const DISABLE_REASONS = new Set(["resume_after_verification", "enable_test_mode_effects"]);

export async function GET(): Promise<Response> {
  return proxyControlPlane("/api/v1/controls/kill-switch");
}

export async function POST(request: Request): Promise<Response> {
  const idempotencyKey = request.headers.get("idempotency-key") ?? "";
  if (
    idempotencyKey.trim() !== idempotencyKey
    || idempotencyKey.length < 16
    || idempotencyKey.length > 128
  ) {
    return Response.json({ code: "INVALID_IDEMPOTENCY_KEY" }, { status: 400 });
  }
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return Response.json({ code: "INVALID_MERCHANT_CONTROL" }, { status: 400 });
  }
  if (
    typeof body !== "object"
    || body === null
    || Array.isArray(body)
    || Object.keys(body).sort().join(",") !== "enabled,reason_code"
  ) {
    return Response.json({ code: "INVALID_MERCHANT_CONTROL" }, { status: 400 });
  }
  const value = body as { enabled?: unknown; reason_code?: unknown };
  const reasons = value.enabled === true ? ENABLE_REASONS : DISABLE_REASONS;
  if (
    typeof value.enabled !== "boolean"
    || typeof value.reason_code !== "string"
    || !reasons.has(value.reason_code)
  ) {
    return Response.json({ code: "INVALID_MERCHANT_CONTROL" }, { status: 400 });
  }
  const config = controlPlaneConfiguration();
  if (!config) return Response.json({ code: "CONTROL_PLANE_NOT_CONFIGURED" }, { status: 503 });
  try {
    const upstream = await fetch(`${config.apiBase}/api/v1/controls/kill-switch`, {
      method: "POST",
      cache: "no-store",
      headers: {
        Authorization: `Bearer ${config.operatorToken}`,
        "Content-Type": "application/json",
        "Idempotency-Key": idempotencyKey,
      },
      body: JSON.stringify(value),
      signal: AbortSignal.timeout(15_000),
    });
    return new Response(await upstream.text(), {
      status: upstream.status,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
    });
  } catch {
    return Response.json({ code: "CONTROL_PLANE_UNAVAILABLE" }, { status: 503 });
  }
}
