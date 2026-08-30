import { controlPlaneConfiguration, proxyControlPlane } from "@/lib/control-plane";

const MODES = new Set(["LOCAL_ML", "HYBRID_GEMINI", "SHADOW"]);

export async function GET(): Promise<Response> {
  return proxyControlPlane("/api/v1/controls/diagnosis-engine");
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
    return Response.json({ code: "INVALID_DIAGNOSIS_CONTROL" }, { status: 400 });
  }
  if (
    typeof body !== "object"
    || body === null
    || Array.isArray(body)
    || Object.keys(body).join(",") !== "mode"
  ) {
    return Response.json({ code: "INVALID_DIAGNOSIS_CONTROL" }, { status: 400 });
  }
  const value = body as { mode?: unknown };
  if (typeof value.mode !== "string" || !MODES.has(value.mode)) {
    return Response.json({ code: "INVALID_DIAGNOSIS_CONTROL" }, { status: 400 });
  }
  const config = controlPlaneConfiguration();
  if (!config) return Response.json({ code: "CONTROL_PLANE_NOT_CONFIGURED" }, { status: 503 });
  try {
    const upstream = await fetch(`${config.apiBase}/api/v1/controls/diagnosis-engine`, {
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
