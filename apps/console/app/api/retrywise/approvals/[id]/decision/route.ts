import { controlPlaneConfiguration } from "@/lib/control-plane";

const ULID = /^[0-9A-HJKMNP-TV-Z]{26}$/;
const REASON = /^[a-z][a-z0-9_]{0,99}$/;

export async function POST(
  request: Request,
  context: { params: Promise<{ id: string }> },
): Promise<Response> {
  const { id } = await context.params;
  if (!ULID.test(id)) return Response.json({ code: "INVALID_APPROVAL_ID" }, { status: 400 });
  const idempotencyKey = request.headers.get("idempotency-key") ?? "";
  if (idempotencyKey.trim() !== idempotencyKey || idempotencyKey.length < 16 || idempotencyKey.length > 128) {
    return Response.json({ code: "INVALID_IDEMPOTENCY_KEY" }, { status: 400 });
  }
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return Response.json({ code: "INVALID_APPROVAL_DECISION" }, { status: 400 });
  }
  if (
    typeof body !== "object" || body === null || Array.isArray(body)
    || Object.keys(body).sort().join(",") !== "reason_code,verdict"
  ) {
    return Response.json({ code: "INVALID_APPROVAL_DECISION" }, { status: 400 });
  }
  const value = body as { verdict?: unknown; reason_code?: unknown };
  if (
    (value.verdict !== "APPROVED" && value.verdict !== "REJECTED")
    || typeof value.reason_code !== "string" || !REASON.test(value.reason_code)
  ) {
    return Response.json({ code: "INVALID_APPROVAL_DECISION" }, { status: 400 });
  }
  const config = controlPlaneConfiguration();
  if (!config) return Response.json({ code: "CONTROL_PLANE_NOT_CONFIGURED" }, { status: 503 });
  try {
    const upstream = await fetch(`${config.apiBase}/api/v1/approvals/${id}/decision`, {
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
