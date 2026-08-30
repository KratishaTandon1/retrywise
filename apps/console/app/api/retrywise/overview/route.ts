const ALLOWED_ENVIRONMENTS = new Set(["REPLAY", "RAZORPAY_TEST_MODE"]);

function configuration(): { apiBase: string; operatorToken: string } | null {
  const apiBase = process.env.RETRYWISE_API_URL?.replace(/\/$/, "");
  const operatorToken = process.env.RETRYWISE_OPERATOR_TOKEN;
  if (!apiBase || !operatorToken) return null;
  return { apiBase, operatorToken };
}

export async function GET(request: Request): Promise<Response> {
  const environment = new URL(request.url).searchParams.get("environment") ?? "REPLAY";
  if (!ALLOWED_ENVIRONMENTS.has(environment)) {
    return Response.json({ code: "INVALID_ENVIRONMENT" }, { status: 400 });
  }

  const config = configuration();
  if (!config) {
    return Response.json(
      { code: "CONTROL_PLANE_NOT_CONFIGURED", evidence_source: "bundled_snapshot" },
      { status: 503 },
    );
  }

  try {
    const upstream = await fetch(
      `${config.apiBase}/api/v1/overview?environment=${encodeURIComponent(environment)}`,
      {
        cache: "no-store",
        headers: { Authorization: `Bearer ${config.operatorToken}` },
        signal: AbortSignal.timeout(15_000),
      },
    );
    return new Response(await upstream.text(), {
      status: upstream.status,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
    });
  } catch {
    return Response.json({ code: "CONTROL_PLANE_UNAVAILABLE" }, { status: 503 });
  }
}
