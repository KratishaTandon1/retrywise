function configuration(): { apiBase: string; operatorToken: string } | null {
  const apiBase = process.env.RETRYWISE_API_URL?.replace(/\/$/, "");
  const operatorToken = process.env.RETRYWISE_OPERATOR_TOKEN;
  if (!apiBase || !operatorToken) return null;
  return { apiBase, operatorToken };
}

export async function POST(request: Request): Promise<Response> {
  const config = configuration();
  if (!config) {
    return Response.json(
      { code: "CONTROL_PLANE_NOT_CONFIGURED", evidence_source: "bundled_snapshot" },
      { status: 503 },
    );
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return Response.json({ code: "INVALID_REPLAY_REQUEST" }, { status: 400 });
  }

  try {
    const upstream = await fetch(`${config.apiBase}/api/v1/impact/runs`, {
      method: "POST",
      cache: "no-store",
      headers: {
        Authorization: `Bearer ${config.operatorToken}`,
        "Content-Type": "application/json",
        "Idempotency-Key": `console-${crypto.randomUUID()}`,
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(30_000),
    });
    return new Response(await upstream.text(), {
      status: upstream.status,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
    });
  } catch {
    return Response.json({ code: "CONTROL_PLANE_UNAVAILABLE" }, { status: 503 });
  }
}
