export function controlPlaneConfiguration(): { apiBase: string; operatorToken: string } | null {
  const apiBase = process.env.RETRYWISE_API_URL?.replace(/\/$/, "");
  const operatorToken = process.env.RETRYWISE_OPERATOR_TOKEN;
  if (!apiBase || !operatorToken) return null;
  return { apiBase, operatorToken };
}

export async function proxyControlPlane(path: string): Promise<Response> {
  const config = controlPlaneConfiguration();
  if (!config) {
    return Response.json({ code: "CONTROL_PLANE_NOT_CONFIGURED" }, { status: 503 });
  }
  try {
    const upstream = await fetch(`${config.apiBase}${path}`, {
      cache: "no-store",
      headers: { Authorization: `Bearer ${config.operatorToken}` },
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
