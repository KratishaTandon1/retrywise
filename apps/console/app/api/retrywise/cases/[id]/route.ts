import { proxyControlPlane } from "@/lib/control-plane";

const ULID = /^[0-9A-HJKMNP-TV-Z]{26}$/;

export async function GET(
  _request: Request,
  context: { params: Promise<{ id: string }> },
): Promise<Response> {
  const { id } = await context.params;
  if (!ULID.test(id)) return Response.json({ code: "INVALID_CASE_ID" }, { status: 400 });
  return proxyControlPlane(`/api/v1/recovery-cases/${id}`);
}
