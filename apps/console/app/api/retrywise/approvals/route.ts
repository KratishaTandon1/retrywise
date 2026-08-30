import { proxyControlPlane } from "@/lib/control-plane";

export async function GET(): Promise<Response> {
  return proxyControlPlane("/api/v1/approvals?limit=100");
}
