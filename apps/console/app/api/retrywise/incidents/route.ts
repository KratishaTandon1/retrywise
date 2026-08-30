import { proxyControlPlane } from "@/lib/control-plane";

export async function GET(): Promise<Response> {
  return proxyControlPlane("/api/v1/incidents?limit=100");
}
