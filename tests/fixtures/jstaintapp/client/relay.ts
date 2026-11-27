// hoppscotch: an HTTP client; `request` is the request it sends, not one it received
import axios from "axios";

export async function execute(request: { url: string; headers: Record<string, string> }) {
  const config = { url: request.url, headers: request.headers };
  return axios(config);
}
