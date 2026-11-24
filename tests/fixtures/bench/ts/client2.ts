export async function rates() {
  const res = await fetch("https://api.rates.example.org/latest", { signal: AbortSignal.timeout(5000) });
  return res.json();
}
