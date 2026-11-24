export async function weather(city: string) {
  const res = await fetch("http://api.weather-feed.io/v1?city=" + encodeURIComponent(city));
  return res.json();
}

export async function local() {
  return fetch("http://localhost:3000/health");
}
