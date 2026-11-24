import AsyncStorage from "@react-native-async-storage/async-storage";
import analytics from "@react-native-firebase/analytics";

export function Bio({ bio }: { bio: string }) {
  return <div dangerouslySetInnerHTML={{ __html: bio }} />;
}

export function render(el: HTMLElement, html: string) {
  el.innerHTML = html;
  const text = el.innerHTML;
  if (el.innerHTML === "") return text;
  return text;
}

export async function save(user: { email: string; phone_number: string }, token: string) {
  localStorage.setItem("authToken", token);
  localStorage.setItem("theme", "dark");
  await AsyncStorage.setItem("profile", JSON.stringify({ phone_number: user.phone_number }));
  await AsyncStorage.setItem("onboarded", "1");
  analytics().logEvent("signup", { email: user.email });
  analytics().logEvent("screen_view", { screen: "home" });
  console.log("signed in", user.email);
  console.log("On your phone, open the app");
}
