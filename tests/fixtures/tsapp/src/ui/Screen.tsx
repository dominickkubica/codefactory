import { useCart } from "@/state/useCart";
import { Button } from "./Button";

// The app's entry screen: loaded by a router, so nothing imports it.
export default function Screen() {
  const { add, total } = useCart();
  return <Button label={`Total ${total()}`} onPress={() => add(2)} />;
}
