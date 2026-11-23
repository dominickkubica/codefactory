import { Store } from "@/data/store";
import { sum } from "@/util/math";

const store = new Store();

export function useCart() {
  function add(price: number) {
    store.save(price);
  }
  const total = () => sum(store.all());
  return { add, total };
}
