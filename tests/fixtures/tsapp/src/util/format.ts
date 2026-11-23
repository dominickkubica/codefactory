import { sum } from "./math"; // loops back: math imports format

export function describe(n: number) {
  return `${n} (${sum([n])})`;
}
