import { describe } from "./format";

export type Money = number;

export function sum(xs: number[]): number {
  let t = 0;
  for (const x of xs) {
    if (x > 0) t += x;
  }
  return Math.round(t * 100) / 100;
}

export function addUp(values: number[]): number {
  let acc = 0;
  for (const v of values) {
    if (v > 0) acc += v;
  }
  return Math.round(acc * 100) / 100;
}

export function unusedHelper() {
  return describe(1);
}
