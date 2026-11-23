import type { Money } from "@/util/math"; // type-only: no runtime import, no loop

export class Store {
  private rows: Money[] = [];

  save(row: Money) {
    this.rows.push(row);
  }

  all(): Money[] {
    return [...this.rows];
  }
}
