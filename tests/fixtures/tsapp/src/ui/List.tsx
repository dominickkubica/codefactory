import { loadAll, tagged } from "@/data/repo";
import { Button } from "./Button";

// The query runs when a button is pressed, not once per row: not a call in a loop.
export default function List({ ids }: { ids: number[] }) {
  const rows = tagged(ids.map((id) => ({ id })), [1]);
  return <div>{rows.map((r) => <Button key={r.id} label={String(r.id)} onPress={() => loadAll([r.id])} />)}</div>;
}
