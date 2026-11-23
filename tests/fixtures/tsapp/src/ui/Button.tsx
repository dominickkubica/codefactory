type Props = { label: string; onPress: () => void };

export function Button({ label, onPress }: Props) {
  return <button onClick={onPress}>{label}</button>;
}
