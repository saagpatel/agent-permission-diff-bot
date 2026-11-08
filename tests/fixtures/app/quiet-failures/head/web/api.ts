export async function loadCart(id: string) {
  const res = await fetch(`/api/cart/${id}`);
  return res.json();
}

let saved = true;

export function saveCart(cart: unknown) {
  fetch("/api/cart", { method: "POST", body: JSON.stringify(cart) }).catch(() => (saved = false));
}
