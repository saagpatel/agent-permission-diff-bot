export async function loadCart(id: string) {
  const res = await fetch(`/api/cart/${id}`);
  return res.json();
}
